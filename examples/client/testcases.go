package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
)

func runPingTest(dst netip.Addr, num int) error {
	start := time.Now()
	transmitted, received, err := ping(dst, 50*time.Millisecond, num)
	if err != nil {
		return err
	}
	log.Printf("ping test: transmitted %d, received %d in %s", transmitted, received, time.Since(start))
	if transmitted != num {
		return fmt.Errorf("expected %d packets transmitted, got %d", num, transmitted)
	}
	if transmitted != received {
		return fmt.Errorf("expected %d packets received, got %d", transmitted, received)
	}
	return nil
}

func ping(dst netip.Addr, interval time.Duration, count int) (transmitted, received int, _ error) {
	cmd := exec.Command(
		"ping",
		"-i", fmt.Sprintf("%f", interval.Seconds()),
		"-c", fmt.Sprintf("%d", count),
		dst.String(),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, 0, fmt.Errorf("ping failed: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "packets transmitted") {
			parts := strings.Split(line, ",")
			if len(parts) >= 2 {
				fmt.Sscanf(parts[0], "%d packets transmitted", &transmitted)
				fmt.Sscanf(parts[1], "%d received", &received)
			}
			break
		}
	}
	return
}

// waitReachable pings dst once per second, until it replies or timeout expires.
// It is used to wait for IPv6 Duplicate Address Detection, or for other clients to connect.
func waitReachable(dst netip.Addr, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := exec.Command("ping", "-c", "1", "-W", "1", dst.String()).Run(); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("%s not reachable after %s", dst, timeout)
}

// iperfResult contains the fields of the iperf3 JSON output used by the iperf test.
type iperfResult struct {
	Error string `json:"error"`
	End   struct {
		SumSent struct {
			Bytes       int64 `json:"bytes"`
			Retransmits int   `json:"retransmits"`
		} `json:"sum_sent"`
		SumReceived struct {
			Bytes         int64   `json:"bytes"`
			BitsPerSecond float64 `json:"bits_per_second"`
		} `json:"sum_received"`
	} `json:"end"`
}

// runIperf runs iperf3 with args, and parses its JSON output.
// iperf3 exits with an error on failure, but it still prints the reason in the JSON output, and the exit error
// is returned as runErr. The iperf3 server runs one test at a time: if it is still closing the previous test,
// the test is retried.
func runIperf(args []string) (res iperfResult, runErr, err error) {
	for attempt := 1; ; attempt++ {
		var output []byte
		output, runErr = exec.Command("iperf3", args...).Output()
		res = iperfResult{}
		if err := json.Unmarshal(output, &res); err != nil {
			return res, runErr, fmt.Errorf("failed to parse output (%v): %w", runErr, err)
		}
		if !strings.Contains(res.Error, "server is busy") || attempt == 5 {
			return res, runErr, nil
		}
		log.Printf("iperf server busy, retrying (attempt %d)", attempt)
		time.Sleep(time.Second)
	}
}

// runIperfTest runs a TCP iperf3 test towards dst, both in upload and in download (reverse mode).
func runIperfTest(dst netip.Addr) error {
	for _, reverse := range []bool{false, true} {
		direction := "upload"
		args := []string{"-c", dst.String(), "-t", "5", "-J", "--connect-timeout", "5000"}
		if reverse {
			direction = "download"
			args = append(args, "-R")
		}
		res, runErr, err := runIperf(args)
		if err != nil {
			return fmt.Errorf("iperf %s: %w", direction, err)
		}
		if res.Error != "" || runErr != nil {
			return fmt.Errorf("iperf %s failed: %s (%v)", direction, res.Error, runErr)
		}
		if res.End.SumReceived.Bytes == 0 {
			return fmt.Errorf("iperf %s: no data received", direction)
		}
		log.Printf("iperf %s: received %d bytes, %.2f Mbit/s, %d retransmits",
			direction, res.End.SumReceived.Bytes, res.End.SumReceived.BitsPerSecond/1e6, res.End.SumSent.Retransmits)
	}
	return nil
}

// runVLANTest creates an IEEE 802.1Q VLAN interface on top of the TAP device, and pings the server on that VLAN.
// Tagged frames are transparently forwarded by the tunnel (Sec. 9.2), so the ping succeeds only if the tag
// is preserved end-to-end.
func runVLANTest(tapName string) error {
	vlanID, err := strconv.Atoi(os.Getenv("VLAN_ID"))
	if err != nil {
		return fmt.Errorf("failed to parse VLAN_ID: %w", err)
	}
	dst := getEnvAddr("VLAN_SERVER_ADDR")

	tap, err := netlink.LinkByName(tapName)
	if err != nil {
		return fmt.Errorf("failed to get TAP interface: %w", err)
	}
	vlan := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{Name: fmt.Sprintf("%s.%d", tapName, vlanID), ParentIndex: tap.Attrs().Index},
		VlanId:    vlanID,
	}
	if err := netlink.LinkAdd(vlan); err != nil {
		return fmt.Errorf("failed to create VLAN interface: %w", err)
	}
	if err := addAddrs(vlan, os.Getenv("VLAN_IPV4"), os.Getenv("VLAN_IPV6")); err != nil {
		return fmt.Errorf("failed to configure VLAN interface: %w", err)
	}
	if err := netlink.LinkSetUp(vlan); err != nil {
		return fmt.Errorf("failed to bring up VLAN interface: %w", err)
	}
	log.Printf("created VLAN interface %s (VLAN ID %d)", vlan.Name, vlanID)

	if err := waitReachable(dst, 10*time.Second); err != nil {
		return err
	}
	return runPingTest(dst, 50)
}

// runTwoClientsTest waits for another client to connect to the same proxy, then pings, at the same time,
// both the server and the other client. The ping succeeds only if the proxy forwards to each client
// the frames destined to it.
func runTwoClientsTest(server, peer netip.Addr) error {
	if err := waitReachable(peer, 20*time.Second); err != nil {
		return fmt.Errorf("peer client: %w", err)
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, dst := range []netip.Addr{server, peer} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := runPingTest(dst, 50); err != nil {
				errs[i] = fmt.Errorf("ping %s: %w", dst, err)
			}
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}
