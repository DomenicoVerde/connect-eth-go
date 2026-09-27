package main

import (
	"fmt"
	"log"
	"net/netip"
	"os/exec"
	"strings"
	"time"
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
