package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	connecteth "github.com/DomenicoVerde/connect-eth-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/yosida95/uritemplate/v3"
)

// logFrames enables a log line for each proxied frame. It can be disabled with LOG_FRAMES=false,
// since logging slows down the proxying loops in high throughput tests (e.g. iperf).
var logFrames = os.Getenv("LOG_FRAMES") != "false"

func main() {
	// get proxy IP address and port from env variables
	proxyPort, err := strconv.Atoi(os.Getenv("PROXY_PORT"))
	if err != nil {
		log.Fatalf("failed to parse proxy port: %v", err)
	}
	proxyAddr := netip.AddrPortFrom(netip.MustParseAddr(os.Getenv("PROXY_ADDR")), uint16(proxyPort))

	serverAddr := getEnvAddr("SERVER_ADDR")

	// store QUIC TLS secrets on file for later decryption
	keyLog, err := os.Create("keys.txt")
	if err != nil {
		log.Fatalf("failed to create key log file: %v", err)
	}
	defer keyLog.Close()

	// start http/3 connection and open tap device
	dev, ethconn, err := establishConn(proxyAddr, keyLog)
	if err != nil {
		log.Fatalf("failed to establish connection: %v", err)
	}

	// start tcpdump to obtain packet captures
	cmd := exec.Command("tcpdump", "-i", dev.Name(), "-w", "client.pcap", "-U")
	if err := cmd.Start(); err != nil {
		log.Fatalf("failed to start tcpdump: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	log.Printf("started tcpdump on TAP device: %s", dev.Name())
	go proxy(ethconn, dev)

	// Wait for the tunnel to be usable before running the testcase: IPv6 addresses can't be used
	// until Duplicate Address Detection completes, and the first packets would be lost.
	if err := waitReachable(serverAddr, 10*time.Second); err != nil {
		log.Fatalf("server not reachable through the tunnel: %v", err)
	}

	testcase := os.Getenv("TESTCASE")
	switch testcase {
	case "ping":
		err = runPingTest(serverAddr, 50)
	case "iperf":
		err = runIperfTest(serverAddr)
	case "vlan":
		err = runVLANTest(dev.Name())
	case "twoclients":
		err = runTwoClientsTest(serverAddr, getEnvAddr("PEER_ADDR"))
	case "twoclients-peer":
		// The peer client only pings the server, then keeps the tunnel open for the other client,
		// until the containers are stopped.
		if err := runPingTest(serverAddr, 50); err != nil {
			log.Fatalf("%s test failed: %v", testcase, err)
		}
		select {}
	default:
		log.Fatalf("unknown testcase: %s", testcase)
	}
	if err != nil {
		log.Fatalf("%s test failed: %v", testcase, err)
	}

	time.Sleep(time.Second) // give tcpdump some time to write the last packets
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		log.Printf("failed to send SIGTERM signal to tcpdump process: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		log.Printf("tcpdump process exited with error: %v", err)
	}
}

// establishConn starts a quic, http/3, proxied connection and opens a tap device
func establishConn(proxyAddr netip.AddrPort, keyLog io.Writer) (*water.Interface, *connecteth.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// QUIC connection
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0)})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on UDP: %w", err)
	}

	conn, err := quic.Dial(
		ctx,
		udpConn,
		&net.UDPAddr{IP: proxyAddr.Addr().AsSlice(), Port: int(proxyAddr.Port())},
		&tls.Config{
			ServerName:         "proxy",
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
			KeyLogWriter:       keyLog,
		},
		&quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1350,
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial QUIC connection: %w", err)
	}

	// HTTP/3 connection
	tr := &http3.Transport{EnableDatagrams: true}
	hconn := tr.NewClientConn(conn)

	// Ethernet over HTTP/3 connection
	template := uritemplate.MustNew(fmt.Sprintf("https://proxy:%d/.well-known/masque/ethernet/", proxyAddr.Port()))
	// Dial fails on any non-2xx response, so there is no need to check the status code here.
	ethconn, _, err := connecteth.Dial(ctx, hconn, template)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial connect-ethernet proxied connection: %w", err)
	}
	log.Printf("Successfully connected to a Ethernet Proxy Server: %s", proxyAddr)

	// TAP device configuration
	dev, err := water.New(water.Config{DeviceType: water.TAP})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create TAP device: %w", err)
	}
	log.Printf("created TAP device: %s", dev.Name())

	link, err := netlink.LinkByName(dev.Name())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get TAP interface: %w", err)
	}

	err = netlink.LinkSetMTU(link, 1300)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to set TAP mtu")
	}

	// IP addresses of the TAP device on the server network, they can be configured to run multiple clients
	if err := addAddrs(link, getEnv("TAP_IPV4", "198.51.100.10/24"), getEnv("TAP_IPV6", "2001:db8:2::10/64")); err != nil {
		return nil, nil, fmt.Errorf("failed to configure TAP interface: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return nil, nil, fmt.Errorf("failed to bring up TAP interface: %w", err)
	}

	time.Sleep(1 * time.Second)

	return dev, ethconn, nil
}

// maxFrameSize is the size of the largest Ethernet frame (without FCS) that can be proxied:
// 1500 bytes of MTU + 14 bytes of Ethernet header + 4 bytes of IEEE 802.1Q tag.
const maxFrameSize = 1518

func proxy(ethconn *connecteth.Conn, dev *water.Interface) error {
	errChan := make(chan error, 2)
	go func() {
		for {
			b := make([]byte, maxFrameSize)
			n, err := ethconn.ReadPacket(b)
			if err != nil {
				errChan <- fmt.Errorf("failed to read from connection: %w", err)
				return
			}
			if logFrames {
				log.Printf("Read %d bytes from connection", n)
			}
			if _, err := dev.Write(b[:n]); err != nil {
				errChan <- fmt.Errorf("failed to write to TUN: %w", err)
				return
			}
		}
	}()

	go func() {
		for {
			b := make([]byte, maxFrameSize)
			n, err := dev.Read(b)
			if err != nil {
				errChan <- fmt.Errorf("failed to read from TAP: %w", err)
				return
			}
			if logFrames {
				log.Printf("read %d bytes from TAP", n)
			}
			err = ethconn.WritePacket(b[:n])
			if err != nil {
				errChan <- fmt.Errorf("failed to write to connection: %w", err)
				return
			}
		}
	}()

	err := <-errChan
	log.Printf("error proxying: %v", err)
	dev.Close()
	ethconn.Close()
	<-errChan // wait for the other goroutine to finish
	return err
}

// addAddrs adds the given IP addresses (in CIDR notation) to link.
func addAddrs(link netlink.Link, cidrs ...string) error {
	for _, cidr := range cidrs {
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse address %s: %w", cidr, err)
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("failed to add address %s to %s: %w", cidr, link.Attrs().Name, err)
		}
	}
	return nil
}

// getEnv returns the value of the environment variable key, or def if it is not set.
func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// getEnvAddr parses the IP address in the environment variable key, and exits on failure.
func getEnvAddr(key string) netip.Addr {
	addr, err := netip.ParseAddr(os.Getenv(key))
	if err != nil {
		log.Fatalf("failed to parse %s: %v", key, err)
	}
	return addr
}
