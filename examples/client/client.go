package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
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

func main() {
	// get proxy IP address and port from env variables
	proxyPort, err := strconv.Atoi(os.Getenv("PROXY_PORT"))
	if err != nil {
		log.Fatalf("failed to parse proxy port: %v", err)
	}
	proxyAddr := netip.AddrPortFrom(netip.MustParseAddr(os.Getenv("PROXY_ADDR")), uint16(proxyPort))

	serverAddr, err := netip.ParseAddr(os.Getenv("SERVER_ADDR"))
	if err != nil {
		log.Fatalf("failed to parse server URL: %v", err)
	}

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

	switch os.Getenv("TESTCASE") {
	case "ping":
		if err := runPingTest(serverAddr, 50); err != nil {
			log.Fatalf("ping test failed: %v", err)
		}
	default:
		log.Fatalf("unknown testcase: %s", os.Getenv("TESTCASE"))
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
	ethconn, rsp, err := connecteth.Dial(ctx, hconn, template)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial connect-ethernet proxied connection: %w", err)
	}
	if rsp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected status code: %d", rsp.StatusCode)
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

	addr, err := netlink.ParseAddr("198.51.100.10/24")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse the IPv4 address: %w", err)
	}

	err = netlink.AddrAdd(link, addr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to add Ipv4 address to TAP interface: %w", err)
	}

	addrv6, err := netlink.ParseAddr("2001:db8:2::10/64")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse the IPv6 address: %w", err)
	}

	err = netlink.AddrAdd(link, addrv6)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to add Ipv6 address to TAP interface: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return nil, nil, fmt.Errorf("failed to bring up TAP interface: %w", err)
	}

	time.Sleep(1 * time.Second)

	return dev, ethconn, nil
}

func proxy(ethconn *connecteth.Conn, dev *water.Interface) error {
	errChan := make(chan error, 2)
	go func() {
		for {
			b := make([]byte, 1500)
			n, err := ethconn.ReadPacket(b)
			if err != nil {
				errChan <- fmt.Errorf("failed to read from connection: %w", err)
				return
			}
			log.Printf("Read %d bytes from connection", n)
			if _, err := dev.Write(b[:n]); err != nil {
				errChan <- fmt.Errorf("failed to write to TUN: %w", err)
				return
			}
		}
	}()

	go func() {
		for {
			b := make([]byte, 1500)
			n, err := dev.Read(b)
			if err != nil {
				errChan <- fmt.Errorf("failed to read from TAP: %w", err)
				return
			}
			log.Printf("read %d bytes from TAP", n)
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
