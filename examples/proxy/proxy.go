//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	connecteth "github.com/DomenicoVerde/connect-eth-go"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/yosida95/uritemplate/v3"
)

// bridgeName is the name of the Linux bridge connecting the server-facing interface with the TAP device of each client.
// The bridge performs MAC learning and flooding, so that each client receives only the frames destined to it,
// as well as broadcast and multicast frames, and clients can reach each other (Sec. 7, 8.1).
const bridgeName = "br0"

// maxFrameSize is the size of the largest Ethernet frame (without FCS) that can be proxied:
// 1500 bytes of MTU + 14 bytes of Ethernet header + 4 bytes of IEEE 802.1Q tag.
const maxFrameSize = 1518

// logFrames enables a log line for each proxied frame. It can be disabled with LOG_FRAMES=false,
// since logging slows down the proxying loops in high throughput tests (e.g. iperf).
var logFrames = os.Getenv("LOG_FRAMES") != "false"

var bridge netlink.Link

func main() {
	// get proxy IP address and port from env variables
	proxyPort, err := strconv.Atoi(os.Getenv("PROXY_PORT"))
	if err != nil {
		log.Fatalf("failed to parse proxy port: %v", err)
	}
	bindProxyTo := netip.AddrPortFrom(netip.MustParseAddr(os.Getenv("PROXY_ADDR")), uint16(proxyPort))

	// bridge the server-facing interface, TAP devices of clients are added upon connection
	ifaceName := os.Getenv("SERVER_INTERFACE")
	br, err := createBridge(ifaceName)
	if err != nil {
		log.Fatalf("failed to create bridge: %v", err)
	}
	bridge = br

	if err := run(bindProxyTo); err != nil {
		log.Fatal(err)
	}
}

// createBridge creates a Linux bridge, and adds the interface ifaceName to it.
func createBridge(ifaceName string) (netlink.Link, error) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s interface: %w", ifaceName, err)
	}

	// Multicast snooping is disabled, so that multicast frames (e.g. IPv6 Neighbor Discovery) are always flooded
	// to all ports, as a plain Ethernet switch would do.
	snooping := false
	br := &netlink.Bridge{
		LinkAttrs:         netlink.LinkAttrs{Name: bridgeName},
		MulticastSnooping: &snooping,
	}
	if err := netlink.LinkAdd(br); err != nil {
		return nil, fmt.Errorf("failed to add bridge %s: %w", bridgeName, err)
	}
	if err := netlink.LinkSetMaster(link, br); err != nil {
		return nil, fmt.Errorf("failed to add %s to bridge %s: %w", ifaceName, bridgeName, err)
	}
	if err := netlink.LinkSetUp(br); err != nil {
		return nil, fmt.Errorf("failed to bring up bridge %s: %w", bridgeName, err)
	}
	log.Printf("created bridge %s with interface %s", bridgeName, ifaceName)
	return br, nil
}

// createTAP creates a new TAP device, and adds it to the bridge.
// The TAP device is not persistent: it is deleted, and removed from the bridge, when it is closed.
func createTAP() (*water.Interface, error) {
	dev, err := water.New(water.Config{DeviceType: water.TAP})
	if err != nil {
		return nil, fmt.Errorf("failed to create TAP device: %w", err)
	}
	link, err := netlink.LinkByName(dev.Name())
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("failed to get TAP interface %s: %w", dev.Name(), err)
	}
	if err := netlink.LinkSetMaster(link, bridge); err != nil {
		dev.Close()
		return nil, fmt.Errorf("failed to add %s to bridge %s: %w", dev.Name(), bridgeName, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		dev.Close()
		return nil, fmt.Errorf("failed to bring up TAP interface %s: %w", dev.Name(), err)
	}
	return dev, nil
}

func run(bindTo netip.AddrPort) error {
	// QUIC Connection
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindTo.Addr().AsSlice(), Port: int(bindTo.Port())})
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}
	defer udpConn.Close()

	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	// Connect-Ethernet Connection
	template := uritemplate.MustNew(fmt.Sprintf("https://proxy:%d/.well-known/masque/ethernet/", bindTo.Port()))
	ln, err := quic.ListenEarly(
		udpConn,
		http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		&quic.Config{EnableDatagrams: true},
	)
	if err != nil {
		return fmt.Errorf("failed to create QUIC listener: %w", err)
	}
	defer ln.Close()

	p := connecteth.Proxy{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/masque/ethernet/", func(w http.ResponseWriter, r *http.Request) {
		req, err := connecteth.ParseRequest(r, template)
		if err != nil {
			var perr *connecteth.RequestParseError
			if errors.As(err, &perr) {
				w.WriteHeader(perr.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		conn, err := p.Proxy(w, req)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err := handleConn(conn); err != nil {
			log.Printf("failed to handle connection: %v", err)
		}
	})
	s := http3.Server{
		Handler:         mux,
		EnableDatagrams: true,
	}
	defer s.Close()

	// Close the server on SIGINT/SIGTERM: clients are notified with a CONNECTION_CLOSE,
	// instead of waiting for the QUIC idle timeout.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		s.Close()
	}()

	if err := s.ServeListener(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func handleConn(conn *connecteth.Conn) error {
	dev, err := createTAP()
	if err != nil {
		conn.Close()
		return err
	}
	log.Printf("client connected, bridged on TAP device %s", dev.Name())

	errChan := make(chan error, 2)
	go func() {
		for {
			b := make([]byte, maxFrameSize)
			n, err := conn.ReadPacket(b)
			if err != nil {
				errChan <- fmt.Errorf("failed to read from connection: %w", err)
				return
			}
			if logFrames {
				log.Printf("read %d bytes from connection", n)
			}
			if _, err := dev.Write(b[:n]); err != nil {
				errChan <- fmt.Errorf("failed to write to TAP %s: %w", dev.Name(), err)
				return
			}
		}
	}()

	go func() {
		for {
			b := make([]byte, maxFrameSize)
			n, err := dev.Read(b)
			if err != nil {
				errChan <- fmt.Errorf("failed to read from TAP %s: %w", dev.Name(), err)
				return
			}
			if logFrames {
				log.Printf("read %d bytes from %s", n, dev.Name())
			}
			if err := conn.WritePacket(b[:n]); err != nil {
				errChan <- fmt.Errorf("failed to write to connection: %w", err)
				return
			}
		}
	}()

	err = <-errChan
	log.Printf("error proxying: %v", err)
	conn.Close()
	dev.Close()
	<-errChan // wait for the other goroutine to finish
	return err
}
