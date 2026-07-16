//go:build linux

package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"

	connecteth "github.com/DomenicoVerde/connect-eth-go"
	"golang.org/x/sys/unix"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/vishvananda/netlink"
	"github.com/yosida95/uritemplate/v3"
)

var serverSocket int
var ifaceLink netlink.Link
var ifaceName = os.Getenv("SERVER_INTERFACE")

func main() {
	// get proxy IP address and port from env variables
	proxyPort, err := strconv.Atoi(os.Getenv("PROXY_PORT"))
	if err != nil {
		log.Fatalf("failed to parse proxy port: %v", err)
	}
	bindProxyTo := netip.AddrPortFrom(netip.MustParseAddr(os.Getenv("PROXY_ADDR")), uint16(proxyPort))

	// get Server interface name
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.Fatalf("failed to get %s interface: %v", ifaceName, err)
	}
	ifaceLink = link

	// create a socket to send/receive packets to/from the server
	fd, err := createSocket(link)
	if err != nil {
		log.Fatalf("failed to create receive socket: %v", err)
	}
	serverSocket = fd

	if err := run(bindProxyTo); err != nil {
		log.Fatal(err)
	}
}

func createSocket(link netlink.Link) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return 0, fmt.Errorf("creating socket: %w", err)
	}

	sll := &unix.SockaddrLinklayer{
		Ifindex:  link.Attrs().Index,
		Protocol: htons(unix.ETH_P_ALL),
	}

	if err := unix.Bind(fd, sll); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("binding socket: %w", err)
	}

	err = unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1)
	if err != nil {
		unix.Close(fd)
		return 0, fmt.Errorf("setting PACKET_IGNORE_OUTGOING: %w", err)
	}

	return fd, nil
}

func htons(host uint16) uint16 {
	return (host<<8)&0xff00 | (host>>8)&0xff
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
	go s.ServeListener(ln)
	defer s.Close()

	select {}
}

func handleConn(conn *connecteth.Conn) error {
	errChan := make(chan error, 2)
	go func() {
		for {
			b := make([]byte, 1500)
			n, err := conn.ReadPacket(b)
			if err != nil {
				errChan <- fmt.Errorf("failed to read from connection: %w", err)
				return
			}
			log.Printf("read %d bytes from connection", n)
			addr := &unix.SockaddrLinklayer{
				Ifindex:  ifaceLink.Attrs().Index,
				Protocol: htons(unix.ETH_P_ALL),
			}
			if err := unix.Sendto(serverSocket, b[:n], 0, addr); err != nil {
				errChan <- fmt.Errorf("writing to server socket: %w", err)
				return
			}
		}
	}()

	go func() {
		for {
			b := make([]byte, 1500)
			n, _, err := unix.Recvfrom(serverSocket, b, 0)
			if err != nil {
				errChan <- fmt.Errorf("failed to read from server socket: %w", err)
				return
			}
			log.Printf("read %d bytes from %s", n, ifaceName)
			err = conn.WritePacket(b[:n])
			if err != nil {
				errChan <- fmt.Errorf("failed to write to connection: %w", err)
				return
			}
		}
	}()

	err := <-errChan
	log.Printf("error proxying: %v", err)
	conn.Close()
	<-errChan // wait for the other goroutine to finish
	return err
}
