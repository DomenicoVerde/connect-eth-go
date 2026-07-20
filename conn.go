package connecteth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

type CloseError struct {
	Remote bool
}

func (e *CloseError) Error() string        { return net.ErrClosed.Error() }
func (e *CloseError) Is(target error) bool { return target == net.ErrClosed }

type http3Stream interface {
	io.ReadWriteCloser
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
	CancelRead(quic.StreamErrorCode)
}

var (
	_ http3Stream = &http3.Stream{}
	_ http3Stream = &http3.RequestStream{}
)

// Conn is a connection structure used to proxy Ethernet frames over HTTP/3.
type Conn struct {
	str http3Stream
	mu  sync.Mutex

	closeChan chan struct{}
	closeErr  error
}

// newProxiedConn creates a new proxied connection structure, handling read/writes from the HTTP/3 stream.
func newProxiedConn(str http3Stream) *Conn {
	c := &Conn{
		str:       str,
		closeChan: make(chan struct{}),
	}
	go func() {
		if err := c.readFromStream(); err != nil {
			log.Printf("reading from stream failed: %v", err)
			c.mu.Lock()
			if c.closeErr == nil {
				c.closeErr = &CloseError{Remote: true}
				close(c.closeChan)
			}
			c.mu.Unlock()
		}
	}()
	// In future version a c.WriteToSream() may be needed
	return c
}

// readFromStream reads HTTP/3 capsules from streams. Actually is used to track if the connection is closed or active.
func (c *Conn) readFromStream() error {
	defer c.str.Close()
	r := quicvarint.NewReader(c.str)
	for {
		t, _, err := http3.ParseCapsule(r)
		if err != nil {
			return err
		}
		switch t {
		// Maybe in future versions new capsules will be defined
		default:
			log.Printf("unknown capsule type: %d", t)
		}
	}
}

// ReadPacket reads an Ethernet frame over the HTTP/3 connection.
func (c *Conn) ReadPacket(b []byte) (n int, err error) {
start:
	data, err := c.str.ReceiveDatagram(context.Background())
	if err != nil {
		select {
		case <-c.closeChan:
			return 0, c.closeErr
		default:
			return 0, err
		}
	}
	contextID, n, err := quicvarint.Parse(data)
	if err != nil {
		return 0, fmt.Errorf("connect-ethernet: malformed datagram: %w", err)
	}
	if contextID != 0 {
		// Drop this datagram. We only support proxying of Ethernet payloads with Context ID set to 0 (Sec. 5)
		goto start
	}
	if err := c.handleIncomingProxiedPacket(data[n:]); err != nil {
		log.Printf("dropping proxied packet: %s", err)
		goto start
	}
	return copy(b, data[n:]), nil
}

func (c *Conn) handleIncomingProxiedPacket(data []byte) error {
	// We don't necessarily assign any addresses to the peer, since it is L2 proxying.
	// In addition, in the Remote Access VPN use case (Section 8.1),
	// the client accepts incoming traffic from all IPs, thus it has no sense to save the ip in the conn.

	// The destination IP address is always valid, since the proxy acts as a L2 bridge. ARP resolution and other stuff
	// is leaved to the OS.

	// We check only that the frame has a correct ethertype. Other checks may be needed in the future.
	if !isEthernet(data) {
		return errors.New("connect-ethernet: not an Ethernet packet")
	}

	return nil
}

// WritePacket encapsulates and sends an Ethernet frame over the HTTP/3 connection.
func (c *Conn) WritePacket(b []byte) (err error) {
	data, err := c.composeDatagram(b)
	if err != nil {
		log.Printf("dropping proxied packet (%d bytes) that can't be proxied: %s", len(b), err)
		return err
	}

	if err := c.str.SendDatagram(data); err != nil {
		var errDTL *quic.DatagramTooLargeError
		if errors.As(err, &errDTL) {
			log.Printf("dropping proxied packet: datagram too large (%d bytes)", len(data))
			return err
		}
		select {
		case <-c.closeChan:
			return c.closeErr
		default:
			return err
		}
	}
	return nil
}

// composeDatagram creates a new HTTP datagram appending the ContextID (0) and the Payload (Ref. Sec. 6)
func (c *Conn) composeDatagram(b []byte) ([]byte, error) {
	if !isEthernet(b) {
		return nil, errors.New("error composing datagram: invalid Ethernet frame")
	}

	data := make([]byte, 0, len(contextIDZero)+len(b))
	data = append(data, contextIDZero...)
	data = append(data, b...)
	return data, nil
}

func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closeErr == nil {
		c.closeErr = &CloseError{Remote: false}
		close(c.closeChan)
	}
	c.mu.Unlock()
	c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	err := c.str.Close()
	return err
}

// isEthernet checks whether data is a valid Ethernet frame or not
func isEthernet(data []byte) bool {
	// header Ethernet >= 14 bytes (src/dst mac - 6 bytes, type - 2 bytes)
	if len(data) < 14 {
		return false
	}

	etherType := uint16(data[12])<<8 | uint16(data[13])
	return etherType >= 0x0600
}
