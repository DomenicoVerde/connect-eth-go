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

// CloseError is returned by ReadPacket and WritePacket once the connection is closed.
// It matches net.ErrClosed when checked with errors.Is.
type CloseError struct {
	// Remote is true if the connection was closed by the peer, false if it was closed locally by calling Close.
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
			c.setClosed(&CloseError{Remote: true})
		}
	}()
	// In future versions a c.writeToStream() may be needed
	return c
}

// readFromStream reads HTTP/3 capsules from the stream, and is used to track whether the connection is closed.
// The draft doesn't define any capsule, so all capsules are unknown and silently skipped (RFC 9297, Sec. 3.2).
func (c *Conn) readFromStream() error {
	defer c.str.Close()
	r := quicvarint.NewReader(c.str)
	for {
		_, cr, err := http3.ParseCapsule(r)
		if err != nil {
			return err
		}
		// The payload must be consumed, otherwise it would be parsed as the next capsule.
		if _, err := io.Copy(io.Discard, cr); err != nil {
			return err
		}
	}
}

// ReadPacket reads an Ethernet frame over the HTTP/3 connection.
// Malformed datagrams and datagrams with an unknown Context ID are silently dropped.
// If b is too small to hold the frame, the frame is dropped and io.ErrShortBuffer is returned.
func (c *Conn) ReadPacket(b []byte) (n int, err error) {
start:
	data, err := c.str.ReceiveDatagram(context.Background())
	if err != nil {
		// ReceiveDatagram only fails once the stream is gone. Mark the connection as closed here,
		// without racing with readFromStream to notice it.
		return 0, c.setClosed(&CloseError{Remote: true})
	}
	contextID, n, err := quicvarint.Parse(data)
	if err != nil {
		log.Printf("dropping malformed datagram: %s", err)
		goto start
	}
	if contextID != 0 {
		// Drop this datagram. We only support proxying of Ethernet payloads with Context ID set to 0 (Sec. 5)
		goto start
	}
	if err := c.handleIncomingProxiedPacket(data[n:]); err != nil {
		log.Printf("dropping proxied packet: %s", err)
		goto start
	}
	if len(b) < len(data[n:]) {
		return 0, fmt.Errorf("connect-ethernet: frame (%d bytes) too large for buffer (%d bytes): %w", len(data[n:]), len(b), io.ErrShortBuffer)
	}
	return copy(b, data[n:]), nil
}

func (c *Conn) handleIncomingProxiedPacket(data []byte) error {
	// We don't necessarily assign any addresses to the peer, since it is L2 proxying.
	// In addition, in the Remote Access VPN use case (Section 8.1),
	// the client accepts incoming traffic from all IPs, thus it makes no sense to save the IP in the conn.

	// The destination IP address is always valid, since the proxy acts as a L2 bridge. ARP resolution and other stuff
	// is left to the OS.

	// We check only that the frame is long enough to contain an Ethernet header.
	if !isEthernet(data) {
		return errors.New("connect-ethernet: not an Ethernet packet")
	}

	return nil
}

// WritePacket encapsulates and sends an Ethernet frame over the HTTP/3 connection.
// Frames that can't be proxied (too short, or too large to fit in a datagram) are dropped (Sec. 7),
// and no error is returned. An error is returned only if the connection can't be used anymore.
func (c *Conn) WritePacket(b []byte) (err error) {
	data, err := c.composeDatagram(b)
	if err != nil {
		log.Printf("dropping proxied packet (%d bytes) that can't be proxied: %s", len(b), err)
		return nil
	}

	if err := c.str.SendDatagram(data); err != nil {
		var errDTL *quic.DatagramTooLargeError
		if errors.As(err, &errDTL) {
			log.Printf("dropping proxied packet: datagram too large (%d bytes)", len(data))
			return nil
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

// setClosed marks the connection as closed, unless it was already, and returns the close error.
func (c *Conn) setClosed(err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closeErr == nil {
		c.closeErr = err
		close(c.closeChan)
	}
	return c.closeErr
}

// Close closes the connection, aborting the underlying HTTP/3 request stream.
func (c *Conn) Close() error {
	c.setClosed(&CloseError{Remote: false})
	c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	err := c.str.Close()
	return err
}

// isEthernet checks whether data is long enough to be an Ethernet frame.
// The EtherType/Length field is not checked: values below 0x0600 are 802.3 length fields
// (e.g. LLC frames such as STP BPDUs), and must be proxied as well.
func isEthernet(data []byte) bool {
	// header Ethernet >= 14 bytes (dst/src mac - 6 bytes each, EtherType/Length - 2 bytes)
	return len(data) >= 14
}
