package connecteth

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

var validFrameEthernetLLC = []byte{
	0x01, 0x80, 0xC2, 0x00, 0x00, 0x00, // Destination MAC (STP multicast)
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // Source MAC
	0x00, 0x03, // 802.3 Length
	0x42, 0x42, 0x03, // LLC header (STP)
}

var validFrameEthernetIpv4 = []byte{
	0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Destination MAC
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // Source MAC
	0x08, 0x00, // EtherType IPv4
}

var validFrameEthernetIpv6 = []byte{
	0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Destination MAC
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // Source MAC
	0x86, 0xDD, // EtherType IPv6
}

var ipv4Header = []byte{
	0x45, 0x00, 0x00, 0x1C, 0x12, 0x34, 0x40, 0x00, // version 4, DSCP, Length, no fragmentation
	0x40, 0x11, 0x00, 0x00, // TTL, Proto UDP, Checksump
	0x01, 0x00, 0x00, 0x01, // Src IP
	0x01, 0x00, 0x00, 0x02, // Dst IP
}
var ipv6Header = []byte{
	0x60, 0x00, 0x00, 0x00, // Version, Traffic Class, Flow Label
	0x00, 0x20, 59, 64, // Payload Length, Next Header, Hop Limit
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Source IP
	0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x48, // Destination IP
}

type mockStream struct {
	reading         []byte
	toRead          <-chan []byte
	sendDatagramErr error
	datagrams       <-chan []byte
}

var _ http3Stream = &mockStream{}

func (m *mockStream) StreamID() quic.StreamID { panic("implement me") }
func (m *mockStream) Read(p []byte) (int, error) {
	if m.reading == nil {
		m.reading = <-m.toRead
	}
	n := copy(p, m.reading)
	m.reading = m.reading[n:]
	return n, nil
}
func (m *mockStream) CancelRead(quic.StreamErrorCode)   {}
func (m *mockStream) Write(p []byte) (n int, err error) { return len(p), nil }
func (m *mockStream) Close() error                      { return nil }
func (m *mockStream) CancelWrite(quic.StreamErrorCode)  {}
func (m *mockStream) Context() context.Context          { return context.Background() }
func (m *mockStream) SetWriteDeadline(time.Time) error  { return nil }
func (m *mockStream) SetReadDeadline(time.Time) error   { return nil }
func (m *mockStream) SetDeadline(time.Time) error       { return nil }
func (m *mockStream) SendDatagram(data []byte) error    { return m.sendDatagramErr }
func (m *mockStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case d := <-m.datagrams:
		return d, nil
	}
}

// eofStream is a mockStream whose stream data is read from a buffer, returning io.EOF at the end.
type eofStream struct {
	mockStream
	r *bytes.Reader
}

func (s *eofStream) Read(p []byte) (int, error) { return s.r.Read(p) }

func TestIncomingDatagrams(t *testing.T) {
	t.Run("empty frame", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket([]byte{}),
			"connect-ethernet: not an Ethernet packet",
		)
	})
	t.Run("truncated header", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(validFrameEthernetIpv4[:13]),
			"connect-ethernet: not an Ethernet packet",
		)
	})
	t.Run("802.3 frame with LLC header", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.NoError(t, conn.handleIncomingProxiedPacket(validFrameEthernetLLC))
	})
	t.Run("ethernet frame encapsulating IPv4", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.NoError(t, conn.handleIncomingProxiedPacket(validFrameEthernetIpv4))
	})
	t.Run("ethernet frame encapsulating IPv6", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.NoError(t, conn.handleIncomingProxiedPacket(validFrameEthernetIpv6))
	})
}

func TestSendingDatagrams(t *testing.T) {
	t.Run("empty frame", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		_, err := conn.composeDatagram([]byte{})
		require.ErrorContains(t, err, "error composing datagram: invalid Ethernet frame")
	})
	t.Run("truncated header", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		_, err := conn.composeDatagram(validFrameEthernetIpv4[:13])
		require.ErrorContains(t, err, "error composing datagram: invalid Ethernet frame")
	})
	t.Run("802.3 frame with LLC header", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		_, err := conn.composeDatagram(validFrameEthernetLLC)
		require.NoError(t, err)
	})
	t.Run("ethernet frame encapsulating IPv4", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		_, err := conn.composeDatagram(validFrameEthernetIpv4)
		require.NoError(t, err)
	})
	t.Run("ethernet frame encapsulating IPv6", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		_, err := conn.composeDatagram(validFrameEthernetIpv6)
		require.NoError(t, err)
	})
}

func TestSendDroppedFrames(t *testing.T) {
	t.Run("datagram too large", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{sendDatagramErr: &quic.DatagramTooLargeError{}})
		require.NoError(t, conn.WritePacket(validFrameEthernetIpv4))
	})
	t.Run("truncated header", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.NoError(t, conn.WritePacket(validFrameEthernetIpv4[:13]))
	})
}

func TestReceiveDroppedDatagrams(t *testing.T) {
	datagrams := make(chan []byte, 4)
	conn := newProxiedConn(&mockStream{datagrams: datagrams})
	datagrams <- []byte{0x40}                                                      // truncated Context ID varint
	datagrams <- append(quicvarint.Append(nil, 2), validFrameEthernetIpv6...)      // unknown Context ID
	datagrams <- append(quicvarint.Append(nil, 0), validFrameEthernetIpv4[:13]...) // truncated Ethernet header
	datagrams <- append(quicvarint.Append(nil, 0), validFrameEthernetIpv4...)

	b := make([]byte, 1500)
	n, err := conn.ReadPacket(b)
	require.NoError(t, err)
	require.Equal(t, validFrameEthernetIpv4, b[:n])
}

func TestReceiveShortBuffer(t *testing.T) {
	datagrams := make(chan []byte, 1)
	conn := newProxiedConn(&mockStream{datagrams: datagrams})
	datagrams <- append(quicvarint.Append(nil, 0), validFrameEthernetIpv4...)

	_, err := conn.ReadPacket(make([]byte, len(validFrameEthernetIpv4)-1))
	require.ErrorIs(t, err, io.ErrShortBuffer)
}

func TestSkipUnknownCapsules(t *testing.T) {
	var b []byte
	b = quicvarint.Append(b, 0x2a) // unknown capsule type
	b = quicvarint.Append(b, 1)    // length
	b = append(b, 0x00)            // payload: would be parsed as a capsule type if not consumed
	b = quicvarint.Append(b, 0x2b) // another unknown capsule, with empty payload
	b = quicvarint.Append(b, 0)

	c := &Conn{str: &eofStream{r: bytes.NewReader(b)}}
	require.ErrorIs(t, c.readFromStream(), io.EOF)
}
