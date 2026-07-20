package connecteth

import (
	"context"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

var invalidFrameEthernet = []byte{
	0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Destination MAC
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // Source MAC
	0x00, 0x00, // EtherType (invalid)
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
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestIncomingDatagrams(t *testing.T) {
	t.Run("empty frame", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket([]byte{}),
			"connect-ethernet: not an Ethernet packet",
		)
	})
	t.Run("invalid ethertype", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(invalidFrameEthernet),
			"connect-ethernet: not an Ethernet packet",
		)
	})
	t.Run("IPv4 packet without Ethernet header", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(ipv4Header),
			"connect-ethernet: not an Ethernet packet",
		)
	})
	t.Run("IPv6 packet without Ethernet header", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(ipv6Header),
			"connect-ethernet: not an Ethernet packet",
		)
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
	t.Run("invalid ethertype", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		_, err := conn.composeDatagram(invalidFrameEthernet)
		require.ErrorContains(t, err, "error composing datagram: invalid Ethernet frame")
	})
	t.Run("IPv4 packet without Ethernet header", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		_, err := conn.composeDatagram(ipv4Header)
		require.ErrorContains(t, err, "error composing datagram: invalid Ethernet frame")
	})
	t.Run("IPv6 packet without Ethernet header", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		_, err := conn.composeDatagram(ipv6Header)
		require.ErrorContains(t, err, "error composing datagram: invalid Ethernet frame")
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

func TestSendLargeDatagrams(t *testing.T) {
	str := &mockStream{sendDatagramErr: &quic.DatagramTooLargeError{}}
	conn := newProxiedConn(str)
	err := conn.WritePacket(validFrameEthernetIpv4)
	require.ErrorContains(t, err, "DATAGRAM frame too large")
}
