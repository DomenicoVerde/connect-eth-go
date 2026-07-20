package connecteth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

func setupConns(t *testing.T) (client, server *Conn) {
	t.Helper()

	p := &Proxy{}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	template := uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/.well-known/masque/ethernet/", conn.LocalAddr().(*net.UDPAddr).Port))
	connChan := make(chan *Conn, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mreq, err := ParseRequest(r, template)
		require.NoError(t, err)

		conn, err := p.Proxy(w, mreq)
		require.NoError(t, err)
		connChan <- conn
	})
	s := http3.Server{
		Handler:         mux,
		Addr:            ":0",
		EnableDatagrams: true,
		TLSConfig:       tlsConf,
	}
	go func() { s.Serve(conn) }()
	t.Cleanup(func() { s.Close() })

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { udpConn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cconn, err := quic.Dial(
		ctx,
		udpConn,
		conn.LocalAddr(),
		&tls.Config{ServerName: "localhost", RootCAs: certPool, NextProtos: []string{http3.NextProtoH3}},
		&quic.Config{EnableDatagrams: true},
	)
	require.NoError(t, err)
	tr := &http3.Transport{EnableDatagrams: true}
	t.Cleanup(func() { tr.Close() })

	client, rsp, err := Dial(ctx, tr.NewClientConn(cconn), template)
	require.NoError(t, err)
	require.Equal(t, rsp.StatusCode, http.StatusOK)

	select {
	case <-time.After(time.Second):
		t.Fatal("timed out")
	case conn := <-connChan:
		return client, conn
	}
	return client, server
}

func TestWriteReadPackets(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		client, server := setupConns(t)
		err := client.WritePacket(validFrameEthernetIpv4)
		require.NoError(t, err)

		receivedPacket := make([]byte, 1500)
		n, err := server.ReadPacket(receivedPacket)
		require.NoError(t, err)
		receivedPacket = receivedPacket[:n]
		require.Equal(t, validFrameEthernetIpv4, receivedPacket)
	})

	t.Run("IPv6", func(t *testing.T) {
		client, server := setupConns(t)
		err := client.WritePacket(validFrameEthernetIpv6)
		require.NoError(t, err)

		receivedPacket := make([]byte, 1500)
		n, err := server.ReadPacket(receivedPacket)
		require.NoError(t, err)
		receivedPacket = receivedPacket[:n]
		require.Equal(t, validFrameEthernetIpv6, receivedPacket)
	})
}

func TestClosing(t *testing.T) {
	client, server := setupConns(t)

	require.NoError(t, client.Close())

	_, err := client.ReadPacket([]byte{0})
	require.ErrorIs(t, err, net.ErrClosed)

	err = client.WritePacket(validFrameEthernetIpv4)
	require.ErrorIs(t, err, net.ErrClosed)

	_, err = server.ReadPacket([]byte{0})
	require.ErrorIs(t, err, net.ErrClosed)

	err = server.WritePacket(validFrameEthernetIpv6)
	require.ErrorIs(t, err, net.ErrClosed)
}
