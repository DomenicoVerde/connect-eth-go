package connecteth

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

func TestClientInvalidTemplate(t *testing.T) {
	t.Run("vlan", func(t *testing.T) {
		_, _, err := Dial(
			context.Background(),
			nil,
			uritemplate.MustNew("https://example.org/.well-known/masque/ethernet/{vlan_id}/"),
		)
		require.ErrorContains(t, err, "connect-ethernet: VLANs not supported")
	})
	t.Run("uri", func(t *testing.T) {
		_, _, err := Dial(
			context.Background(),
			nil,
			uritemplate.MustNew("https://[::1"),
		)
		require.ErrorContains(t, err, "connect-ethernet: failed to parse URI:")
	})
}

func TestClientWaitForSettings(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	ln, err := quic.Listen(conn, tlsConf, nil)
	require.NoError(t, err)
	defer ln.Close()

	tr := &http3.Transport{}
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	cconn, err := quic.DialAddr(
		ctx,
		conn.LocalAddr().String(),
		&tls.Config{ServerName: "localhost", RootCAs: certPool, NextProtos: []string{http3.NextProtoH3}},
		&quic.Config{EnableDatagrams: true},
	)
	require.NoError(t, err)
	// We're connecting to a QUIC, not an HTTP/3 server.
	// We'll never receive any HTTP/3 settings.
	_, _, err = Dial(
		ctx,
		tr.NewClientConn(cconn),
		uritemplate.MustNew("https://example.org/.well-known/masque/ethernet/"),
	)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestClientDatagramCheck(t *testing.T) {
	s := http3.Server{
		TLSConfig:       tlsConf,
		EnableDatagrams: false,
	}
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	go func() { s.Serve(ln) }()
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cconn, err := quic.DialAddr(
		ctx,
		ln.LocalAddr().String(),
		&tls.Config{ServerName: "localhost", RootCAs: certPool, NextProtos: []string{http3.NextProtoH3}},
		&quic.Config{EnableDatagrams: true},
	)
	require.NoError(t, err)
	defer cconn.CloseWithError(0, "")

	// Create a HTTP/3 client and dial the server
	tr := &http3.Transport{}
	defer tr.Close()

	// Now use the QUIC connection in the Dial call
	_, _, err = Dial(
		context.Background(),
		tr.NewClientConn(cconn),
		uritemplate.MustNew("https://example.org/.well-known/masque/ethernet/"),
	)
	require.ErrorContains(t, err, "connect-ethernet: server didn't enable datagrams")
}

func TestClientAbortOnFailedResponse(t *testing.T) {
	aborted := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			close(aborted)
		case <-time.After(time.Second):
		}
	})
	s := http3.Server{
		Handler:         mux,
		EnableDatagrams: true,
		TLSConfig:       tlsConf,
	}
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	go func() { s.Serve(ln) }()
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cconn, err := quic.DialAddr(
		ctx,
		ln.LocalAddr().String(),
		&tls.Config{ServerName: "localhost", RootCAs: certPool, NextProtos: []string{http3.NextProtoH3}},
		&quic.Config{EnableDatagrams: true},
	)
	require.NoError(t, err)
	defer cconn.CloseWithError(0, "")

	tr := &http3.Transport{EnableDatagrams: true}
	defer tr.Close()

	_, rsp, err := Dial(ctx, tr.NewClientConn(cconn), uritemplate.MustNew("https://localhost/.well-known/masque/ethernet/"))
	require.ErrorContains(t, err, "connect-ethernet: server responded with 403")
	require.Equal(t, http.StatusForbidden, rsp.StatusCode)

	select {
	case <-aborted:
	case <-time.After(time.Second):
		t.Fatal("request stream was not aborted")
	}
}
