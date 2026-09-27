package connecteth

import (
	"errors"
	"net/http"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

var contextIDZero = quicvarint.Append([]byte{}, 0)

type Proxy struct{}

// Proxy establishes the Ethernet tunnel, sending a successful response to the client (Sec. 4.5).
// It fails if w doesn't belong to an HTTP/3 request stream: in that case no response has been sent yet,
// so the caller can still respond with an error status code.
func (s *Proxy) Proxy(w http.ResponseWriter, _ *Request) (*Conn, error) {
	// This check must happen before sending the response, otherwise the client would consider the tunnel established.
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		return nil, errors.New("connect-ethernet: response writer is not an HTTP/3 stream")
	}

	// Ethernet proxy response (Sec. 4.5, 8)
	w.Header().Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	w.WriteHeader(http.StatusOK)

	return newProxiedConn(streamer.HTTPStream()), nil
}
