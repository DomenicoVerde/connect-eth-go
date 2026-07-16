package connecteth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// Dial starts a connection to a target Ethernet proxy (Sec. 4.4, 8)
func Dial(ctx context.Context, conn *http3.ClientConn, template *uritemplate.Template) (*Conn, *http.Response, error) {
	if len(template.Varnames()) > 0 {
		return nil, nil, errors.New("connect-ethernet: IP flow forwarding not supported")
	}

	u, err := url.Parse(template.Raw())
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ethernet: failed to parse URI: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, nil, context.Cause(ctx)
	case <-conn.Context().Done():
		return nil, nil, context.Cause(conn.Context())
	case <-conn.ReceivedSettings():
	}
	settings := conn.Settings()
	if !settings.EnableExtendedConnect {
		return nil, nil, errors.New("connect-ethernet: server didn't enable Extended CONNECT")
	}
	if !settings.EnableDatagrams {
		return nil, nil, errors.New("connect-ethernet: server didn't enable datagrams")
	}

	rstr, err := conn.OpenRequestStream(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ethernet: failed to open request stream: %w", err)
	}
	if err := rstr.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  requestProtocol,
		Host:   u.Host,
		Header: http.Header{http3.CapsuleProtocolHeader: []string{capsuleProtocolHeaderValue}},
		URL:    u,
	}); err != nil {
		return nil, nil, fmt.Errorf("connect-ethernet: failed to send request: %w", err)
	}

	rsp, err := rstr.ReadResponse()
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ethernet: failed to read response: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		return nil, rsp, fmt.Errorf("connect-ethernet: server responded with %d", rsp.StatusCode)
	}
	return newProxiedConn(rstr), rsp, nil
}
