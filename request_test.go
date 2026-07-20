package connecteth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

func newRequest(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Method = http.MethodConnect
	req.Proto = requestProtocol
	req.Header.Add("Capsule-Protocol", capsuleProtocolHeaderValue)
	return req
}

func TestConnectEthernetRequestParsing(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		template := uritemplate.MustNew("https://localhost:1234/.well-known/masque/ethernet/")
		req := newRequest("https://localhost:1234/.well-known/masque/ethernet/")
		r, err := ParseRequest(req, template)
		require.NoError(t, err)
		require.Equal(t, &Request{}, r)
	})

	t.Run("reject templates with variables", func(t *testing.T) {
		template := uritemplate.MustNew("https://localhost:1234/.well-known/masque/ethernet/{vlan_id}/")
		req := newRequest("https://localhost:1234/.well-known/masque/ethernet/32/")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "connect-ethernet currently does not support template variables")
	})

	t.Run("bad url internal server error", func(t *testing.T) {
		template := uritemplate.MustNew("https://[::1")
		req := newRequest("https://localhost:1234/.well-known/masque/ethernet/")
		_, err := ParseRequest(req, template)
		require.Equal(t, http.StatusInternalServerError, err.(*RequestParseError).HTTPStatus)
	})

	template := uritemplate.MustNew("https://localhost:1234/.well-known/masque/ethernet/")

	t.Run("wrong protocol", func(t *testing.T) {
		req := newRequest("https://localhost:1234/.well-known/masque/ethernet/")
		req.Proto = "not-connect-ethernet"
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "unexpected protocol: not-connect-ethernet")
		require.Equal(t, http.StatusNotImplemented, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("wrong url path", func(t *testing.T) {
		req := newRequest("https://localhost:1234/.well-known/masque/not-ethernet/")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "path (/.well-known/masque/not-ethernet/) does not match template path (/.well-known/masque/ethernet/)")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("wrong request method", func(t *testing.T) {
		req := newRequest("https://localhost:1234/.well-known/masque/ethernet/")
		req.Method = http.MethodHead
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "expected CONNECT request, got HEAD")
		require.Equal(t, http.StatusMethodNotAllowed, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("wrong :authority", func(t *testing.T) {
		req := newRequest("https://quic-go.net:1234/.well-known/masque/ethernet/")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "host in :authority (quic-go.net:1234) does not match template host (localhost:1234)")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("missing Capsule-Protocol header", func(t *testing.T) {
		req := newRequest("https://localhost:1234/.well-known/masque/ethernet/")
		req.Header.Del("Capsule-Protocol")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "missing Capsule-Protocol header")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("invalid Capsule-Protocol header", func(t *testing.T) {
		req := newRequest("https://localhost:1234/.well-known/masque/ethernet/")
		req.Header.Set("Capsule-Protocol", "🤡")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "invalid capsule header value: [🤡]")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("invalid Capsule-Protocol header value type", func(t *testing.T) {
		req := newRequest("https://localhost:1234/.well-known/masque/ethernet/")
		req.Header.Set("Capsule-Protocol", "1")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "incorrect capsule header value type: int64")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("invalid Capsule-Protocol header value", func(t *testing.T) {
		req := newRequest("https://localhost:1234/.well-known/masque/ethernet/")
		v, err := httpsfv.Marshal(httpsfv.NewItem(false))
		require.NoError(t, err)
		req.Header.Set("Capsule-Protocol", v)
		_, err = ParseRequest(req, template)
		require.EqualError(t, err, "incorrect capsule header value: false")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})
}
