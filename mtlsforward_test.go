package mtlsforward_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pvliesdonk/mtlsforward"
)

func TestDemo(t *testing.T) {
	cfg := mtlsforward.CreateConfig()
	cfg.Headers["sslClientCert"] = "SSL_CLIENT_CERT"
	cfg.Headers["sslCertChainPrefix"] = "CERT_CHAIN"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := mtlsforward.New(ctx, next, cfg, "mtlsforward")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	assertHeader(t, req, "SSL_CLIENT_CERT", "contents")
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("invalid header value: %s", req.Header.Get(key))
	}
}
