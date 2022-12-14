// Package mtlsforward implements a middleware for
// Traefik Proxy that forwards mTLS certificates inside
// HTTP headers.
package mtlsforward

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// Config handles configuration of the sslClientCert (e.g. SSL_CLIENT_CERT) and sslCertChainPrefix (e.g. SSL_CERT_CHAIN) headers.
type Config struct {
	Headers map[string]string
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Headers: make(map[string]string),
	}
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	_, ok := config.Headers["sslClientCert"]
	if !ok {
		return nil, fmt.Errorf("configuration option 'sslClientCert' not set")
	}
	_, ok = config.Headers["sslCertChainPrefix"]
	if !ok {
		return nil, fmt.Errorf("configuration option 'sslCertChainPrefix' not set")
	}

	return &mTLSForward{
		headers: config.Headers,
		next:    next,
		name:    name,
	}, nil
}

type mTLSForward struct {
	headers map[string]string
	next    http.Handler
	name    string
}

func (m mTLSForward) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	// are we using mTLS?
	if request.TLS != nil && len(request.TLS.PeerCertificates) > 0 {
		for i, cert := range request.TLS.PeerCertificates {
			fmt.Println("Found certificate with subject", cert.Subject, "issued by", cert.Issuer)
			certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
			if i == 0 {
				// client cert
				fmt.Println(string(certPEM))
				request.Header.Set(m.headers["sslClientCert"], url.QueryEscape(string(certPEM)))
			} else {
				// part of chain
				headerName := m.headers["sslCertChainPrefix"] + "_" + strconv.Itoa(i-1)
				fmt.Println(string(certPEM))
				request.Header.Set(headerName, url.QueryEscape(string(certPEM)))
			}
		}
	}
	fmt.Println("Ready for next plugin")

	// call to next plugin
	m.next.ServeHTTP(writer, request)
}
