// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package transport provides the hardened HTTP client and bounded body reader
// the MPL-2.0 client SDK (pkg/sdk) needs — reimplemented here so the SDK carries
// NO dependency on the BUSL-1.1 core (internal/crypto, internal/httpbody). This
// keeps pkg/, proto/ and examples/ a clean MPL-2.0 tree (PLAT-12); a CI
// license-boundary gate asserts `go list -deps ./pkg/...` imports no internal/
// or ee/ package.
package transport

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// MaxClientResponseBodyBytes caps a successful HTTP response one SDK call buffers.
	MaxClientResponseBodyBytes int64 = 32 << 20
	// MaxClientErrorResponseBodyBytes is the tighter cap for error envelopes.
	MaxClientErrorResponseBodyBytes int64 = 1 << 20

	maxRedirects = 5
)

// ErrTooLarge reports an HTTP body that exceeded its documented cap.
var ErrTooLarge = errors.New("probectl sdk transport: body too large")

// HardenedHTTPClient returns an HTTP client with a TLS 1.2+ AEAD-only floor,
// certificate verification on (the default), HTTP/2 attempted,
// HTTPS_PROXY/HTTP_PROXY/NO_PROXY honored, and redirects capped — the same
// outbound posture as the control plane's hardened client, without the BUSL
// dependency.
func HardenedHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: limitRedirects,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				},
				CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
			},
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
}

func limitRedirects(_ *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("probectl sdk transport: redirect rejected after %d hops", maxRedirects)
	}
	return nil
}

// ReadLimited reads up to maxBytes from r (reading one extra byte to detect
// overflow), returning ErrTooLarge if the body exceeds the cap.
func ReadLimited(r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes < 0 {
		return nil, fmt.Errorf("probectl sdk transport: negative limit %d", maxBytes)
	}
	b, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, ErrTooLarge
	}
	return b, nil
}
