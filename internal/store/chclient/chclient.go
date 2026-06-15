// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package chclient is the shared ClickHouse HTTP-interface client used by every
// ClickHouse-backed store (flowstore, otelstore, pathstore, ebpfstore). Those
// stores had each hand-rolled the SAME transport: a circuit-breaker wrapper, a
// JSONEachRow row decoder, a param_* query-string builder, and the
// any→float/string/int coercions — four near-identical copies that drifted
// (only one had per-target breakers). CODE-006 extracts them here once:
//
//   - Conn: a hardened (TLS-validated) HTTP client with a circuit breaker PER
//     data-plane endpoint (SCALE-021 — one down silo never trips another), and
//     Do/Stats over it.
//   - Decode: the JSONEachRow → []map[string]any parse.
//   - Params: the server-bound param_* query-string (values never enter SQL).
//   - Float/String/Int/UintSlice/Count: the result coercions.
//
// Stores keep their own DDL, routing, and tenant-scoping logic and build their
// SQL; chclient owns only the wire transport + decode, so a fix (e.g. the
// per-target breaker) lands once for all four.
package chclient

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/breaker"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// MaxResponseBytes bounds how many bytes a single ClickHouse HTTP response body
// is read into memory on the result-read path (RED-003a / SCALE-001). The
// ClickHouse endpoint is authenticated infrastructure, but a huge or malicious
// response (a runaway query, a compromised/spoofed data plane) must not be
// buffered without limit: an unbounded io.ReadAll on a multi-GiB body is an
// all-tenant memory DoS in the shared control plane. 64 MiB comfortably holds
// any legitimate JSONEachRow result the stores aggregate (top-talkers,
// capacity buckets, counts) while turning an oversized body into a bounded
// error instead of an allocation.
const MaxResponseBytes = 64 << 20 // 64 MiB

// ErrResponseTooLarge is returned by ReadResponseBody when the ClickHouse
// response exceeds MaxResponseBytes. It is a fail-closed signal: the caller
// errors the read rather than returning a truncated (and therefore wrong) decode.
var ErrResponseTooLarge = fmt.Errorf("chclient: clickhouse response exceeds %d-byte limit", MaxResponseBytes)

// ReadResponseBody reads a ClickHouse HTTP response body into memory under a
// hard MaxResponseBytes cap (RED-003a / SCALE-001). It reads at most
// MaxResponseBytes+1 via an io.LimitReader and treats hitting the +1 sentinel
// byte as an overflow — so an oversized/malicious body returns
// ErrResponseTooLarge after allocating ≤64 MiB, never the full body. Every
// store's live ClickHouse read funnels through this one helper (the CODE-006
// shared-transport seam), so the bound holds for flowstore, ebpfstore,
// pathstore, and otelstore on the path the consumer actually calls.
func ReadResponseBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, MaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("chclient: read clickhouse response: %w", err)
	}
	if len(body) > MaxResponseBytes {
		return nil, ErrResponseTooLarge
	}
	return body, nil
}

// errServerError is the sentinel the breaker callback returns for an
// upstream-fault HTTP response (5xx / 429). It counts the response as a breaker
// failure (RESIL-005: an up-but-erroring store must short-circuit too) while the
// response still escapes to the caller, which keeps the body/status. Do strips
// this sentinel so callers see a successful transport with the real response.
var errServerError = errors.New("chclient: upstream server error (5xx/429)")

// serverFault reports whether an HTTP status is an upstream fault that should
// count against the circuit breaker: 5xx (server error) or 429 (overload).
func serverFault(status int) bool {
	return status >= 500 || status == http.StatusTooManyRequests
}

// Conn is a breaker-guarded ClickHouse HTTP connection. The zero value is not
// usable; call New.
type Conn struct {
	def      *breaker.Breaker
	client   *http.Client
	breakers sync.Map // baseURL -> *breaker.Breaker (per-target, SCALE-021)
}

// New builds a Conn with the hardened HTTP client (TLS 1.2+/AEAD/always-verify
// for https endpoints; plain http loopback unaffected — U-036) and a default
// circuit breaker for the pooled endpoint.
func New(timeout time.Duration) *Conn {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Conn{def: breaker.New(0, 0), client: crypto.HardenedHTTPClient(timeout)}
}

// BreakerFor returns the circuit breaker for a routed endpoint: the pooled
// default ("") uses the long-lived breaker; each siloed BaseURL gets its own so
// one silo's outage can't trip another's writes (SCALE-021).
func (c *Conn) BreakerFor(base string) *breaker.Breaker {
	if base == "" {
		return c.def
	}
	key := strings.TrimRight(base, "/")
	if b, ok := c.breakers.Load(key); ok {
		return b.(*breaker.Breaker)
	}
	b, _ := c.breakers.LoadOrStore(key, breaker.New(0, 0))
	return b.(*breaker.Breaker)
}

// Do issues req through the circuit breaker for the given data-plane endpoint
// (base "" = the pooled default). The response escapes to the caller, which
// must close it.
func (c *Conn) Do(base string, req *http.Request) (*http.Response, error) {
	var resp *http.Response
	err := c.BreakerFor(base).Do(func() error {
		r, e := c.client.Do(req) //nolint:bodyclose // escapes to the caller
		if e != nil {
			return e
		}
		resp = r
		// RESIL-005: a completed-but-5xx/429 response is an upstream fault.
		// Count it against the breaker (return the sentinel) but still surface
		// the response — Do strips the sentinel below so the caller can read
		// the body/status.
		if serverFault(r.StatusCode) {
			return errServerError
		}
		return nil
	})
	if errors.Is(err, errServerError) {
		err = nil
	}
	return resp, err
}

// Stats exposes the default (pooled) breaker's state for fallback metrics.
func (c *Conn) Stats() breaker.Stats { return c.def.Stats() }

// Params carries SERVER-BOUND query parameters: each key k is sent as param_k
// and bound by ClickHouse to the {k:Type} placeholder, so a value is data, not
// SQL syntax — no client-side escaping, no injection surface.
type Params map[string]string

// QS renders the &param_*=... suffix ("" for no params).
func (p Params) QS() string {
	if len(p) == 0 {
		return ""
	}
	var sb strings.Builder
	for k, v := range p {
		sb.WriteString("&param_")
		sb.WriteString(urlEscape(k))
		sb.WriteString("=")
		sb.WriteString(urlEscape(v))
	}
	return sb.String()
}
