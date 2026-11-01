// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type fixtureTokenResolver struct {
	resolves int
	releases int
}

func (r *fixtureTokenResolver) ResolveBytesUncached(context.Context, string) ([]byte, func(), error) {
	r.resolves++
	value := []byte("fixture")
	return value, func() {
		for i := range value {
			value[i] = 0
		}
		r.releases++
	}, nil
}

type fixtureSourceTransport func(*http.Request) (*http.Response, error)

func (f fixtureSourceTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLibreNMSHTTPSourceUsesFixedPathsAndReleasesBearer(t *testing.T) {
	resolver := &fixtureTokenResolver{}
	var paths []string
	source := &LibreNMSHTTPSource{
		origin: "https://nms.example", credentialRef: "env:SOURCE_TOKEN", resolver: resolver,
		client: &http.Client{Transport: fixtureSourceTransport(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.Host != "nms.example" ||
				r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer fixture" ||
				r.Header.Get("Accept") != "application/json" {
				t.Fatalf("source request escaped its fixed origin or lost bearer policy: %s", r.URL.Redacted())
			}
			paths = append(paths, r.URL.EscapedPath())
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"status":"ok"}`)), Header: make(http.Header)}, nil
		})},
	}
	for _, resource := range []string{"devices", "locations", "groups", "rules"} {
		body, err := source.Open(context.Background(), resource)
		if err != nil {
			t.Fatal(err)
		}
		body.Close()
	}
	body, err := source.OpenMembership(context.Background(), "Linux Servers")
	if err != nil {
		t.Fatal(err)
	}
	body.Close()
	want := []string{"/api/v0/devices", "/api/v0/resources/locations",
		"/api/v0/devicegroups", "/api/v0/rules", "/api/v0/devicegroups/Linux%20Servers"}
	if len(paths) != len(want) {
		t.Fatalf("paths=%v", paths)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Fatalf("path %d=%q, want %q", i, paths[i], want[i])
		}
	}
	if resolver.resolves != len(want) || resolver.releases != len(want) {
		t.Fatalf("token lease not released per request: %+v", resolver)
	}
	for _, name := range []string{"", ".", "..", "../admin", "a/b", `a\b`, "%2f", " leading"} {
		if _, err := source.OpenMembership(context.Background(), name); !errors.Is(err, ErrSourceUnavailable) {
			t.Errorf("unsafe group path %q accepted: %v", name, err)
		}
	}
	if _, err := source.Open(context.Background(), "../../admin"); !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("unlisted source endpoint accepted: %v", err)
	}
	if resolver.resolves != len(want) {
		t.Fatal("invalid path resolved a credential")
	}
}

func TestLibreNMSHTTPSourceHidesNonSuccessBody(t *testing.T) {
	resolver := &fixtureTokenResolver{}
	body := &observedSourceBody{Reader: strings.NewReader("source-only-secret")}
	source := &LibreNMSHTTPSource{origin: "https://nms.example", credentialRef: "env:SOURCE_TOKEN",
		resolver: resolver, client: &http.Client{Transport: fixtureSourceTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusFound, Body: body, Header: make(http.Header)}, nil
		}), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	result, err := source.Open(context.Background(), "devices")
	if result != nil || !errors.Is(err, ErrSourceUnavailable) ||
		strings.Contains(err.Error(), "source-only-") || body.reads != 0 || !body.closed ||
		resolver.releases != 1 {
		t.Fatalf("non-success source leaked body or token: body=%v err=%v reads=%d closed=%v releases=%d",
			result, err, body.reads, body.closed, resolver.releases)
	}
}

type observedSourceBody struct {
	io.Reader
	reads  int
	closed bool
}

func (b *observedSourceBody) Read(p []byte) (int, error) { b.reads++; return b.Reader.Read(p) }
func (b *observedSourceBody) Close() error               { b.closed = true; return nil }

func TestLibreNMSHTTPSourceRequiresReferenceAndEgressPolicy(t *testing.T) {
	resolver := &fixtureTokenResolver{}
	for _, ref := range []string{"", "literal:fixture", "fixture"} {
		if _, err := NewLibreNMSHTTPSource("https://nms.example", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			"", ref, resolver, time.Second); !errors.Is(err, ErrSourceUnavailable) {
			t.Fatalf("plaintext credential %q accepted: %v", ref, err)
		}
	}
	if _, err := NewLibreNMSHTTPSource("https://nms.example", nil, "", "env:SOURCE_TOKEN",
		resolver, time.Second); !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("source without deployment egress policy accepted: %v", err)
	}
}
