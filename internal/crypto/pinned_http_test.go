// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPinnedHTTPSClientKeepsTLSOriginAndRejectsUnapprovedEgress(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "https://elsewhere.example/secret", http.StatusFound)
		case "/ok":
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected source path %q", r.URL.Path)
		}
	}))
	defer server.Close()
	caFile := filepath.Join(t.TempDir(), "source-ca.pem")
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	allowed := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	client, err := PinnedHTTPSClient(server.URL, allowed, caFile, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig == nil ||
		transport.TLSClientConfig.MinVersion != tls.VersionTLS12 ||
		transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("pinned client lost TLS verification or enabled a proxy")
	}
	response, err := client.Get(server.URL + "/ok")
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("approved HTTPS origin refused: response=%v err=%v", response, err)
	}
	response.Body.Close()
	response, err = client.Get(server.URL + "/redirect")
	if err != nil || response.StatusCode != http.StatusFound {
		t.Fatalf("redirect was followed or hidden: response=%v err=%v", response, err)
	}
	response.Body.Close()
	if requests != 2 {
		t.Fatalf("approved source saw %d requests, want two", requests)
	}
	blocked, err := PinnedHTTPSClient(server.URL,
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, caFile, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blocked.Get(server.URL + "/ok"); err == nil {
		t.Fatal("unapproved resolved destination was dialed")
	}
	if requests != 2 {
		t.Fatal("rejected destination reached source")
	}
	if _, err := client.Get(strings.Replace(server.URL, "127.0.0.1", "localhost", 1) + "/ok"); err == nil {
		t.Fatal("alternate host was accepted by pinned client")
	}
}

func TestPinnedHTTPSClientRejectsCredentialOrPathInOrigin(t *testing.T) {
	allowed := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	for _, origin := range []string{
		"http://127.0.0.1", "https://user:pass@127.0.0.1",
		"https://127.0.0.1/api", "https://127.0.0.1/?token=secret",
		"https://127.0.0.1/#fragment", "https://127.0.0.1:0",
		"https://127.0.0.1:65536", "https://bad_name.example",
	} {
		if _, err := PinnedHTTPSClient(origin, allowed, "", time.Second); err == nil {
			t.Errorf("unsafe source origin accepted: %s", origin)
		}
	}
	if _, err := PinnedHTTPSClient("https://127.0.0.1", nil, "", time.Second); err == nil {
		t.Fatal("missing deployment egress policy accepted")
	}
	if _, err := PinnedHTTPSClient("https://127.0.0.1", allowed, "", 0); err == nil {
		t.Fatal("unbounded source request accepted")
	}
}
