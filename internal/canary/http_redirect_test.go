// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary_test

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/crypto"
)

func TestHTTPRedirectVerifiesEachDestinationAndKeepsProbeTrustIsolated(t *testing.T) {
	dir := t.TempDir()
	canary.SetCAFileDir(dir)
	t.Cleanup(func() { canary.SetCAFileDir("") })
	type lane struct {
		name, file string
		ca         *crypto.CA
	}
	lanes := []lane{{name: "red"}, {name: "blue"}}
	for i := range lanes {
		var err error
		lanes[i].ca, err = crypto.GenerateCA("redirect-"+lanes[i].name, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		lanes[i].file = filepath.Join(dir, lanes[i].name+".crt")
		if err := os.WriteFile(lanes[i].file, lanes[i].ca.CertPEM(), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i, own := range lanes {
		for _, scenario := range []struct {
			name                  string
			destinationHost       string
			foreignCA, plainStart bool
			wantSuccess           bool
		}{
			{name: "reject_original_name_at_redirect_IP", destinationHost: "localhost"},
			{name: "accept_redirect_IP_name", destinationHost: "127.0.0.1", wantSuccess: true},
			{name: "reject_foreign_trust", destinationHost: "127.0.0.1", foreignCA: true},
			{name: "HTTP_to_HTTPS_keeps_configured_trust", destinationHost: "127.0.0.1", plainStart: true, wantSuccess: true},
			{name: "HTTP_to_HTTPS_rejects_foreign_trust", destinationHost: "127.0.0.1", plainStart: true, foreignCA: true},
		} {
			t.Run(own.name+"/"+scenario.name, func(t *testing.T) {
				issuer := own.ca
				if scenario.foreignCA {
					issuer = lanes[1-i].ca
				}
				var hits atomic.Int32
				destination := redirectProbeTLS(t, issuer, scenario.destinationHost, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					hits.Add(1)
					w.WriteHeader(http.StatusOK)
				}))
				redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, destination.URL, http.StatusFound)
				})
				var origin *httptest.Server
				if scenario.plainStart {
					origin = httptest.NewServer(redirect)
					t.Cleanup(origin.Close)
				} else {
					origin = redirectProbeTLS(t, own.ca, "localhost", redirect)
				}
				target, err := url.Parse(origin.URL)
				if err != nil {
					t.Fatal(err)
				}
				target.Host = "localhost:" + target.Port()
				probe, err := canary.NewHTTP(canary.Config{Type: "http", Target: target.String(), Timeout: 5 * time.Second,
					Params: map[string]string{canary.AllowPrivateParam: "true", "ca_file": own.file}})
				if err != nil {
					t.Fatal(err)
				}
				result, err := probe.Run(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if result.Success != scenario.wantSuccess {
					t.Fatalf("redirect destination TLS result=%v want=%v response_status=%s", result.Success, scenario.wantSuccess, result.Attributes["http.response.status_code"])
				}
				if scenario.wantSuccess {
					if hits.Load() != 1 || result.Attributes["probectl.tls.server.verified"] != "true" {
						t.Fatal("valid destination was not requested through its own verified TLS connection", hits.Load(), result.Attributes["probectl.tls.server.verified"])
					}
					if result.HTTP == nil || result.HTTP.StatusCode != http.StatusOK || !result.HTTP.TLSVerified || result.HTTP.SameOrigin {
						t.Fatal("redirect response facts lost actual TLS or claimed the configured origin", result.HTTP)
					}
				} else if hits.Load() != 0 || result.Attributes["http.response.status_code"] != "" {
					t.Fatal("request reached an unverified redirect destination", hits.Load())
				}
				if !scenario.wantSuccess && result.HTTP != nil {
					t.Fatal("a refused request or posture handshake created primary response facts", result.HTTP)
				}
				if result.Target != target.String() || !strings.HasPrefix(result.Attributes["url.full"], target.String()) {
					t.Fatal("redirect replaced the configured probe identity")
				}
			})
		}
	}
}

func redirectProbeTLS(t *testing.T, ca *crypto.CA, host string, handler http.Handler) *httptest.Server {
	t.Helper()
	cert, key, err := ca.IssueServerCert(host, []string{host}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}
