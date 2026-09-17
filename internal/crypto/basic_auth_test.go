// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package crypto

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

type basicAuthRoundTripFunc func(*http.Request) (*http.Response, error)

func (f basicAuthRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func basicAuthRequestError(client *http.Client, req *http.Request) error {
	response, err := client.Do(req)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	return err
}

func TestBasicAuthHTTPClientBindsCredentialToOrigin(t *testing.T) {
	path := writeBasicAuthTestFile(t, `{"username":"audit","password":"not-logged"}`)
	client, err := BasicAuthHTTPClient(time.Second, "https://clickhouse.example:8443/base", path)
	if err != nil {
		t.Fatalf("BasicAuthHTTPClient: %v", err)
	}
	transport := client.Transport.(*originBasicAuthTransport)
	transport.base = basicAuthRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("audit:not-logged"))
		if got := req.Header.Get("Authorization"); got != want {
			t.Fatalf("Authorization = %q, want Basic credential", got)
		}
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})

	req, _ := http.NewRequest(http.MethodGet, "https://clickhouse.example:8443/base/query", nil)
	response, err := client.Do(req)
	if err != nil {
		t.Fatalf("same-origin request: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("close same-origin response: %v", err)
	}

	cross, _ := http.NewRequest(http.MethodGet, "https://other.example:8443/query", nil)
	if err := basicAuthRequestError(client, cross); err == nil || !strings.Contains(err.Error(), "different origin") {
		t.Fatalf("cross-origin error = %v, want origin refusal", err)
	} else if strings.Contains(err.Error(), "not-logged") {
		t.Fatalf("cross-origin error leaked password: %v", err)
	}

	downgrade, _ := http.NewRequest(http.MethodGet, "http://clickhouse.example:8443/query", nil)
	if err := basicAuthRequestError(client, downgrade); err == nil || !strings.Contains(err.Error(), "different origin") {
		t.Fatalf("scheme-change error = %v, want origin refusal", err)
	}

	outsidePath, _ := http.NewRequest(http.MethodGet, "https://clickhouse.example:8443/other-service", nil)
	if err := basicAuthRequestError(client, outsidePath); err == nil || !strings.Contains(err.Error(), "path prefix") {
		t.Fatalf("outside-prefix error = %v, want path refusal", err)
	}
	traversal, _ := http.NewRequest(http.MethodGet, "https://clickhouse.example:8443/base/../other-service", nil)
	if err := basicAuthRequestError(client, traversal); err == nil || !strings.Contains(err.Error(), "path prefix") {
		t.Fatalf("traversal error = %v, want path refusal", err)
	}
	hostOverride, _ := http.NewRequest(http.MethodGet, "https://clickhouse.example:8443/base/query", nil)
	hostOverride.Host = "other-vhost.example:8443"
	if err := basicAuthRequestError(client, hostOverride); err == nil || !strings.Contains(err.Error(), "Host override") {
		t.Fatalf("Host override error = %v, want refusal", err)
	}
	opaque := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "https", Host: "clickhouse.example:8443", Opaque: "//other-vhost.example/base/query"},
		Header: make(http.Header),
	}
	if err := basicAuthRequestError(client, opaque); err == nil || !strings.Contains(err.Error(), "opaque") {
		t.Fatalf("opaque target error = %v, want refusal", err)
	}
}

func TestBasicAuthCredentialFileRejectsAmbiguousOrUnsafeInput(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "duplicate", body: `{"username":"a","username":"b","password":"p"}`, want: "duplicate field"},
		{name: "unknown", body: `{"username":"a","password":"p","token":"x"}`, want: "unknown field"},
		{name: "trailing", body: `{"username":"a","password":"p"}{}`, want: "exactly one"},
		{name: "empty", body: `{"username":"a","password":""}`, want: "non-empty"},
		{name: "colon username", body: `{"username":"a:b","password":"p"}`, want: "invalid control"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeBasicAuthTestFile(t, tc.body)
			_, err := BasicAuthHTTPClient(time.Second, "https://store.example", path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestBasicAuthCredentialFileRequiresOwnerOnlyRegularFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission contract")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "credential.json")
	if err := os.WriteFile(target, []byte(`{"username":"a","password":"p"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := BasicAuthHTTPClient(time.Second, "https://store.example", target); err == nil || !strings.Contains(err.Error(), "want 0600") {
		t.Fatalf("mode error = %v, want 0600 refusal", err)
	}
	if err := os.Chmod(target, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "credential-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := BasicAuthHTTPClient(time.Second, "https://store.example", link); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink error = %v, want refusal", err)
	}
}

func TestBasicAuthCredentialFileRejectsPermissionChangeAfterInitialLstat(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission contract")
	}
	path := writeBasicAuthTestFile(t, `{"username":"a","password":"p"}`)
	_, err := readBasicAuthCredentialFileWithHook(path, func() {
		if chmodErr := os.Chmod(path, 0o644); chmodErr != nil {
			t.Fatal(chmodErr)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "changed while opening") {
		t.Fatalf("error = %v, want post-open permission refusal", err)
	}
}

func TestBasicAuthCredentialFileRejectsReplacementAfterInitialLstat(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX replacement contract")
	}
	path := writeBasicAuthTestFile(t, `{"username":"a","password":"generation-one"}`)
	_, err := readBasicAuthCredentialFileWithHook(path, func() {
		replacement := filepath.Join(filepath.Dir(path), "replacement.json")
		if writeErr := os.WriteFile(replacement, []byte(`{"username":"a","password":"generation-two"}`), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
		if renameErr := os.Rename(replacement, path); renameErr != nil {
			t.Fatal(renameErr)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "changed while opening") {
		t.Fatalf("error = %v, want replacement refusal", err)
	}
}

func TestBasicAuthCredentialFileRejectsFIFOReplacementWithoutBlocking(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX FIFO contract")
	}
	path := writeBasicAuthTestFile(t, `{"username":"a","password":"p"}`)
	started := time.Now()
	_, err := readBasicAuthCredentialFileWithHook(path, func() {
		if removeErr := os.Remove(path); removeErr != nil {
			t.Fatal(removeErr)
		}
		if fifoErr := syscall.Mkfifo(path, 0o600); fifoErr != nil {
			t.Fatal(fifoErr)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "changed while opening") {
		t.Fatalf("error = %v, want FIFO replacement refusal", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("FIFO replacement blocked credential loading for %s", elapsed)
	}
}

func TestBasicAuthEndpointRejectsURLCredentials(t *testing.T) {
	path := writeBasicAuthTestFile(t, `{"username":"a","password":"p"}`)
	_, err := BasicAuthHTTPClient(time.Second, "https://inline:secret@store.example", path)
	if err == nil || !strings.Contains(err.Error(), "must not contain URL credentials") {
		t.Fatalf("error = %v, want URL credential refusal", err)
	}
}

func TestBasicAuthEndpointRejectsQueryAndFragment(t *testing.T) {
	path := writeBasicAuthTestFile(t, `{"username":"a","password":"p"}`)
	for _, endpoint := range []string{"https://store.example/base?token=bad", "https://store.example/base#fragment"} {
		if _, err := BasicAuthHTTPClient(time.Second, endpoint, path); err == nil || !strings.Contains(err.Error(), "query or fragment") {
			t.Fatalf("endpoint %q error = %v, want query/fragment refusal", endpoint, err)
		}
	}
}

func TestBasicAuthEndpointRejectsRemotePlaintext(t *testing.T) {
	path := writeBasicAuthTestFile(t, `{"username":"a","password":"p"}`)
	if _, err := BasicAuthHTTPClient(time.Second, "http://store.example:8123", path); err == nil || !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("remote HTTP error = %v, want TLS refusal", err)
	}
	if _, err := BasicAuthHTTPClient(time.Second, "http://127.0.0.1:8123", path); err != nil {
		t.Fatalf("loopback HTTP should remain available for local development: %v", err)
	}
}

func TestBasicAuthClientFactoryUsesOneImmutableCredentialSnapshot(t *testing.T) {
	path := writeBasicAuthTestFile(t, `{"username":"store","password":"generation-one"}`)
	factory, err := LoadBasicAuthClientFactory(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"username":"store","password":"generation-two"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	wantOne := "Basic " + base64.StdEncoding.EncodeToString([]byte("store:generation-one"))
	for _, endpoint := range []string{"https://clickhouse-a.example/base", "https://clickhouse-b.example/base"} {
		client, err := factory.HTTPClient(time.Second, endpoint)
		if err != nil {
			t.Fatal(err)
		}
		transport := client.Transport.(*originBasicAuthTransport)
		transport.base = basicAuthRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			if got := req.Header.Get("Authorization"); got != wantOne {
				t.Fatalf("Authorization after rotation = %q, want original snapshot", got)
			}
			return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		})
		req, _ := http.NewRequest(http.MethodGet, endpoint+"/query", nil)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatalf("close %s response: %v", endpoint, err)
		}
	}

	rotated, err := LoadBasicAuthClientFactory(path)
	if err != nil {
		t.Fatal(err)
	}
	client, err := rotated.HTTPClient(time.Second, "https://clickhouse-c.example/base")
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*originBasicAuthTransport)
	transport.base = basicAuthRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		wantTwo := "Basic " + base64.StdEncoding.EncodeToString([]byte("store:generation-two"))
		if got := req.Header.Get("Authorization"); got != wantTwo {
			t.Fatalf("reloaded Authorization = %q, want rotated snapshot", got)
		}
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	})
	req, _ := http.NewRequest(http.MethodGet, "https://clickhouse-c.example/base/query", nil)
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("close rotated response: %v", err)
	}
}

func writeBasicAuthTestFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestBasicAuthFactoryPinsARoutedOriginToItsOwnCredential (DPR-044): a client
// derived from the shared factory reaches the pooled origin with the pooled
// credential, a registered data-plane origin with that plane's credential,
// still refuses any other origin, and a contradictory registration for one
// origin is refused rather than resolved.
func TestBasicAuthFactoryPinsARoutedOriginToItsOwnCredential(t *testing.T) {
	pooled := writeBasicAuthTestFile(t, `{"username":"pooled","password":"pooled-secret"}`)
	plane := writeBasicAuthTestFile(t, `{"username":"eu","password":"eu-secret"}`)
	factory, err := LoadBasicAuthClientFactory(pooled)
	if err != nil {
		t.Fatal(err)
	}
	if err := factory.WithOriginCredentialFile("https://ch-eu.example:8443", plane); err != nil {
		t.Fatalf("register plane: %v", err)
	}
	if err := factory.WithOriginCredentialFile("https://ch-eu.example:8443", pooled); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("a different credential for the same origin must be refused, got %v", err)
	}
	if err := factory.WithOriginCredentialFile("https://ch-eu.example:8443", plane); err != nil {
		t.Fatalf("re-registering the same credential must be idempotent: %v", err)
	}
	client, err := factory.HTTPClient(time.Second, "https://clickhouse.example:8443")
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*originBasicAuthTransport)
	seen := map[string]string{}
	transport.base = basicAuthRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		seen[req.URL.Host] = req.Header.Get("Authorization")
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	})
	for _, target := range []string{"https://clickhouse.example:8443/?query=1", "https://ch-eu.example:8443/?query=1"} {
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		_ = resp.Body.Close()
	}
	if want := "Basic " + base64.StdEncoding.EncodeToString([]byte("pooled:pooled-secret")); seen["clickhouse.example:8443"] != want {
		t.Fatalf("pooled origin got %q", seen["clickhouse.example:8443"])
	}
	if want := "Basic " + base64.StdEncoding.EncodeToString([]byte("eu:eu-secret")); seen["ch-eu.example:8443"] != want {
		t.Fatalf("plane origin got %q, want the plane credential", seen["ch-eu.example:8443"])
	}
	other, _ := http.NewRequest(http.MethodGet, "https://ch-us.example:8443/?query=1", nil)
	if err := basicAuthRequestError(client, other); err == nil || !strings.Contains(err.Error(), "different origin") {
		t.Fatalf("unregistered origin must be refused, got %v", err)
	} else if strings.Contains(err.Error(), "secret") {
		t.Fatalf("error leaked a credential: %v", err)
	}
}
