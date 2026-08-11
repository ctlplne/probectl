// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package crypto

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const maxBasicAuthCredentialFileBytes = 8 << 10

// basicAuthCredentialFile is the deliberately small, operator-owned schema
// accepted by LoadBasicAuthClientFactory. Keeping the password in a mode-0600 file
// avoids URL userinfo, command arguments, and environment-variable values.
// Unknown and duplicate fields are rejected so an operator and the process
// cannot disagree about which credential was consumed.
type basicAuthCredentialFile struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// BasicAuthClientFactory is one immutable in-memory snapshot of an owner-only
// credential file. A control-plane startup loads a shared ClickHouse file once,
// then derives one path/origin-bound HTTP client per enabled store. That avoids
// a mixed credential generation if an operator atomically rotates the file
// while the process is constructing its stores.
type BasicAuthClientFactory struct {
	username string
	password string
}

// LoadBasicAuthClientFactory validates and snapshots one credential file.
func LoadBasicAuthClientFactory(credentialFile string) (*BasicAuthClientFactory, error) {
	credential, err := readBasicAuthCredentialFile(credentialFile)
	if err != nil {
		return nil, err
	}
	return &BasicAuthClientFactory{username: credential.Username, password: credential.Password}, nil
}

// BasicAuthHTTPClient builds the normal certificate-verifying hardened client
// and adds HTTP Basic authentication for exactly one configured origin. The
// origin pin is important: redirects and routed requests cannot carry the
// credential to another scheme, host, or port. The caller may reuse the client
// for paths below endpoint, but not for another service.
func BasicAuthHTTPClient(timeout time.Duration, endpoint, credentialFile string) (*http.Client, error) {
	factory, err := LoadBasicAuthClientFactory(credentialFile)
	if err != nil {
		return nil, err
	}
	return factory.HTTPClient(timeout, endpoint)
}

// HTTPClient derives a certificate-verifying client that sends this snapshot's
// credential only within endpoint's exact origin and canonical path prefix.
func (f *BasicAuthClientFactory) HTTPClient(timeout time.Duration, endpoint string) (*http.Client, error) {
	if f == nil || f.username == "" || f.password == "" {
		return nil, errors.New("crypto: basic-auth client factory is not initialized")
	}
	endpointURL, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || endpointURL.Scheme == "" || endpointURL.Host == "" {
		return nil, errors.New("crypto: basic-auth endpoint must be an absolute http(s) URL")
	}
	if endpointURL.Scheme != "http" && endpointURL.Scheme != "https" {
		return nil, fmt.Errorf("crypto: basic-auth endpoint has unsupported scheme %q", endpointURL.Scheme)
	}
	if endpointURL.Scheme == "http" && !basicAuthLoopbackHost(endpointURL.Hostname()) {
		return nil, errors.New("crypto: basic-auth endpoint must use HTTPS (plaintext HTTP is allowed only for loopback development)")
	}
	if endpointURL.User != nil {
		return nil, errors.New("crypto: basic-auth endpoint must not contain URL credentials")
	}
	if endpointURL.RawQuery != "" || endpointURL.Fragment != "" {
		return nil, errors.New("crypto: basic-auth endpoint must not contain a query or fragment")
	}

	client := HardenedHTTPClient(timeout)
	client.Transport = &originBasicAuthTransport{
		base:       client.Transport,
		origin:     canonicalOrigin(endpointURL),
		pathPrefix: canonicalPath(endpointURL.Path),
		username:   f.username,
		password:   f.password,
	}
	return client, nil
}

func basicAuthLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && addr.Unmap().IsLoopback()
}

type originBasicAuthTransport struct {
	base       http.RoundTripper
	origin     string
	pathPrefix string
	username   string
	password   string
}

func (t *originBasicAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("crypto: basic-auth request is missing its target URL")
	}
	if req.URL.Opaque != "" {
		return nil, errors.New("crypto: refusing an opaque datastore request target")
	}
	if req.Host != "" && !strings.EqualFold(req.Host, req.URL.Host) {
		return nil, errors.New("crypto: refusing a datastore request with a mismatched Host override")
	}
	if canonicalOrigin(req.URL) != t.origin {
		return nil, fmt.Errorf("crypto: refusing to send datastore credential to a different origin (%s)", canonicalOrigin(req.URL))
	}
	if !withinPathPrefix(canonicalPath(req.URL.Path), t.pathPrefix) {
		return nil, fmt.Errorf("crypto: refusing to send datastore credential outside its configured path prefix (%s)", t.pathPrefix)
	}
	if req.URL.User != nil {
		return nil, errors.New("crypto: refusing a datastore request containing URL credentials")
	}
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	clone.SetBasicAuth(t.username, t.password)
	return t.base.RoundTrip(clone)
}

func canonicalPath(raw string) string {
	cleaned := pathpkg.Clean("/" + strings.TrimPrefix(raw, "/"))
	if cleaned == "." || cleaned == "" {
		return "/"
	}
	return cleaned
}

func withinPathPrefix(candidate, prefix string) bool {
	if prefix == "/" {
		return true
	}
	return candidate == prefix || strings.HasPrefix(candidate, prefix+"/")
}

func canonicalOrigin(u *url.URL) string {
	if u == nil {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

func readBasicAuthCredentialFile(path string) (basicAuthCredentialFile, error) {
	return readBasicAuthCredentialFileWithHook(path, nil)
}

func readBasicAuthCredentialFileWithHook(path string, afterInitialLstat func()) (basicAuthCredentialFile, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return basicAuthCredentialFile{}, errors.New("crypto: basic-auth credential file path is empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return basicAuthCredentialFile{}, errors.New("crypto: resolve basic-auth credential file path")
	}
	linked, err := os.Lstat(abs)
	if err != nil {
		return basicAuthCredentialFile{}, fmt.Errorf("crypto: open basic-auth credential file: %w", err)
	}
	if linked.Mode()&os.ModeSymlink != 0 || !linked.Mode().IsRegular() {
		return basicAuthCredentialFile{}, errors.New("crypto: basic-auth credential file must be a regular non-symlink file")
	}
	if runtime.GOOS != "windows" && linked.Mode().Perm() != 0o600 {
		return basicAuthCredentialFile{}, fmt.Errorf("crypto: basic-auth credential file permissions are %04o, want 0600", linked.Mode().Perm())
	}
	if afterInitialLstat != nil {
		afterInitialLstat()
	}

	// O_NONBLOCK prevents an attacker-controlled replacement with a FIFO from
	// hanging startup between the initial Lstat and descriptor validation.
	file, err := os.OpenFile(abs, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return basicAuthCredentialFile{}, fmt.Errorf("crypto: open basic-auth credential file: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	linkedAfterOpen, linkedErr := os.Lstat(abs)
	if err != nil || linkedErr != nil || !opened.Mode().IsRegular() ||
		linkedAfterOpen.Mode()&os.ModeSymlink != 0 || !linkedAfterOpen.Mode().IsRegular() ||
		!os.SameFile(linked, opened) ||
		!os.SameFile(linkedAfterOpen, opened) ||
		(runtime.GOOS != "windows" && (opened.Mode().Perm() != 0o600 || linkedAfterOpen.Mode().Perm() != 0o600)) {
		return basicAuthCredentialFile{}, errors.New("crypto: basic-auth credential file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBasicAuthCredentialFileBytes+1))
	if err != nil {
		return basicAuthCredentialFile{}, errors.New("crypto: read basic-auth credential file")
	}
	if len(raw) > maxBasicAuthCredentialFileBytes {
		return basicAuthCredentialFile{}, fmt.Errorf("crypto: basic-auth credential file exceeds %d bytes", maxBasicAuthCredentialFileBytes)
	}
	openedAfterRead, statErr := file.Stat()
	linkedAfterRead, lstatErr := os.Lstat(abs)
	if statErr != nil || lstatErr != nil || !openedAfterRead.Mode().IsRegular() ||
		linkedAfterRead.Mode()&os.ModeSymlink != 0 || !linkedAfterRead.Mode().IsRegular() ||
		!os.SameFile(openedAfterRead, linkedAfterRead) ||
		(runtime.GOOS != "windows" && (openedAfterRead.Mode().Perm() != 0o600 || linkedAfterRead.Mode().Perm() != 0o600)) {
		return basicAuthCredentialFile{}, errors.New("crypto: basic-auth credential file changed while reading")
	}

	credential, err := decodeBasicAuthCredential(raw)
	if err != nil {
		return basicAuthCredentialFile{}, err
	}
	if credential.Username == "" || credential.Password == "" {
		return basicAuthCredentialFile{}, errors.New("crypto: basic-auth credential file requires non-empty username and password")
	}
	if strings.ContainsAny(credential.Username, ":\r\n") || strings.ContainsAny(credential.Password, "\r\n") {
		return basicAuthCredentialFile{}, errors.New("crypto: basic-auth credential contains invalid control or separator characters")
	}
	return credential, nil
}

func decodeBasicAuthCredential(raw []byte) (basicAuthCredentialFile, error) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return basicAuthCredentialFile{}, errors.New("crypto: basic-auth credential file must contain one JSON object")
	}
	var credential basicAuthCredentialFile
	seen := make(map[string]struct{}, 2)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return basicAuthCredentialFile{}, errors.New("crypto: decode basic-auth credential file")
		}
		key, ok := token.(string)
		if !ok {
			return basicAuthCredentialFile{}, errors.New("crypto: basic-auth credential file has a non-string field name")
		}
		if _, duplicate := seen[key]; duplicate {
			return basicAuthCredentialFile{}, fmt.Errorf("crypto: basic-auth credential file has duplicate field %q", key)
		}
		seen[key] = struct{}{}
		switch key {
		case "username":
			if err := decoder.Decode(&credential.Username); err != nil {
				return basicAuthCredentialFile{}, errors.New("crypto: basic-auth username must be a string")
			}
		case "password":
			if err := decoder.Decode(&credential.Password); err != nil {
				return basicAuthCredentialFile{}, errors.New("crypto: basic-auth password must be a string")
			}
		default:
			return basicAuthCredentialFile{}, fmt.Errorf("crypto: basic-auth credential file has unknown field %q", key)
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return basicAuthCredentialFile{}, errors.New("crypto: basic-auth credential file has an invalid JSON object")
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			_ = token
		}
		return basicAuthCredentialFile{}, errors.New("crypto: basic-auth credential file must contain exactly one JSON object")
	}
	return credential, nil
}
