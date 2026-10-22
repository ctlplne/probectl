// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package chtest

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// ReaderPassword is the throwaway password of every reader ProvisionReader
// creates. It is deliberately not key-shaped: the login lives only for one
// test on a disposable server.
const ReaderPassword = "reader-password-ci-only"

// ProvisionReader creates a fresh least-privilege reader login on the live
// ClickHouse at chURL, whose URL userinfo must be a login with access
// management (the dev/CI stack's). The reader gets SELECT on the control
// login's default database and nothing else, exactly as the shipped
// deployments provision probectl_reader, and is dropped when the test ends.
// It returns the reader's name and a client that authenticates as it.
func ProvisionReader(t *testing.T, chURL, prefix string) (string, *http.Client) {
	t.Helper()
	db, err := Exec(chURL, "SELECT currentDatabase()")
	if err != nil {
		t.Fatalf("control database: %v", err)
	}
	user := fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	for _, stmt := range []string{
		"CREATE USER IF NOT EXISTS " + user + " IDENTIFIED WITH sha256_password BY '" + ReaderPassword + "'",
		"GRANT SELECT ON " + strings.TrimSpace(db) + ".* TO " + user,
	} {
		if _, err := Exec(chURL, stmt); err != nil {
			t.Fatalf("provision reader %s: %v", user, err)
		}
	}
	t.Cleanup(func() { _, _ = Exec(chURL, "DROP USER IF EXISTS "+user) })
	return user, BasicAuthClient(user, ReaderPassword)
}

// BasicAuthClient authenticates every request as user/password.
func BasicAuthClient(user, password string) *http.Client {
	c := crypto.HardenedHTTPClient(30 * time.Second)
	c.Transport = basicAuthPassword{user: user, password: password, base: c.Transport}
	return c
}

type basicAuthPassword struct {
	user, password string
	base           http.RoundTripper
}

func (b basicAuthPassword) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.SetBasicAuth(b.user, b.password)
	return b.base.RoundTrip(clone)
}

// URLClient authenticates as chURL's own userinfo — the control login of the
// dev/CI stack — for a test that plants the control login as the "reader".
func URLClient(chURL string) *http.Client {
	u, err := url.Parse(chURL)
	if err != nil || u.User == nil {
		return http.DefaultClient
	}
	pw, _ := u.User.Password()
	return BasicAuthClient(u.User.Username(), pw)
}

// Exec runs one statement as chURL's userinfo login and returns the body.
func Exec(chURL, query string) (string, error) {
	u, err := url.Parse(chURL)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, u.Scheme+"://"+u.Host+"/", strings.NewReader(query))
	if err != nil {
		return "", err
	}
	if u.User != nil {
		pw, _ := u.User.Password()
		req.SetBasicAuth(u.User.Username(), pw)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("clickhouse %d: %s", resp.StatusCode, body)
	}
	return string(body), nil
}
