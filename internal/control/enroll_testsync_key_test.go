// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/enroll"
	"github.com/ctlplne/probectl/internal/testsync"
)

// G9: both the first enrollment and every rotation hand the agent the
// deployment's test-bundle public key, so an agent enrolled before central
// test distribution was on receives it at its next renewal. With distribution
// off, neither response carries a key.
func TestEnrollmentAndRotationDeliverTheTestBundleKey(t *testing.T) {
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	// The pool is never dialed: only the public key is read here.
	pool, err := pgxpool.New(context.Background(), "postgres://unused@127.0.0.1:1/unused?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	src, err := testsync.NewSource(pool, priv)
	if err != nil {
		t.Fatal(err)
	}
	const (
		csrPEM  = "-----BEGIN CERTIFICATE REQUEST-----\\nZmFrZS1jc3I=\\n-----END CERTIFICATE REQUEST-----\\n"
		certPEM = "-----BEGIN CERTIFICATE-----\\nZmFrZS1jZXJ0\\n-----END CERTIFICATE-----\\n"
	)
	for _, tc := range []struct{ name, path, body string }{
		{"enroll", "/enroll/agent", `{"token":"join-token","csr_pem":"` + csrPEM + `"}`},
		{"rotate", "/enroll/agent/rotate", `{"cert_pem":"` + certPEM + `","csr_pem":"` + csrPEM + `","proof":"00ff"}`},
	} {
		for _, on := range []bool{true, false} {
			srv := testServer(nil)
			srv.enrollSvc = forensicEnrollmentService{identity: &enroll.Identity{
				TenantID: "11111111-1111-4111-8111-111111111111", AgentID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
				NotAfter: time.Now().Add(time.Hour),
			}}
			srv.identityAudit = func(context.Context, string, string, string, map[string]any) error { return nil }
			if on {
				srv.WithTestSync(src)
			}
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body)))
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: status %d: %s", tc.name, rec.Code, rec.Body.String())
			}
			var got enroll.Identity
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if on && got.TestSyncPublicKey != string(pub) {
				t.Fatalf("%s with distribution on: testsync_public_key = %q, want the deployment key", tc.name, got.TestSyncPublicKey)
			}
			if !on && got.TestSyncPublicKey != "" {
				t.Fatalf("%s with distribution off carried a key", tc.name)
			}
		}
	}
}
