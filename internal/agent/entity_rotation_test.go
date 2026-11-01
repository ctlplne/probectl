// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

func TestEvidenceRotationRejectsWrongPlaneBeforeAtomicSwap(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	const agentID = "22222222-2222-4222-8222-222222222222"
	issuer, err := crypto.GenerateCA("entity-rotation-issuer", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath, serverCAPath := filepath.Join(dir, IdentityCertFile),
		filepath.Join(dir, IdentityKeyFile), filepath.Join(dir, IdentityServerCAFile)
	oldCert, oldKey, err := issuer.IssueClientCert(agentID, crypto.EntitySPIFFEID(tenant, agentID), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{certPath: oldCert, keyPath: oldKey} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var wrongPlane atomic.Bool
	wrongPlane.Store(true)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/enroll/agent/rotate" {
			http.NotFound(w, r)
			return
		}
		var request map[string]string
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		spiffeID := crypto.EntitySPIFFEID(tenant, agentID)
		if wrongPlane.Load() {
			spiffeID = crypto.AgentSPIFFEID(tenant, agentID)
		}
		newCert, serial, err := issuer.SignCSR([]byte(request["csr_pem"]), spiffeID, time.Hour)
		if err != nil {
			http.Error(w, "could not sign CSR", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(issuedIdentity{
			CertPEM: string(newCert), CABundle: string(issuer.CertPEM()),
			SPIFFEID: spiffeID, TenantID: tenant, AgentID: agentID,
			Serial: serial.Text(16), NotAfter: time.Now().Add(time.Hour),
		})
	}))
	defer server.Close()
	serverTrust := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(serverCAPath, serverTrust, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateEvidenceRotation(server.URL, certPath, keyPath, serverCAPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(context.Background(), server.URL, certPath, keyPath, serverCAPath); err == nil {
		t.Fatal("wrong-plane renewal replaced evidence SVID")
	}
	for path, want := range map[string][]byte{
		certPath: oldCert, keyPath: oldKey, serverCAPath: serverTrust,
	} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("wrong-plane renewal changed %s: %v", filepath.Base(path), err)
		}
	}
	wrongPlane.Store(false)
	if _, err := Rotate(context.Background(), server.URL, certPath, keyPath, serverCAPath); err != nil {
		t.Fatalf("same-identity evidence renewal: %v", err)
	}
	renewedCert, err := os.ReadFile(certPath)
	if err != nil || bytes.Equal(renewedCert, oldCert) {
		t.Fatalf("valid renewal did not replace evidence leaf: %v", err)
	}
	if _, err := crypto.EntitySPIFFEIDFromCertFile(certPath); err != nil {
		t.Fatalf("renewed SVID changed plane: %v", err)
	}
	if err := crypto.VerifyIdentityPair(certPath, keyPath); err != nil {
		t.Fatalf("renewal certificate and local private key differ: %v", err)
	}
	if got, err := os.ReadFile(serverCAPath); err != nil || !bytes.Equal(got, serverTrust) {
		t.Fatalf("renewal replaced independent server trust: %v", err)
	}
}
