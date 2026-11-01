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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
)

type captureSiteEvidence struct {
	claims chan entity.Observation
}

func (c captureSiteEvidence) Submit(_ context.Context, items []entity.Observation) (int, int, error) {
	for _, item := range items {
		c.claims <- item
	}
	return len(items), 0, nil
}

func TestAgentSiteEvidenceUsesVerifiedAgentSourceNotSiteLabelForRouting(t *testing.T) {
	const agentID = "22222222-2222-4222-8222-222222222222"
	conf := &Config{Agent: Meta{Labels: map[string]string{"site": "dub-1"}}}
	a := &Agent{cfg: conf, tenantID: "11111111-1111-4111-8111-111111111111",
		agentID: agentID, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	claim, err := a.siteObservation(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := claim.Normalize(time.Now()); err != nil ||
		claim.Source != (entity.SourceKey{AgentID: agentID, Kind: entity.AgentSite,
			SourceRef: agentID}) ||
		claim.Alias != (entity.AliasKey{Kind: entity.AgentSiteAlias, Value: "dub-1"}) ||
		claim.SourceRef != "agent:label:site" {
		t.Fatalf("site label selected a routing context or lost provenance: %+v, %v", claim, err)
	}
	claims := make(chan entity.Observation, 1)
	a.WithSiteEvidence(captureSiteEvidence{claims: claims})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.runSiteEvidence(ctx); close(done) }()
	select {
	case got := <-claims:
		if got.Source != claim.Source || got.Alias != claim.Alias {
			t.Fatalf("worker sent another source: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("site evidence worker did not send its first bounded claim")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("site evidence worker ignored cancellation")
	}
}

func TestAgentSiteEvidenceConfigRequiresWholeCredential(t *testing.T) {
	if err := (EvidenceConfig{}).validate(); err != nil {
		t.Fatal(err)
	}
	if err := (EvidenceConfig{ControlAddr: "control:443", CertFile: "entity.pem"}).validate(); err == nil {
		t.Fatal("partial evidence credential accepted")
	}
	if err := (EvidenceConfig{ControlAddr: "control:443", CertFile: "entity/cert.pem",
		KeyFile: "ordinary/key.pem", CAFile: "entity/server-ca.pem"}).validate(); err == nil {
		t.Fatal("evidence identity spread across two directories")
	}
	if err := (EvidenceConfig{ControlAddr: "control:443", CertFile: "entity/cert.pem",
		KeyFile: "entity/key.pem", CAFile: "entity/ca.pem"}).validate(); err == nil {
		t.Fatal("rotation would replace the evidence connection's server trust")
	}
}

func TestEvidenceRotationKeepsPlaneAndServerTrust(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111111"
	const agentID = "22222222-2222-4222-8222-222222222222"
	ca, err := crypto.GenerateCA("entity-rotation-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "entity-identity")
	oldPEM, oldKey, err := ca.IssueClientCert("entity-agent", crypto.EntitySPIFFEID(tenantID, agentID), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeIdentityDir(dir, oldPEM, oldKey, ca.CertPEM()); err != nil {
		t.Fatal(err)
	}
	wrongPlane := true
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		spiffe := crypto.EntitySPIFFEID(tenantID, agentID)
		if wrongPlane {
			spiffe = crypto.AgentSPIFFEID(tenantID, agentID)
		}
		certPEM, serial, err := ca.SignCSR([]byte(in["csr_pem"]), spiffe, time.Hour)
		if err != nil {
			http.Error(w, "bad csr", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(issuedIdentity{CertPEM: string(certPEM),
			CABundle: string(ca.CertPEM()), SPIFFEID: spiffe, TenantID: tenantID,
			AgentID: agentID, Serial: serial.Text(16), NotAfter: time.Now().Add(time.Hour)})
	}))
	defer srv.Close()
	serverCA := filepath.Join(dir, IdentityServerCAFile)
	trust := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(serverCA, trust, 0o600); err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, IdentityCertFile), filepath.Join(dir, IdentityKeyFile)
	if _, err := Rotate(context.Background(), srv.URL, certFile, keyFile, serverCA); err == nil {
		t.Fatal("wrong-plane renewal replaced the evidence SVID")
	}
	unchanged, err := os.ReadFile(certFile)
	if err != nil || !bytes.Equal(unchanged, oldPEM) {
		t.Fatal("refused renewal replaced the old evidence SVID")
	}
	wrongPlane = false
	if _, err := Rotate(context.Background(), srv.URL, certFile, keyFile, serverCA); err != nil {
		t.Fatalf("same-plane evidence renewal: %v", err)
	}
	rotated, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	oldLeaf, _ := firstCert(oldPEM)
	newLeaf, err := firstCert(rotated)
	if err != nil || oldLeaf.SerialNumber.Cmp(newLeaf.SerialNumber) == 0 {
		t.Fatal("evidence renewal kept the old serial")
	}
	newID, err := crypto.EntitySPIFFEIDFromCert(newLeaf)
	if err != nil || newID.TenantID != tenantID || newID.AgentID != agentID {
		t.Fatalf("evidence renewal changed its verified sender: %+v, %v", newID, err)
	}
	if got, err := os.ReadFile(serverCA); err != nil || !bytes.Equal(got, trust) {
		t.Fatal("evidence renewal replaced its independent server trust")
	}
}

func TestEvidenceRotationRequiresTLSAndDedicatedAtomicDirectory(t *testing.T) {
	dir := t.TempDir()
	evidence := filepath.Join(dir, "evidence")
	ordinary := filepath.Join(dir, "ordinary")
	if err := os.Mkdir(evidence, 0o700); err != nil {
		t.Fatal(err)
	}
	cert, key, trust := filepath.Join(evidence, IdentityCertFile),
		filepath.Join(evidence, IdentityKeyFile), filepath.Join(evidence, IdentityServerCAFile)
	if err := ValidateEvidenceRotation("http://control:8443", cert, key, trust); err == nil {
		t.Fatal("evidence renewal accepted plaintext")
	}
	if err := ValidateEvidenceRotation("https://control:8443", cert, key, trust); err != nil {
		t.Fatal(err)
	}
	if err := ValidateEvidenceRotation("https://control:8443", cert,
		filepath.Join(ordinary, IdentityKeyFile), trust); err == nil {
		t.Fatal("evidence key in another identity directory")
	}
	if err := ValidateDistinctIdentityDirs(cert, filepath.Join(ordinary, IdentityCertFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(evidence, ordinary); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDistinctIdentityDirs(cert, filepath.Join(ordinary, IdentityCertFile)); err == nil {
		t.Fatal("evidence directory aliases the ordinary listener identity")
	}
}
