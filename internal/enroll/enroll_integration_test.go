// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

// Sprint 11 acceptance (ADR docs/adr/agent-enrollment.md): enrollment
// happy-path, token replay rejection, wrong-tenant impossibility, rotation —
// against real Postgres (the CI integration job provides it; skips locally).
package enroll_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/enroll"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
	"github.com/imfeelingtheagi/probectl/migrations"
)

func dsn() string {
	if v := os.Getenv("PROBECTL_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://probectl@localhost:5432/postgres?sslmode=disable" // dev-only fallback (CI sets TLS, OPS-010)
}

func setup(ctx context.Context, t *testing.T) (*pgxpool.Pool, *enroll.Service, string) {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		// WIRE-005: in CI (PROBECTL_TEST_REQUIRE_SERVICES=1) a missing Postgres
		// is a RED build — the enroll-replay / wrong-tenant / rotation defenses
		// MUST execute, not silently skip.
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(pool.Close)

	// Init the hierarchy once per database (idempotent across test runs).
	if _, err := enroll.InitCA(ctx, pool); err != nil && !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("init CA: %v", err)
	}
	svc, err := enroll.Load(ctx, pool, nil)
	if err != nil {
		t.Fatalf("load enrollment service: %v", err)
	}

	tn, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("enr-%d", time.Now().UnixNano()), "Enroll T")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return pool, svc, tn.ID
}

// TestPublicBundleExportsRootAndIntermediate covers `agent-ca export`'s core:
// PublicBundle returns the public trust bundle (root + intermediate) WITHOUT
// unsealing the key, and equals the canonical Service.Bundle().
func TestPublicBundleExportsRootAndIntermediate(t *testing.T) {
	ctx := context.Background()
	pool, svc, _ := setup(ctx, t)

	bundle, err := enroll.PublicBundle(ctx, pool)
	if err != nil {
		t.Fatalf("public bundle: %v", err)
	}
	if n := strings.Count(string(bundle), "BEGIN CERTIFICATE"); n != 2 {
		t.Fatalf("public bundle must carry root + intermediate (2 certs), got %d", n)
	}
	if string(bundle) != string(svc.Bundle()) {
		t.Fatal("PublicBundle must equal Service.Bundle() (root + intermediate)")
	}
	if strings.Contains(string(bundle), "PRIVATE KEY") {
		t.Fatal("PublicBundle must never contain private key material")
	}
}

func TestEnrollHappyPathIssuesTenantBoundSVID(t *testing.T) {
	ctx := context.Background()
	pool, svc, tenantID := setup(ctx, t)

	display, _, err := svc.MintToken(ctx, tenantID, "", "ci", "test", time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	csr, _, err := crypto.CreateCSR("host-a")
	if err != nil {
		t.Fatal(err)
	}
	id, err := svc.Enroll(ctx, enroll.Request{Token: display, CSRPEM: string(csr), Hostname: "host-a", Version: "v1"})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	// The SVID is bound to the TOKEN's tenant — SPIFFE id carries tenant+agent.
	if id.TenantID != tenantID {
		t.Fatalf("identity tenant = %s, want the token's %s", id.TenantID, tenantID)
	}
	wantPrefix := "spiffe://probectl/tenant/" + tenantID + "/agent/"
	if !strings.HasPrefix(id.SPIFFEID, wantPrefix) {
		t.Fatalf("spiffe id %q does not bind the tenant", id.SPIFFEID)
	}

	// The Sprint 4 binding now vouches for the pair (a REAL, repo-issued identity).
	binding := pipeline.NewRegistryBinding(pool)
	if err := binding.Verify(ctx, tenantID, id.AgentID); err != nil {
		t.Fatalf("S4 binding must vouch for the enrolled agent: %v", err)
	}
	// And refuses the same agent under ANOTHER tenant (wrong-tenant rejection).
	other, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("enr-o-%d", time.Now().UnixNano()), "Other")
	if err != nil {
		t.Fatal(err)
	}
	if err := binding.Verify(ctx, other.ID, id.AgentID); err == nil {
		t.Fatal("S4 binding vouched for the agent under a foreign tenant")
	}
}

func TestEnrollTokenReplayRejected(t *testing.T) {
	ctx := context.Background()
	_, svc, tenantID := setup(ctx, t)

	display, _, err := svc.MintToken(ctx, tenantID, "", "", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csr, _, _ := crypto.CreateCSR("host-b")
	if _, err := svc.Enroll(ctx, enroll.Request{Token: display, CSRPEM: string(csr)}); err != nil {
		t.Fatalf("first use: %v", err)
	}
	// REPLAY: the same token a second time must be refused, uninformatively.
	csr2, _, _ := crypto.CreateCSR("host-c")
	if _, err := svc.Enroll(ctx, enroll.Request{Token: display, CSRPEM: string(csr2)}); err == nil {
		t.Fatal("token replay was accepted (single-use violated)")
	}
	// Unknown/garbage tokens are equally refused.
	if _, err := svc.Enroll(ctx, enroll.Request{Token: "pjt_deadbeef", CSRPEM: string(csr2)}); err == nil {
		t.Fatal("unknown token accepted")
	}
}

// TestEnrollTokenRevokeBlocksRedeem is the regression test for the
// revoke-enroll-token surface: voiding an unredeemed token must make
// redemption fail, the outcome must be reported truthfully (true only when a
// row actually changed), and a second revoke must report false.
func TestEnrollTokenRevokeBlocksRedeem(t *testing.T) {
	ctx := context.Background()
	pool, svc, tenantID := setup(ctx, t)

	display, tokenID, err := svc.MintToken(ctx, tenantID, "", "", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := store.NewEnrollTokens(pool).Revoke(ctx, tokenID)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !revoked {
		t.Fatal("revoke reported false for a fresh unredeemed token")
	}
	csr, _, _ := crypto.CreateCSR("host-revoked")
	if _, err := svc.Enroll(ctx, enroll.Request{Token: display, CSRPEM: string(csr)}); err == nil {
		t.Fatal("revoked token was redeemed (revocation not enforced)")
	}
	// Idempotence honesty: a second revoke changed nothing and says so.
	if again, err := store.NewEnrollTokens(pool).Revoke(ctx, tokenID); err != nil || again {
		t.Fatalf("second revoke = (%v, %v), want (false, nil)", again, err)
	}
}

func TestRotationKeepsIdentityAndRecordsNewSerial(t *testing.T) {
	ctx := context.Background()
	pool, svc, tenantID := setup(ctx, t)
	_ = pool
	// agents.id is a uuid column; pin a unique v4 UUID (global PK).
	agentID := fmt.Sprintf("a7000000-0000-4000-8000-%012x", time.Now().UnixNano()&0xffffffffffff)

	display, _, err := svc.MintToken(ctx, tenantID, agentID, "", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csr1, key1, _ := crypto.CreateCSR("host-r")
	first, err := svc.Enroll(ctx, enroll.Request{Token: display, CSRPEM: string(csr1)})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	// Rotate: new key, proof signed by the CURRENT key.
	csr2, _, _ := crypto.CreateCSR("host-r")
	proof, err := crypto.ECDSASignPEM(key1, csr2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Rotate(ctx, enroll.RotateRequest{
		CertPEM: leafOnly(first.CertPEM), CSRPEM: string(csr2), ProofHex: fmt.Sprintf("%x", proof)})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if second.SPIFFEID != first.SPIFFEID || second.TenantID != first.TenantID || second.AgentID != first.AgentID {
		t.Fatalf("rotation changed identity: %+v -> %+v", first, second)
	}
	if second.Serial == first.Serial {
		t.Fatal("rotation did not issue a new serial")
	}

	// A FOREIGN cert (different hierarchy) must be refused.
	foreignCA, _ := crypto.GenerateRootCA("evil root", time.Hour)
	foreignInter, _ := foreignCA.IssueIntermediate("evil inter", time.Hour)
	fcsr, fkey, _ := crypto.CreateCSR("evil")
	fleaf, _, err := foreignInter.SignCSR(fcsr, "spiffe://probectl/tenant/"+tenantID+"/agent/"+agentID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fcsr2, _, _ := crypto.CreateCSR("evil2")
	fproof, _ := crypto.ECDSASignPEM(fkey, fcsr2)
	if _, err := svc.Rotate(ctx, enroll.RotateRequest{
		CertPEM: string(fleaf), CSRPEM: string(fcsr2), ProofHex: fmt.Sprintf("%x", fproof)}); err == nil {
		t.Fatal("rotation accepted a certificate from a FOREIGN CA")
	}

	// A bad possession proof must be refused even with OUR cert.
	csr3, _, _ := crypto.CreateCSR("host-r")
	if _, err := svc.Rotate(ctx, enroll.RotateRequest{
		CertPEM: leafOnly(second.CertPEM), CSRPEM: string(csr3), ProofHex: "deadbeef"}); err == nil {
		t.Fatal("rotation accepted a bad possession proof")
	}
}

// TestWrongTenantCannotBeRequested: the tenant comes ONLY from the token —
// there is no request field to even attempt a cross-tenant enrollment, and a
// token minted for tenant A can never yield tenant B.
func TestWrongTenantCannotBeRequested(t *testing.T) {
	ctx := context.Background()
	pool, svc, tenantA := setup(ctx, t)

	tnB, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("enr-b-%d", time.Now().UnixNano()), "B")
	if err != nil {
		t.Fatal(err)
	}
	display, _, err := svc.MintToken(ctx, tenantA, "", "", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csr, _, _ := crypto.CreateCSR("host-w")
	id, err := svc.Enroll(ctx, enroll.Request{Token: display, CSRPEM: string(csr)})
	if err != nil {
		t.Fatal(err)
	}
	if id.TenantID != tenantA || id.TenantID == tnB.ID {
		t.Fatalf("token for tenant A yielded tenant %s", id.TenantID)
	}
	// The issued agent exists ONLY in A's registry partition (RLS-scoped).
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tnB.ID)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			// RLS hides A's agent from B, so Get returns NotFound (the fail-closed
			// signal) — that IS the pass. Only a non-error + non-nil agent (B can
			// actually read A's agent) is the cross-tenant leak.
			a, gerr := (store.Agents{}).Get(ctx, sc, id.AgentID)
			if gerr == nil && a != nil {
				t.Fatal("enrolled agent visible in tenant B's registry (CROSS-TENANT LEAK)")
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
}

// leafOnly strips the chain down to the first certificate block (Rotate
// parses the leaf; clients send the leaf).
func leafOnly(chainPEM string) string {
	const end = "-----END CERTIFICATE-----"
	i := strings.Index(chainPEM, end)
	if i < 0 {
		return chainPEM
	}
	return chainPEM[:i+len(end)] + "\n"
}

// Sprint 12 (WIRE-003): revocation persists, blocks re-enrollment AND
// rotation, and surfaces through ListRevoked (the boot/refresh feed).
func TestRevokeAgentPersistsAndBlocksReissuance(t *testing.T) {
	ctx := context.Background()
	pool, svc, tenantID := setup(ctx, t)
	_ = pool
	// agents.id is a uuid column; pin a unique v4 UUID (global PK).
	agentID := fmt.Sprintf("a6000000-0000-4000-8000-%012x", time.Now().UnixNano()&0xffffffffffff)

	display, _, err := svc.MintToken(ctx, tenantID, agentID, "", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csr1, key1, _ := crypto.CreateCSR("host-rev")
	id, err := svc.Enroll(ctx, enroll.Request{Token: display, CSRPEM: string(csr1)})
	if err != nil {
		t.Fatal(err)
	}

	serials, spiffeID, err := svc.Revoke(ctx, tenantID, agentID, "test")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if len(serials) == 0 || spiffeID != id.SPIFFEID {
		t.Fatalf("revoke returned serials=%d spiffe=%s, want the issued identity", len(serials), spiffeID)
	}

	// The persisted feed contains the material (what boot/refresh installs).
	feedSerials, feedIDs, err := svc.ListRevoked(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !containsStr(feedSerials, id.Serial) || !containsStr(feedIDs, id.SPIFFEID) {
		t.Fatalf("feed missing revoked material: serials=%v ids=%v", feedSerials, feedIDs)
	}

	// Rotation of the revoked identity refuses (no resurrection)...
	csr2, _, _ := crypto.CreateCSR("host-rev")
	proof, _ := crypto.ECDSASignPEM(key1, csr2)
	if _, err := svc.Rotate(ctx, enroll.RotateRequest{
		CertPEM: leafOnly(id.CertPEM), CSRPEM: string(csr2), ProofHex: fmt.Sprintf("%x", proof)}); !errors.Is(err, enroll.ErrRevoked) {
		t.Fatalf("rotation of a revoked identity must refuse with ErrRevoked, got %v", err)
	}
	// ...and so does re-enrollment with a fresh token PINNED to the same id.
	display2, _, err := svc.MintToken(ctx, tenantID, agentID, "", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csr3, _, _ := crypto.CreateCSR("host-rev")
	if _, err := svc.Enroll(ctx, enroll.Request{Token: display2, CSRPEM: string(csr3)}); !errors.Is(err, enroll.ErrRevoked) {
		t.Fatalf("re-enrollment of a revoked identity must refuse with ErrRevoked, got %v", err)
	}
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
