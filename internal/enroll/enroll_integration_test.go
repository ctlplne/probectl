// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

// Sprint 11 acceptance (ADR docs/adr/agent-enrollment.md): enrollment
// happy-path, token replay rejection, wrong-tenant impossibility, rotation —
// against real Postgres (the CI integration job provides it; skips locally).
package enroll_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/enroll"
	"github.com/ctlplne/probectl/internal/pipeline"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/usage"
	"github.com/ctlplne/probectl/migrations"
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

	// KEYS-003: agent-ca init refuses to persist the CA intermediate key as
	// plaintext, so configure a deployment envelope sealer first — exactly as a
	// real deployment does via PROBECTL_ENVELOPE_KEY/BYOK. Test-only KEK; mirrors
	// seal_test.go's success path. SetPrimary is process-global + idempotent.
	kek := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	sealer, err := tenantcrypto.NewEnvelopeSealer("test", kek)
	if err != nil {
		t.Fatalf("test envelope sealer: %v", err)
	}
	tenantcrypto.SetPrimary(sealer)

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

	// Issuing an SVID proves identity, not liveness. The registry reservation must
	// remain non-operational until the holder opens the authenticated mTLS
	// transport and calls Register/Heartbeat.
	//
	// DPR-217: this assertion used to live at the END of the test, AFTER
	// binding.Verify — and Verify heartbeats the agent on purpose, because a
	// verified batch IS a bus collector's heartbeat (DPR-082,
	// internal/pipeline/tenantverify.go). So the test simulated a batch arriving
	// and then asserted that nothing had arrived, and it has been failing on CI
	// ever since. In production nothing calls Verify between enrollment and the
	// agent's first batch. Assert it where it belongs: immediately after
	// enrollment.
	assertAgentStatus(ctx, t, pool, tenantID, id.AgentID, "registered", true)

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

	// And now the other half of the same property, which was never asserted: a
	// verified batch DOES make the agent operational. Verify above is what the
	// ingest path calls, so by here the agent has been heartbeaten exactly once.
	assertAgentStatus(ctx, t, pool, tenantID, id.AgentID, "online", false)
}

// assertAgentStatus reads the agent through the tenant transaction and checks
// both the derived status and whether it has ever been seen. wantNeverSeen keeps
// the two apart: "registered" is also what a long-silent agent derives to, so the
// null last_seen_at is the part that proves nothing has ever connected.
func assertAgentStatus(
	ctx context.Context,
	t *testing.T,
	pool *pgxpool.Pool,
	tenantID, agentID, wantStatus string,
	wantNeverSeen bool,
) {
	t.Helper()
	var got *store.Agent
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool, func(ctx context.Context, scope tenancy.Scope) error {
		var getErr error
		got, getErr = (store.Agents{}).Get(ctx, scope, agentID)
		return getErr
	})
	if err != nil {
		t.Fatalf("get agent %s: %v", agentID, err)
	}
	if got.Status != wantStatus {
		t.Fatalf("agent status = %q, want %q: %+v", got.Status, wantStatus, got)
	}
	if wantNeverSeen && got.LastSeenAt != nil {
		t.Fatalf("agent has never connected but carries last_seen_at %v: %+v", got.LastSeenAt, got)
	}
	if !wantNeverSeen && got.LastSeenAt == nil {
		t.Fatalf("agent should have been seen but last_seen_at is null: %+v", got)
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

func TestBMPRouterEnrollIssueRotateRevokeTwoTenant(t *testing.T) {
	ctx := context.Background()
	pool, svc, tenantA := setup(ctx, t)
	tenantBRecord, err := store.NewTenants(pool).Create(
		ctx,
		fmt.Sprintf("bmp-b-%d", time.Now().UnixNano()),
		"BMP tenant B",
	)
	if err != nil {
		t.Fatal(err)
	}
	tenantB := tenantBRecord.ID
	routerA := fmt.Sprintf("b1000000-0000-4000-8000-%012x", time.Now().UnixNano()&0xffffffffffff)
	routerB := fmt.Sprintf("b2000000-0000-4000-8000-%012x", time.Now().UnixNano()&0xffffffffffff)

	tokenA, _, err := svc.MintToken(ctx, tenantA, routerA, "router-a", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csrA, keyA, err := crypto.CreateCSR("router-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterCollectorForTenant(
		ctx,
		tenantB,
		tokenA,
		"router-a",
		"bmp",
		string(csrA),
	); !errors.Is(err, enroll.ErrInvalidToken) {
		t.Fatalf("tenant B consumed tenant A's BMP token: %v", err)
	}
	regA, err := svc.RegisterCollectorForTenant(
		ctx,
		tenantA,
		tokenA,
		"router-a",
		"bmp",
		string(csrA),
	)
	if err != nil {
		t.Fatalf("register BMP router A: %v", err)
	}
	if regA.SVID == nil {
		t.Fatal("BMP registration returned no SVID")
	}
	wantA := crypto.BMPSPIFFEID(tenantA, routerA)
	if regA.Plane != "bmp" || regA.SVID.Plane != "bmp" ||
		regA.SVID.SPIFFEID != wantA || regA.SVID.AgentID != routerA {
		t.Fatalf("BMP registration = %+v, want tenant-bound bmp SVID %q", regA, wantA)
	}

	identities := store.NewAgentIdentities(pool)
	known, err := identities.KnownIssuedIdentity(
		ctx,
		tenantA,
		routerA,
		regA.SVID.SPIFFEID,
		regA.SVID.Serial,
	)
	if err != nil || !known {
		t.Fatalf("issued BMP identity not found in tenant A registry: known=%v err=%v", known, err)
	}
	knownInB, err := identities.KnownIssuedIdentity(
		ctx,
		tenantB,
		routerA,
		regA.SVID.SPIFFEID,
		regA.SVID.Serial,
	)
	if err != nil {
		t.Fatalf("tenant B lookup: %v", err)
	}
	if knownInB {
		t.Fatal("tenant A's BMP identity was visible as registry-issued in tenant B")
	}
	if knownWrongSerial, err := identities.KnownIssuedIdentity(
		ctx,
		tenantA,
		routerA,
		regA.SVID.SPIFFEID,
		"deadbeef",
	); err != nil || knownWrongSerial {
		t.Fatalf("unissued serial accepted: known=%v err=%v", knownWrongSerial, err)
	}

	csrA2, _, err := crypto.CreateCSR("router-a")
	if err != nil {
		t.Fatal(err)
	}
	proofA, err := crypto.ECDSASignPEM(keyA, csrA2)
	if err != nil {
		t.Fatal(err)
	}
	rotatedA, err := svc.Rotate(ctx, enroll.RotateRequest{
		CertPEM:  leafOnly(regA.SVID.CertPEM),
		CSRPEM:   string(csrA2),
		ProofHex: fmt.Sprintf("%x", proofA),
	})
	if err != nil {
		t.Fatalf("rotate BMP router A: %v", err)
	}
	if rotatedA.SPIFFEID != regA.SVID.SPIFFEID || rotatedA.Plane != "bmp" ||
		rotatedA.Serial == regA.SVID.Serial {
		t.Fatalf("BMP rotation changed identity or retained serial: first=%+v rotated=%+v", regA.SVID, rotatedA)
	}
	var rotatedFrom string
	err = tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantA)),
		pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(
				ctx,
				`SELECT COALESCE(rotated_from, '')
				   FROM agent_identities
				  WHERE tenant_id = $1
				    AND agent_id = $2
				    AND serial = $3`,
				tenantA,
				routerA,
				rotatedA.Serial,
			).Scan(&rotatedFrom)
		},
	)
	if err != nil {
		t.Fatalf("read BMP rotation provenance: %v", err)
	}
	if rotatedFrom != regA.SVID.Serial {
		t.Fatalf("rotated_from = %q, want %q", rotatedFrom, regA.SVID.Serial)
	}

	tokenB, _, err := svc.MintToken(ctx, tenantB, routerB, "router-b", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csrB, _, err := crypto.CreateCSR("router-b")
	if err != nil {
		t.Fatal(err)
	}
	regB, err := svc.RegisterCollectorForTenant(
		ctx,
		tenantB,
		tokenB,
		"router-b",
		"bmp",
		string(csrB),
	)
	if err != nil {
		t.Fatalf("register BMP router B: %v", err)
	}

	serials, spiffeID, err := svc.Revoke(ctx, tenantA, routerA, "test")
	if err != nil {
		t.Fatalf("revoke BMP router A: %v", err)
	}
	if spiffeID != regA.SVID.SPIFFEID ||
		(!containsStr(serials, regA.SVID.Serial) && !containsStr(serials, rotatedA.Serial)) {
		t.Fatalf("BMP revoke material = serials=%v spiffe=%q", serials, spiffeID)
	}
	revocations := crypto.NewRevocationList()
	revocations.RevokeID(spiffeID)
	for _, serial := range serials {
		revocations.RevokeSerial(serial)
	}
	if !revocations.IsRevoked(rotatedA.Serial, rotatedA.SPIFFEID) {
		t.Fatal("existing RevokeID/RevokeSerial path did not reject rotated BMP identity")
	}
	if revocations.IsRevoked(regB.SVID.Serial, regB.SVID.SPIFFEID) {
		t.Fatal("revoking tenant A's BMP router affected tenant B")
	}
	revokedB, err := identities.IsAgentRevoked(ctx, tenantB, routerB)
	if err != nil {
		t.Fatal(err)
	}
	if revokedB {
		t.Fatal("tenant B BMP identity was marked revoked by tenant A's revocation")
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

type denyAgentQuota struct{ allow bool }

func (d denyAgentQuota) AllowCreate(_ context.Context, _ string, resource string) error {
	if d.allow || resource != usage.MeterAgents {
		return nil
	}
	return errors.New("agents quota exceeded (5/5)")
}

// DPR-081: a bus collector is a metered agent — registering one at the
// tenant's agent cap is refused with the quota error the gRPC path already
// raises, and admitted once the cap is lifted.
func TestCollectorRegistrationHonoursTheAgentQuota(t *testing.T) {
	ctx := context.Background()
	pool, svc, _ := setup(ctx, t)
	defer pool.Close()
	tn, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("quota-%d", time.Now().UnixNano()), "quota")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { usage.SetQuotaChecker(nil) })
	usage.SetQuotaChecker(denyAgentQuota{})
	token, _, err := svc.MintToken(ctx, tn.ID, "", "flow-collector", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterCollectorForTenant(ctx, tn.ID, token, "flow-1", "flow", ""); !errors.Is(err, enroll.ErrQuotaExceeded) {
		t.Fatalf("registration at the cap must be refused with ErrQuotaExceeded, got %v", err)
	}
	usage.SetQuotaChecker(denyAgentQuota{allow: true})
	token2, _, err := svc.MintToken(ctx, tn.ID, "", "flow-collector", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterCollectorForTenant(ctx, tn.ID, token2, "flow-1", "flow", ""); err != nil {
		t.Fatalf("registration under the cap must succeed: %v", err)
	}
}

// DPR-194: the renewal a running control plane never noticed. This is the round
// trip the unit test cannot make: renew through the store, then ask a Service
// that was loaded BEFORE the renewal what its issuing window is. Before the fix
// it answered with the superseded certificate for the life of the process.
func TestRefreshAdoptsARenewedIntermediateWithoutAReload(t *testing.T) {
	ctx := context.Background()
	pool, svc, tenantID := setup(ctx, t)

	_, before := svc.IssuingWindow()
	if before.IsZero() {
		t.Fatal("the loaded service must report an issuing window")
	}

	// Renewal must be signed by THIS deployment's root, and the root key is only
	// ever handed out by InitCA — setup() has already run it against this shared
	// database, so the key it returned is gone. Clear the hierarchy and mint a
	// fresh one rather than skipping: a skip here would mean the round trip this
	// test exists for never runs in CI, which is what
	// TestClickHouseIsolationMandatoryServicePolicy is there to prevent. This test
	// is declared last in the file and leaves a valid hierarchy behind, which is
	// the state every other test's setup() tolerates.
	if _, err := pool.Exec(ctx, `DELETE FROM agent_ca`); err != nil {
		t.Fatalf("clear agent CA for a fresh hierarchy: %v", err)
	}
	rootKey, err := enroll.InitCA(ctx, pool)
	if err != nil {
		t.Fatalf("init a fresh agent CA: %v", err)
	}
	svc, err = enroll.Load(ctx, pool, nil)
	if err != nil {
		t.Fatalf("reload against the fresh hierarchy: %v", err)
	}
	_, before = svc.IssuingWindow()
	if changed, err := svc.Refresh(ctx); err != nil || changed {
		t.Fatalf("refresh with no renewal: changed=%v err=%v, want false/nil", changed, err)
	}

	notAfter, err := enroll.RenewIntermediate(ctx, pool, rootKey, 2*365*24*time.Hour)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if !notAfter.After(before) {
		t.Fatalf("the renewed intermediate must outlive the old one: %s vs %s", notAfter, before)
	}

	// The service was loaded before the renewal and has not been recreated.
	if _, stale := svc.IssuingWindow(); !stale.Equal(before) {
		t.Fatalf("the window changed without a refresh: %s", stale)
	}
	changed, err := svc.Refresh(ctx)
	if err != nil {
		t.Fatalf("refresh after renewal: %v", err)
	}
	if !changed {
		t.Fatal("a refresh after a renewal must report the intermediate changed")
	}
	_, after := svc.IssuingWindow()
	if !after.Equal(notAfter) {
		t.Errorf("after the refresh the window must be the NEW expiry; got %s, want %s", after, notAfter)
	}
	// The overlap has to survive the refresh, or the swap strands every agent
	// holding a leaf from the superseded intermediate.
	if n := bytes.Count(svc.Bundle(), []byte("BEGIN CERTIFICATE")); n != 3 {
		t.Errorf("bundle after refresh has %d certificates, want 3 (root + new + superseded)", n)
	}
	// And an agent can still enroll on the new chain.
	if _, _, err := svc.MintToken(ctx, tenantID, "00000000-0000-4000-8000-00000000f194", "post-renewal", "test", time.Hour); err != nil {
		t.Errorf("minting a join token after the refresh failed: %v", err)
	}
}
