// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package tenantkeys

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

// The S-T6 integration leg (live Postgres): the key chain persists through
// the provider-role store — provision, rotate, destroy round-trip across
// KEYRING RESTARTS (state lives in tenant_keys, not memory), per-tenant
// isolation holds against the real table, and a destroyed chain stays
// destroyed for a fresh keyring (crypto-offboarding is durable).
func itPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testsupport.PostgresDSN()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

func itTenant(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO tenants (slug, name) VALUES ($1, $1)
		 ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name RETURNING id::text`, slug).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func itMaster(t *testing.T) *crypto.Envelope {
	t.Helper()
	kp, err := crypto.NewStaticKeyProviderFromBase64("it-master",
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return crypto.NewEnvelope(kp)
}

func TestKeyChainPersistencePG(t *testing.T) {
	pool := itPool(t)
	defer pool.Close()
	ctx := context.Background()
	tnA := itTenant(t, pool, "it-keys-a")
	tnB := itTenant(t, pool, "it-keys-b")
	store := NewPGStore(pool)
	// Reset any prior run's chains (test idempotence).
	if _, err := pool.Exec(ctx, `DELETE FROM tenant_keys WHERE tenant_id IN ($1, $2)`, tnA, tnB); err != nil {
		t.Fatal(err)
	}

	ring, err := NewKeyring(store, itMaster(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("alert-channel-secret")

	// Provision (auto v1) + seal, then rotate to v2 and seal again.
	blob1, err := ring.Seal(ctx, tnA, []byte("pg-one"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.rotate(ctx, tnA, ModeManaged, ""); err != nil {
		t.Fatal(err)
	}
	blob2, err := ring.Seal(ctx, tnA, []byte("pg-two"), aad)
	if err != nil {
		t.Fatal(err)
	}
	blobB, err := ring.Seal(ctx, tnB, []byte("pg-bee"), aad)
	if err != nil {
		t.Fatal(err)
	}

	// A FRESH keyring (control-plane restart) opens both generations purely
	// from persisted state.
	ring2, err := NewKeyring(NewPGStore(pool), itMaster(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := ring2.Open(ctx, tnA, blob1, aad); err != nil || string(p) != "pg-one" {
		t.Fatalf("restart open v1: %q %v", p, err)
	}
	if p, err := ring2.Open(ctx, tnA, blob2, aad); err != nil || string(p) != "pg-two" {
		t.Fatalf("restart open v2: %q %v", p, err)
	}
	// Cross-tenant: A's chain cannot open B's blob against the real table.
	if _, err := ring2.Open(ctx, tnA, blobB, aad); err == nil {
		t.Fatal("cross-tenant open must fail")
	}

	// Destroy is durable: a third keyring still refuses A but serves B.
	if n, err := ring2.DestroyKeys(ctx, tnA); err != nil || n != 2 {
		t.Fatalf("destroy: n=%d err=%v", n, err)
	}
	ring3, err := NewKeyring(NewPGStore(pool), itMaster(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring3.Open(ctx, tnA, blob2, aad); !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("post-destroy restart open: %v", err)
	}
	if _, err := ring3.Seal(ctx, tnA, []byte("new"), aad); !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("post-destroy restart seal: %v", err)
	}
	if p, err := ring3.Open(ctx, tnB, blobB, aad); err != nil || string(p) != "pg-bee" {
		t.Fatalf("tenant B after A destroy: %q %v", p, err)
	}
	// The wiped material is verifiable in the table itself.
	var withMaterial int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM tenant_keys WHERE tenant_id = $1 AND (wrapped_kek IS NOT NULL OR byok_ref <> '')`,
		tnA).Scan(&withMaterial); err != nil {
		t.Fatal(err)
	}
	if withMaterial != 0 {
		t.Fatalf("destroyed chain still holds material: %d rows", withMaterial)
	}
}

// TestKeyRotationMutationAndAuditAtomicPG proves the production transaction,
// not only the in-memory model: an audit failure rolls back both key mutations,
// concurrent rotations receive unique sequential versions, and tenant B never
// participates in tenant A's transaction.
func TestKeyRotationMutationAndAuditAtomicPG(t *testing.T) {
	pool := itPool(t)
	defer pool.Close()
	ctx := context.Background()
	tnA := itTenant(t, pool, "it-keys-atomic-a")
	tnB := itTenant(t, pool, "it-keys-atomic-b")
	if _, err := pool.Exec(ctx,
		`DELETE FROM tenant_keys WHERE tenant_id IN ($1, $2)`, tnA, tnB); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`DELETE FROM audit_events WHERE tenant_id IN ($1, $2)`, tnA, tnB); err != nil {
		t.Fatal(err)
	}

	store := NewPGStore(pool)
	ring, err := NewKeyring(store, itMaster(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("atomic-pg")
	blobA, err := ring.Seal(ctx, tnA, []byte("tenant-a-v1"), aad)
	if err != nil {
		t.Fatalf("seed tenant A: %v", err)
	}
	blobB, err := ring.Seal(ctx, tnB, []byte("tenant-b-v1"), aad)
	if err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}

	store.audit = func(context.Context, tenancy.Scope, string, KeyVersion) error {
		return errors.New("injected audit sink failure")
	}
	if _, err := ring.RotateAudited(ctx, tnA, "alice@example.test", ModeManaged, ""); err == nil {
		t.Fatal("rotation must fail when the transaction-bound audit append fails")
	}
	assertPGKeyChain(t, pool, tnA, 1, 1)
	assertPGKeyChain(t, pool, tnB, 1, 1)
	var failedAuditRows int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_events
		 WHERE tenant_id = $1 AND action = 'security.key_rotate'`, tnA).Scan(&failedAuditRows); err != nil {
		t.Fatal(err)
	}
	if failedAuditRows != 0 {
		t.Fatalf("failed rotation committed %d audit rows", failedAuditRows)
	}
	fresh, err := NewKeyring(NewPGStore(pool), itMaster(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := fresh.Open(ctx, tnA, blobA, aad); err != nil || string(plain) != "tenant-a-v1" {
		t.Fatalf("tenant A predecessor after rollback: %q %v", plain, err)
	}
	if plain, err := fresh.Open(ctx, tnB, blobB, aad); err != nil || string(plain) != "tenant-b-v1" {
		t.Fatalf("tenant B after tenant A rollback: %q %v", plain, err)
	}

	store.audit = appendRotationAudit
	const rotations = 4
	errs := make(chan error, rotations)
	var wg sync.WaitGroup
	for i := 0; i < rotations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := ring.RotateAudited(ctx, tnA, "alice@example.test", ModeManaged, "")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent PG rotation: %v", err)
		}
	}
	assertPGKeyChain(t, pool, tnA, rotations+1, rotations+1)
	assertPGKeyChain(t, pool, tnB, 1, 1)
	var auditRows int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_events
		 WHERE tenant_id = $1
		   AND actor = 'alice@example.test'
		   AND action = 'security.key_rotate'`, tnA).Scan(&auditRows); err != nil {
		t.Fatal(err)
	}
	if auditRows != rotations {
		t.Fatalf("committed rotation audits = %d, want %d", auditRows, rotations)
	}
}

func assertPGKeyChain(t *testing.T, pool *pgxpool.Pool, tenantID string, rows, activeVersion int) {
	t.Helper()
	var gotRows, activeCount, gotActiveVersion int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*),
		       count(*) FILTER (WHERE state = 'active'),
		       coalesce(max(version) FILTER (WHERE state = 'active'), 0)
		  FROM tenant_keys
		 WHERE tenant_id = $1`, tenantID).Scan(&gotRows, &activeCount, &gotActiveVersion); err != nil {
		t.Fatal(err)
	}
	if gotRows != rows || activeCount != 1 || gotActiveVersion != activeVersion {
		t.Fatalf("tenant %s chain rows=%d active_count=%d active_version=%d; want rows=%d active_count=1 active_version=%d",
			tenantID, gotRows, activeCount, gotActiveVersion, rows, activeVersion)
	}
}
