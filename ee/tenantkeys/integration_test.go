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
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
	"github.com/imfeelingtheagi/probectl/migrations"
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
	if _, err := ring.Rotate(ctx, tnA, ModeManaged, ""); err != nil {
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
