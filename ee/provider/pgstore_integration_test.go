// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

//go:build integration

package provider

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/migrations"
)

// The PG-backed provider store against the real test stack (Kafka-less: only
// Postgres is needed). Proves: the 0024 schema works end-to-end, the
// probectl_provider role can run the whole lifecycle, and — the storage-layer
// guardrail — that role CANNOT read telemetry tables at all.
func pgPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("PROBECTL_TEST_POSTGRES")
	if dsn == "" {
		dsn = "postgres://probectl:probectl@localhost:5432/probectl"
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

func TestPGStoreLifecycle(t *testing.T) {
	pool := pgPool(t)
	defer pool.Close()
	st := NewPGStore(pool)
	ctx := context.Background()

	// Operator round-trip incl. sealed TOTP columns.
	tok := crypto.Hash([]byte("enroll-integration"))
	op, err := st.CreateOperator(ctx, Operator{Email: "it@msp.example", Name: "IT", Role: RoleAdmin}, tok)
	if err != nil && err != ErrConflict {
		t.Fatalf("create operator: %v", err)
	}
	if err == ErrConflict { // idempotent re-runs
		o, _, e := st.OperatorByEmail(ctx, "it@msp.example")
		if e != nil {
			t.Fatal(e)
		}
		op = *o
	}
	if _, err := st.OperatorByEnrollHash(ctx, tok); err != nil && !op.Enrolled {
		t.Fatalf("enroll hash lookup: %v", err)
	}
	sealed := crypto.Sealed{KeyID: "it", WrappedDEK: []byte{1, 2}, Ciphertext: []byte{3, 4}}
	if err := st.SetOperatorTOTP(ctx, op.ID, sealed); err != nil {
		t.Fatal(err)
	}
	if err := st.ActivateOperator(ctx, op.ID, "pbkdf2$sha256$600000$x$y"); err != nil {
		t.Fatal(err)
	}
	got, cred, err := st.OperatorByEmail(ctx, "it@msp.example")
	if err != nil || !got.Enrolled || cred.TOTP.KeyID != "it" {
		t.Fatalf("operator readback: %+v %+v %v", got, cred, err)
	}

	// Tenant lifecycle.
	slug := "it-" + time.Now().UTC().Format("150405")
	tn, err := st.CreateTenant(ctx, slug, "Integration Tenant", "pooled", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetTenantStatus(ctx, tn.ID, "suspended"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetTenantStatus(ctx, tn.ID, "offboarding"); err != nil {
		t.Fatal(err)
	}

	// Grants.
	g, err := st.CreateGrant(ctx, Grant{
		OperatorID: op.ID, TenantID: tn.ID, Reason: "integration", Scope: "read",
		GrantedBy: op.Email, GrantedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ConsentGrant(ctx, g.ID, "admin@tenant", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := st.IncrementGrantUse(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	back, err := st.GetGrant(ctx, g.ID)
	if err != nil || back.UseCount != 1 || back.ConsentedAt == nil {
		t.Fatalf("grant readback: %+v %v", back, err)
	}

	// Fleet aggregation runs (rows depend on the shared DB's agents).
	if _, err := st.FleetSummary(ctx); err != nil {
		t.Fatalf("fleet: %v", err)
	}
}

// TestProviderRoleCannotReadTelemetry is the storage-layer guardrail test:
// the probectl_provider role has NO grant on results/tests — a direct read
// attempt fails with a permission error, no matter what the Go code does.
func TestProviderRoleCannotReadTelemetry(t *testing.T) {
	pool := pgPool(t)
	defer pool.Close()
	err := tenancy.InProvider(context.Background(), pool, func(ctx context.Context, q tenancy.Querier) error {
		var n int
		return q.QueryRow(ctx, `SELECT count(*) FROM results`).Scan(&n)
	})
	if err == nil {
		t.Fatal("probectl_provider must NOT be able to read the results table")
	}
	err = tenancy.InProvider(context.Background(), pool, func(ctx context.Context, q tenancy.Querier) error {
		var n int
		return q.QueryRow(ctx, `SELECT count(*) FROM tests`).Scan(&n)
	})
	if err == nil {
		t.Fatal("probectl_provider must NOT be able to read the tests table")
	}
	// And the sanctioned read DOES work: agents via the explicit fleet policy.
	err = tenancy.InProvider(context.Background(), pool, func(ctx context.Context, q tenancy.Querier) error {
		var n int
		return q.QueryRow(ctx, `SELECT count(*) FROM agents`).Scan(&n)
	})
	if err != nil {
		t.Fatalf("the fleet policy read must work: %v", err)
	}
}
