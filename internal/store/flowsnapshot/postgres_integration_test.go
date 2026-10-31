// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowsnapshot_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
	"github.com/ctlplne/probectl/internal/tenantlife"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

type postgresFixture struct {
	admin     *pgxpool.Pool
	pool      *pgxpool.Pool
	objects   objectstore.Store
	red, blue *store.Tenant
	engine    *tenantlife.Engine
	validate  flowsnapshot.Validate
}

func newPostgresFixture(t *testing.T) *postgresFixture {
	t.Helper()
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, testsupport.PostgresDSN())
	if err != nil {
		testsupport.SkipOrFatal(t, "snapshot PostgreSQL configuration unavailable")
		return nil
	}
	t.Cleanup(admin.Close)
	if err := admin.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "snapshot PostgreSQL unavailable")
		return nil
	}
	// SweepRetention enumerates all active tenants in its database. Keep
	// deliberate audit faults in other integration fixtures outside this
	// fixture's population; never filter their errors in the production sweep.
	server := admin
	database := fmt.Sprintf("probectl_qa_beta_fx1_snapshot_%d", time.Now().UnixNano())
	quotedDatabase := pgx.Identifier{database}.Sanitize()
	if _, err := server.Exec(ctx, `CREATE DATABASE `+quotedDatabase); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := server.Exec(cleanup, `DROP DATABASE IF EXISTS `+quotedDatabase+` WITH (FORCE)`); err != nil {
			t.Errorf("own snapshot database cleanup: %v", err)
		}
	})
	adminConfig := server.Config()
	adminConfig.ConnConfig.Database = database
	admin, err = pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, admin); err != nil {
		t.Fatalf("migration: %v", err)
	}
	pool := admin
	if dsn := os.Getenv("PROBECTL_FLOW_FILTER_TEST_DATABASE_URL"); dsn != "" {
		configuration, parseErr := pgxpool.ParseConfig(dsn)
		if parseErr != nil {
			t.Fatal("invalid runtime database configuration")
		}
		// Admission must prevent nested-lease starvation even at the smallest
		// supported pool, including a concurrent lifecycle instance.
		configuration.ConnConfig.Database = database
		configuration.MaxConns = 4
		pool, err = pgxpool.NewWithConfig(ctx, configuration)
		if err != nil {
			t.Fatal("invalid runtime database configuration")
		}
		t.Cleanup(pool.Close)
		if err := pool.Ping(ctx); err != nil {
			t.Fatal("runtime database unavailable")
		}
		// The running control plane reserves a singleton-lease session. Keep
		// that session occupied here as well: only three workers remain.
		reserved, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(reserved.Release)
	}
	objects, err := objectstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := tenantcrypto.NewEnvelopeSealer("qa-snapshot-only", base64.StdEncoding.EncodeToString(key))
	crypto.Zeroize(key)
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(sealer)
	t.Cleanup(tenantcrypto.Reset)
	tenants := store.NewTenants(pool)
	red, err := tenants.Create(ctx, fmt.Sprintf("fx1-snapshot-red-%d", time.Now().UnixNano()), "Red")
	if err != nil {
		t.Fatal(err)
	}
	blue, err := tenants.Create(ctx, fmt.Sprintf("fx1-snapshot-blue-%d", time.Now().UnixNano()), "Blue")
	if err != nil {
		t.Fatal(err)
	}
	e := tenantlife.New(pool, nil, objects, nil, nil, "QA fixture has no backups", nil)
	t.Cleanup(func() {
		for _, tenant := range []*store.Tenant{red, blue} {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			attestation, err := e.Erase(ctx, tenant.ID, tenant.Slug, "qa-fixture")
			cancel()
			if err != nil || !attestation.Complete {
				t.Errorf("own snapshot fixture erasure incomplete: %+v %v", attestation, err)
			}
		}
	})
	return &postgresFixture{admin: admin, pool: pool, objects: objects, red: red, blue: blue, engine: e, validate: func(_ context.Context, _ flowsnapshot.Scope, proof json.RawMessage) error {
		if string(proof) != `{"fixture":"source-valid"}` {
			return errors.New("invalid source proof")
		}
		return nil
	}}
}

func (f *postgresFixture) replica(router tenancy.Router, tempDir string) *flowsnapshot.Service {
	return flowsnapshot.New(f.pool, f.objects, router, tenancy.NewPostgresWriterFence(f.pool), f.validate, flowsnapshot.Config{TempDir: tempDir})
}
func allowPostgresSnapshot(_ context.Context, _ flowsnapshot.Scope, required []string) error {
	found := map[string]bool{}
	for _, permission := range required {
		found[permission] = true
	}
	if !found["ai.query"] || !found["flow.read"] {
		return errors.New("snapshot lost source permissions")
	}
	return nil
}
func postgresInput(n int) flowsnapshot.Input {
	rows := make([]json.RawMessage, n)
	for i := range rows {
		rows[i] = json.RawMessage(fmt.Sprintf(`{"group":{"src_addr":"192.0.%d.%d","fixture_row":"%05d"},"metrics":{"bytes:total":"18446744073709551616001"}}`, i/256, i%256, i))
	}
	return flowsnapshot.Input{Query: json.RawMessage(`{"from":"2020-01-01","table_rows":50000}`), Header: json.RawMessage(`{"other":{"other":true},"totals":{"bytes:total":"922337203685477580800050000"}}`), Validity: json.RawMessage(`{"fixture":"source-valid"}`), Rows: rows, ValidUntil: time.Now().Add(time.Hour)}
}

func TestSnapshotsPostgresRealReplicasRLSOwnershipPortabilityAndErasure(t *testing.T) {
	f := newPostgresFixture(t)
	if f == nil {
		return
	}
	ctx := t.Context()
	scope := flowsnapshot.Scope{TenantID: f.red.ID, Owner: "alice@example.test"}
	firstReplica := f.replica(tenancy.PooledRouter{}, t.TempDir())
	secondReplica := f.replica(tenancy.PooledRouter{}, t.TempDir())
	page, err := firstReplica.Create(ctx, scope, []string{"metrics.read"}, 4999, allowPostgresSnapshot, func(context.Context) (flowsnapshot.Input, error) { return postgresInput(50000), nil })
	if err != nil {
		t.Fatal(err)
	}
	first := page
	rows := 0
	for {
		for _, row := range page.Rows {
			if !strings.Contains(string(row), fmt.Sprintf(`"fixture_row":"%05d"`, rows)) || !strings.Contains(string(row), `"18446744073709551616001"`) {
				t.Fatalf("row %d changed", rows)
			}
			rows++
		}
		if page.NextCursor == "" {
			break
		}
		page, err = secondReplica.Resume(ctx, scope, page.NextCursor, allowPostgresSnapshot)
		if err != nil {
			t.Fatal(err)
		}
	}
	if rows != 50000 {
		t.Fatalf("selected rows %d", rows)
	}
	for _, foreign := range []flowsnapshot.Scope{{TenantID: f.blue.ID, Owner: scope.Owner}, {TenantID: f.red.ID, Owner: "bob@example.test"}} {
		if _, err := secondReplica.Resume(ctx, foreign, first.NextCursor, allowPostgresSnapshot); !errors.Is(err, flowsnapshot.ErrNotFound) {
			t.Fatalf("foreign snapshot read: %v", err)
		}
	}
	// The app role itself confines predicate-free SELECTs, independently of
	// get's explicit tenant AND owner predicates.
	for _, tenant := range []string{f.red.ID, f.blue.ID} {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM flow_snapshots`).Scan(&count); err != nil {
				return err
			}
			want := 0
			if tenant == f.red.ID {
				want = 1
			}
			if count != want {
				return fmt.Errorf("predicate-free snapshot count %d, want %d", count, want)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	providerErr := tenancy.InProvider(ctx, f.pool, func(ctx context.Context, q tenancy.Querier) error {
		var count int
		return q.QueryRow(ctx, `SELECT count(*) FROM flow_snapshots`).Scan(&count)
	})
	var providerDenied *pgconn.PgError
	if !errors.As(providerErr, &providerDenied) || providerDenied.Code != "42501" {
		t.Fatalf("provider did not receive storage permission denial: %v", providerErr)
	}
	newID, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(f.red.ID)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO flow_snapshots(tenant_id,id,owner_id,generation,query_hash,object_lane,created_at,expires_at,row_count,page_size,permissions,private_header,charged_bytes,state) SELECT $1::uuid,$2::uuid,owner_id,generation,query_hash,object_lane,created_at,expires_at,row_count,page_size,permissions,private_header,charged_bytes,state FROM flow_snapshots WHERE tenant_id=$3::uuid`, f.blue.ID, newID, f.red.ID)
		return err
	})
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) || pgError.Code != "42501" {
		t.Fatalf("foreign WITH CHECK did not refuse: %v", err)
	}
	// An app-role transaction with no tenant GUC sees neither tenant.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE probectl_app`); err != nil {
		t.Fatal(err)
	}
	var unscoped int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM flow_snapshots`).Scan(&unscoped); err != nil || unscoped != 0 {
		t.Fatalf("missing tenant GUC read %d: %v", unscoped, err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	// Hybrid keeps metadata pooled and isolates objects. Another snapshot for
	// the sibling proves both the physical object lane and sibling retention.
	hybrid := f.replica(tenancy.DeclaredRouter{Model: tenancy.IsolationHybrid}, t.TempDir())
	blueScope := flowsnapshot.Scope{TenantID: f.blue.ID, Owner: scope.Owner}
	blue, err := hybrid.Create(ctx, blueScope, []string{"flow.read"}, 1, allowPostgresSnapshot, func(context.Context) (flowsnapshot.Input, error) { return postgresInput(3), nil })
	if err != nil {
		t.Fatal(err)
	}
	keys, err := f.objects.List(ctx, "silo/"+f.blue.ID+"/flow-explorer/snapshots/")
	if err != nil || len(keys) != 2 {
		t.Fatalf("hybrid object namespace: %d %v", len(keys), err)
	}
	// No portability path serializes the encrypted keys or derived object
	// inventory. Source telemetry/reusable filters remain the portable inputs.
	var archive bytes.Buffer
	manifest, err := f.engine.Export(ctx, f.red.ID, &archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Objects) != 0 {
		t.Fatal("ephemeral object inventory was exported")
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(header.Name, "flow_snapshots") || strings.Contains(header.Name, "flow_snapshot_epochs") {
			t.Fatalf("private cache metadata exported: %s", header.Name)
		}
	}
	subject, err := f.engine.ExportSubject(ctx, f.red.ID, scope.Owner, &bytes.Buffer{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if subject.TenantID != f.red.ID {
		t.Fatal("subject export crossed tenant")
	}
	report, err := f.engine.EraseSubject(ctx, f.red.ID, scope.Owner, "qa-operator", "snapshot lifecycle proof")
	if err != nil || !report.Complete {
		t.Fatalf("subject cache erasure incomplete: %+v %v", report, err)
	}
	if _, err := secondReplica.Resume(ctx, scope, first.NextCursor, allowPostgresSnapshot); !errors.Is(err, flowsnapshot.ErrNotFound) {
		t.Fatalf("erased snapshot replayed: %v", err)
	}
	for _, prefix := range []string{"tenant/" + f.red.ID + "/flow-explorer/snapshots/", "silo/" + f.red.ID + "/flow-explorer/snapshots/"} {
		keys, err := f.objects.List(ctx, prefix)
		if err != nil || len(keys) != 0 {
			t.Fatalf("physical cache survived: %d %v", len(keys), err)
		}
	}
	if _, err := hybrid.Resume(ctx, blueScope, blue.NextCursor, allowPostgresSnapshot); err != nil {
		t.Fatalf("sibling cache affected: %v", err)
	}
}

func TestSnapshotsPostgresRealErasureDrainsSourceReadAndPublication(t *testing.T) {
	f := newPostgresFixture(t)
	if f == nil {
		return
	}
	ctx := t.Context()
	scope := flowsnapshot.Scope{TenantID: f.red.ID, Owner: "alice@example.test"}
	replica := f.replica(tenancy.PooledRouter{}, t.TempDir())
	entered := make(chan struct{})
	release := make(chan struct{})
	built := make(chan flowsnapshot.Page, 1)
	buildError := make(chan error, 1)
	go func() {
		page, err := replica.Create(ctx, scope, []string{"flow.read"}, 1, allowPostgresSnapshot, func(context.Context) (flowsnapshot.Input, error) {
			close(entered)
			<-release
			return postgresInput(3), nil
		})
		built <- page
		buildError <- err
	}()
	<-entered
	erased := make(chan error, 1)
	go func() {
		report, err := f.engine.EraseSubject(ctx, f.red.ID, scope.Owner, "qa-operator", "paused source query race")
		if err == nil && !report.Complete {
			err = fmt.Errorf("incomplete erasure: %+v", report)
		}
		erased <- err
	}()
	select {
	case err := <-erased:
		close(release)
		t.Fatalf("erasure passed the live query lease: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	page := <-built
	if err := <-buildError; err != nil {
		t.Fatal(err)
	}
	if err := <-erased; err != nil {
		t.Fatal(err)
	}
	if _, err := replica.Resume(ctx, scope, page.NextCursor, allowPostgresSnapshot); !errors.Is(err, flowsnapshot.ErrNotFound) {
		t.Fatalf("paused query replayed after erasure: %v", err)
	}
	keys, err := f.objects.List(ctx, "tenant/"+f.red.ID+"/flow-explorer/snapshots/")
	if err != nil || len(keys) != 0 {
		t.Fatalf("paused query left objects after completed erasure: %d %v", len(keys), err)
	}
}

func TestSnapshotsPostgresRealAuditFailureCannotPublishPartialResult(t *testing.T) {
	f := newPostgresFixture(t)
	if f == nil {
		return
	}
	ctx := t.Context()
	if _, err := f.admin.Exec(ctx, `CREATE OR REPLACE FUNCTION public.probectl_qa_beta_snapshot_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.actor = 'probectl-qa-beta-snapshot-audit-refusal' AND NEW.action = 'flow.snapshot.create' THEN RAISE EXCEPTION 'QA snapshot audit append refused'; END IF; RETURN NEW; END $$;
DROP TRIGGER IF EXISTS probectl_qa_beta_snapshot_audit_fault ON audit_events;
CREATE TRIGGER probectl_qa_beta_snapshot_audit_fault BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION public.probectl_qa_beta_snapshot_audit_fault()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.admin.Exec(context.Background(), `DROP TRIGGER IF EXISTS probectl_qa_beta_snapshot_audit_fault ON audit_events; DROP FUNCTION IF EXISTS public.probectl_qa_beta_snapshot_audit_fault()`); err != nil {
			t.Errorf("own audit fault cleanup: %v", err)
		}
	})
	replica := f.replica(tenancy.PooledRouter{}, t.TempDir())
	scope := flowsnapshot.Scope{TenantID: f.red.ID, Owner: "probectl-qa-beta-snapshot-audit-refusal"}
	if _, err := replica.Create(ctx, scope, []string{"flow.read"}, 1, allowPostgresSnapshot, func(context.Context) (flowsnapshot.Input, error) { return postgresInput(3), nil }); err == nil {
		t.Fatal("result published despite failed atomic audit append")
	}
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(f.red.ID)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var manifests, completed int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM flow_snapshots WHERE tenant_id=$1::uuid`, f.red.ID).Scan(&manifests); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1::uuid AND action='flow.snapshot.create'`, f.red.ID).Scan(&completed); err != nil {
			return err
		}
		if manifests != 0 || completed != 0 {
			return fmt.Errorf("audit refusal left %d manifests / %d completion events", manifests, completed)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := f.objects.List(ctx, "tenant/"+f.red.ID+"/flow-explorer/snapshots/")
	if err != nil || len(keys) != 0 {
		t.Fatalf("failed audit left ciphertext: %d %v", len(keys), err)
	}
}

func TestSnapshotsPostgresRealRetentionPolicyAuditRollbackAndInvalidation(t *testing.T) {
	f := newPostgresFixture(t)
	if f == nil {
		return
	}
	ctx := t.Context()
	tenantCtx := tenancy.WithTenant(ctx, tenancy.ID(f.red.ID))
	days := 30
	policy := tenantlife.RetentionPolicy{TenantID: f.red.ID, FlowRetentionDays: &days}
	if err := f.engine.SetRetention(tenantCtx, policy, "qa-policy-operator"); err != nil {
		t.Fatal(err)
	}
	replica := f.replica(tenancy.PooledRouter{}, t.TempDir())
	scope := flowsnapshot.Scope{TenantID: f.red.ID, Owner: "alice@example.test"}
	page, err := replica.Create(ctx, scope, []string{"flow.read"}, 1, allowPostgresSnapshot, func(context.Context) (flowsnapshot.Input, error) { return postgresInput(3), nil })
	if err != nil {
		t.Fatal(err)
	}
	blueScope := flowsnapshot.Scope{TenantID: f.blue.ID, Owner: scope.Owner}
	blue, err := replica.Create(ctx, blueScope, []string{"flow.read"}, 1, allowPostgresSnapshot, func(context.Context) (flowsnapshot.Input, error) { return postgresInput(3), nil })
	if err != nil {
		t.Fatal(err)
	}
	type state struct {
		Generation, Head int64
		Hash             string
		Days             int
		Invalidating     bool
		Manifests        int
	}
	read := func() state {
		t.Helper()
		var v state
		err := tenancy.InTenant(tenantCtx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			if err := sc.Q.QueryRow(ctx, `SELECT generation,invalidating FROM flow_snapshot_epochs WHERE tenant_id=$1::uuid`, f.red.ID).Scan(&v.Generation, &v.Invalidating); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT head_seq,head_hash FROM audit_stream_heads WHERE tenant_id=$1::uuid`, f.red.ID).Scan(&v.Head, &v.Hash); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT flow_retention_days FROM tenant_retention WHERE tenant_id=$1::uuid`, f.red.ID).Scan(&v.Days); err != nil {
				return err
			}
			return sc.Q.QueryRow(ctx, `SELECT count(*) FROM flow_snapshots WHERE tenant_id=$1::uuid`, f.red.ID).Scan(&v.Manifests)
		})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	before := read()
	if _, err := f.admin.Exec(ctx, `CREATE OR REPLACE FUNCTION public.probectl_qa_beta_snapshot_policy_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.actor = 'probectl-qa-beta-snapshot-policy-refusal' AND NEW.action = 'lifecycle.retention_set' THEN RAISE EXCEPTION 'QA retention policy audit append refused'; END IF; RETURN NEW; END $$;
DROP TRIGGER IF EXISTS probectl_qa_beta_snapshot_policy_fault ON audit_events;
CREATE TRIGGER probectl_qa_beta_snapshot_policy_fault BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION public.probectl_qa_beta_snapshot_policy_fault()`); err != nil {
		t.Fatal(err)
	}
	dropFault := func() {
		t.Helper()
		if _, err := f.admin.Exec(context.Background(), `DROP TRIGGER IF EXISTS probectl_qa_beta_snapshot_policy_fault ON audit_events; DROP FUNCTION IF EXISTS public.probectl_qa_beta_snapshot_policy_fault()`); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(dropFault)
	days = 14
	if err := f.engine.SetRetention(tenantCtx, policy, "probectl-qa-beta-snapshot-policy-refusal"); err == nil {
		t.Fatal("policy audit refusal succeeded")
	}
	if after := read(); after != before {
		t.Fatalf("failed policy audit changed state: before=%+v after=%+v", before, after)
	}
	if _, err := replica.Resume(ctx, scope, page.NextCursor, allowPostgresSnapshot); err != nil {
		t.Fatalf("failed policy/audit invalidated old result: %v", err)
	}
	dropFault()
	if err := f.engine.SetRetention(tenantCtx, policy, "qa-policy-operator"); err != nil {
		t.Fatal(err)
	}
	if after := read(); after.Days != 14 || after.Manifests != 0 || after.Invalidating || after.Generation <= before.Generation {
		t.Fatalf("policy/cache transition incomplete: %+v", after)
	}
	if _, err := replica.Resume(ctx, scope, page.NextCursor, allowPostgresSnapshot); !errors.Is(err, flowsnapshot.ErrNotFound) {
		t.Fatalf("changed policy replayed old result: %v", err)
	}
	keys, err := f.objects.List(ctx, "tenant/"+f.red.ID+"/flow-explorer/snapshots/")
	if err != nil || len(keys) != 0 {
		t.Fatalf("changed policy left cache objects: %d %v", len(keys), err)
	}
	if _, err := replica.Resume(ctx, blueScope, blue.NextCursor, allowPostgresSnapshot); err != nil {
		t.Fatalf("policy change affected sibling: %v", err)
	}
	// An empty cache adds no unrelated audit events to the standing exact-one
	// retention policy contract.
	empty := read()
	days = 7
	if err := f.engine.SetRetention(tenantCtx, policy, "qa-policy-operator"); err != nil {
		t.Fatal(err)
	}
	if after := read(); after.Head != empty.Head+1 || after.Days != 7 {
		t.Fatalf("empty-cache policy audit changed contract: before=%+v after=%+v", empty, after)
	}
}

func TestSnapshotsPostgresRealBackgroundPruneRequiresIntentAndInvalidatesCache(t *testing.T) {
	f := newPostgresFixture(t)
	if f == nil {
		return
	}
	ctx := t.Context()
	// Scheduled retention leaves lifecycle-fenced tenants to the erasure worker.
	// The DB itself forbids an active registry row with a committed audit fence.
	for _, kind := range []string{"offboarding"} {
		fixture, err := store.NewTenants(f.pool).Create(ctx, fmt.Sprintf("fx1-retention-fenced-%s-%d", kind, time.Now().UnixNano()), "Fenced QA")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := f.admin.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, fixture.ID); err != nil {
				t.Errorf("own empty registry fixture cleanup: %v", err)
			}
		})
		if _, err := f.admin.Exec(ctx, `UPDATE tenants SET status='offboarding',audit_write_fenced_at=now() WHERE id=$1::uuid`, fixture.ID); err != nil {
			t.Fatal(err)
		}
	}
	memory := flowstore.NewMemory()
	now := time.Now().UTC()
	for _, tenant := range []string{f.red.ID, f.blue.ID} {
		old := flowstore.Row{TenantID: tenant, AgentID: "qa-collector", Exporter: "192.0.2.1", TS: now.Add(-48 * time.Hour), SrcAddr: "198.51.100.1", DstAddr: "203.0.113.1", Bytes: 1, Packets: 1}
		fresh := old
		fresh.TS = now
		if err := memory.Insert(ctx, []flowstore.Row{old, fresh}); err != nil {
			t.Fatal(err)
		}
	}
	refuseIntent := true
	refusal := errors.New("QA provider prune intent refused")
	sink := func(ctx context.Context, actor, action, target string, data map[string]any) error {
		if refuseIntent && target == f.red.ID && data["store"] == "flows" && data["status"] == "intent" {
			return refusal
		}
		_, err := audit.ProviderAppend(ctx, f.pool, actor, action, target, data)
		return err
	}
	engine := tenantlife.New(f.pool, memory, f.objects, nil, sink, "QA no backups", nil)
	days := 1
	if err := engine.SetRetention(tenancy.WithTenant(ctx, tenancy.ID(f.red.ID)), tenantlife.RetentionPolicy{TenantID: f.red.ID, FlowRetentionDays: &days}, "qa-policy-operator"); err != nil {
		t.Fatal(err)
	}
	replica := f.replica(tenancy.PooledRouter{}, t.TempDir())
	redScope := flowsnapshot.Scope{TenantID: f.red.ID, Owner: "alice@example.test"}
	blueScope := flowsnapshot.Scope{TenantID: f.blue.ID, Owner: redScope.Owner}
	create := func(scope flowsnapshot.Scope) flowsnapshot.Page {
		t.Helper()
		page, err := replica.Create(ctx, scope, []string{"flow.read"}, 1, allowPostgresSnapshot, func(context.Context) (flowsnapshot.Input, error) { return postgresInput(3), nil })
		if err != nil {
			t.Fatal(err)
		}
		return page
	}
	red, blue := create(redScope), create(blueScope)
	count := func(tenant string) int64 {
		t.Helper()
		var rows bytes.Buffer
		n, err := memory.ExportTenant(ctx, tenant, &rows)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if err := engine.SweepRetention(ctx); !errors.Is(err, refusal) {
		t.Fatalf("failed prune intent not returned: %v", err)
	}
	if count(f.red.ID) != 2 {
		t.Fatal("source changed after refused intent")
	}
	if _, err := replica.Resume(ctx, redScope, red.NextCursor, allowPostgresSnapshot); err != nil {
		t.Fatalf("cache changed after refused source-prune intent: %v", err)
	}
	refuseIntent = false
	if err := engine.SweepRetention(ctx); err != nil {
		t.Fatal(err)
	}
	if count(f.red.ID) != 1 || count(f.blue.ID) != 2 {
		t.Fatal("source retention did not preserve fresh/sibling inputs")
	}
	if _, err := replica.Resume(ctx, redScope, red.NextCursor, allowPostgresSnapshot); !errors.Is(err, flowsnapshot.ErrNotFound) {
		t.Fatalf("source prune replayed old cache: %v", err)
	}
	if _, err := replica.Resume(ctx, blueScope, blue.NextCursor, allowPostgresSnapshot); err != nil {
		t.Fatalf("source prune affected sibling cache: %v", err)
	}
	keys, err := f.objects.List(ctx, "tenant/"+f.red.ID+"/flow-explorer/snapshots/")
	if err != nil || len(keys) != 0 {
		t.Fatalf("source prune left cached objects: %d %v", len(keys), err)
	}
}

func TestSnapshotsPostgresRealBackgroundExpiryReclaimsObjectsAndCharge(t *testing.T) {
	f := newPostgresFixture(t)
	if f == nil {
		return
	}
	ctx := t.Context()
	replica := flowsnapshot.New(f.pool, f.objects, tenancy.PooledRouter{}, tenancy.NewPostgresWriterFence(f.pool), f.validate, flowsnapshot.Config{Lifetime: 2 * time.Second, TempDir: t.TempDir()})
	redScope := flowsnapshot.Scope{TenantID: f.red.ID, Owner: "alice@example.test"}
	red, err := replica.Create(ctx, redScope, []string{"flow.read"}, 1, allowPostgresSnapshot, func(context.Context) (flowsnapshot.Input, error) { return postgresInput(3), nil })
	if err != nil {
		t.Fatal(err)
	}
	other := f.replica(tenancy.PooledRouter{}, t.TempDir())
	blueScope := flowsnapshot.Scope{TenantID: f.blue.ID, Owner: redScope.Owner}
	blue, err := other.Create(ctx, blueScope, []string{"flow.read"}, 1, allowPostgresSnapshot, func(context.Context) (flowsnapshot.Input, error) { return postgresInput(3), nil })
	if err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(time.Until(red.ExpiresAt) + 20*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	engine := tenantlife.New(f.pool, nil, f.objects, nil, func(ctx context.Context, actor, action, target string, data map[string]any) error {
		_, err := audit.ProviderAppend(ctx, f.pool, actor, action, target, data)
		return err
	}, "QA no backups", nil)
	if err := engine.SweepFlowSnapshotExpiry(ctx); err != nil {
		t.Fatal(err)
	}
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(f.red.ID)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var count, charged int64
		if err := sc.Q.QueryRow(ctx, `SELECT count(*),COALESCE(sum(charged_bytes),0)::bigint FROM flow_snapshots WHERE tenant_id=$1::uuid`, f.red.ID).Scan(&count, &charged); err != nil {
			return err
		}
		if count != 0 || charged != 0 {
			return fmt.Errorf("expired snapshot still charged: %d rows / %d bytes", count, charged)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := f.objects.List(ctx, "tenant/"+f.red.ID+"/flow-explorer/snapshots/")
	if err != nil || len(keys) != 0 {
		t.Fatalf("expired cache objects remain: %d %v", len(keys), err)
	}
	if _, err := other.Resume(ctx, blueScope, blue.NextCursor, allowPostgresSnapshot); err != nil {
		t.Fatalf("expiry maintenance affected live sibling: %v", err)
	}
}

func TestSnapshotsPostgresRealFixturesIsolateRetentionPopulations(t *testing.T) {
	first := newPostgresFixture(t)
	if first == nil {
		return
	}
	second := newPostgresFixture(t)
	if second == nil {
		return
	}
	var foreign int
	if err := second.admin.QueryRow(t.Context(), `SELECT count(*) FROM tenants WHERE id=$1::uuid OR id=$2::uuid`, first.red.ID, first.blue.ID).Scan(&foreign); err != nil {
		t.Fatal(err)
	}
	if foreign != 0 {
		t.Fatal("snapshot retention fixture shares another fixture's sweep population")
	}
}
