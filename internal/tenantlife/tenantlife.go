// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package tenantlife is the per-tenant lifecycle engine (S-T5, F55):
// tenant-scoped data EXPORT (portability), VERIFIABLE full deletion across
// every store (Postgres / ClickHouse flows / TSDB / object store / path graph
// / topology / OTLP trace+log store / eBPF L7 edge store) with an audit-grade
// attestation, and per-tenant retention/erasure controls.
//
// This is CORE deliberately (the ratified editions decision): export and
// verifiable deletion are a compliance right, not a commercial feature. Only
// the provider-console offboarding views ride ee/.
//
// Scoping facts the engine builds on:
//   - Postgres deletion runs table-by-table UNDER tenancy.InTenant: RLS (and
//     the S-T2 silo routing) scope every DELETE, so erasing tenant A cannot
//     touch tenant B even if this code were buggy (defense in depth) — and a
//     siloed tenant's deletes land inside its own schema.
//   - The tenant-owned table set derives LIVE from information_schema minus
//     the shared provider-owned deny list (internal/tenancy) — the same
//     vocabulary the silo provisioner uses, so the two can never disagree.
//   - Provider-plane rows ABOUT the tenant (usage, quotas, break-glass, and
//     compatibility-window rows) are erased through the provider role.
//   - "Deleted" is verified by counting AFTER deleting: the attestation
//     records per-store remaining==0, not a promise.
package tenantlife

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/objectstore"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/endpointstore"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
)

// TSDBTenantDeleter is implemented by TSDB writers that can delete a
// tenant's series in place (the memory writer). The prometheus remote-write
// mode cannot — that store's erasure is the documented manual step
// (delete_series admin API / retention), recorded honestly in the
// attestation.
type TSDBTenantDeleter interface {
	DeleteTenant(ctx context.Context, tenantID string) (int, error)
}

// AuditSink records lifecycle events on the PROVIDER audit stream — the
// chain that survives the tenant's own audit data being erased.
type AuditSink func(ctx context.Context, actor, action, target string, data map[string]any) error

const (
	retentionAuditTimeout       = 5 * time.Second
	retentionPolicyAuditAction  = "lifecycle.retention_set"
	maxRetentionAuditActorBytes = 256
)

var errRetentionAuditUnavailable = errors.New("tenantlife: retention audit sink is unavailable")

type retentionPolicyAuditAppender func(
	context.Context,
	tenancy.Scope,
	string,
	string,
	string,
	map[string]any,
) (audit.Event, error)

// PathDeleter is the pathstore erasure seam (memory + ClickHouse implement it).
type PathDeleter interface {
	DeleteTenant(ctx context.Context, tenantID string) (deleted, remaining int, err error)
}

// TopologyDeleter drops a tenant's topology graph (every snapshot/version).
type TopologyDeleter interface {
	DeleteTenant(tenant string) int
}

// TopologyRetentionPruner removes stale derived topology labels for one tenant.
type TopologyRetentionPruner interface {
	PruneTenantBefore(tenant string, cutoff time.Time) int
}

// EndpointRetentionPruner removes stale endpoint latest-view labels for one
// tenant. The endpoint store is a derived cache; lifecycle owns its age clock.
type EndpointRetentionPruner interface {
	PruneTenantBefore(tenant string, cutoff time.Time) int
}

// OtelDeleter is the OTLP trace/log store erasure seam (otelstore memory +
// ClickHouse implement it). Externally-ingested traces/logs (ARCH-001) are
// tenant PII and a whole telemetry plane, so they MUST be erased on
// offboarding too (TENANT-008) — count-verified like the other stores.
type OtelDeleter interface {
	EraseTenant(ctx context.Context, tenantID string) (deleted, remaining int, err error)
}

// OtelRetentionPruner removes one tenant's OTLP rows older than cutoff.
type OtelRetentionPruner interface {
	PruneTenantBefore(ctx context.Context, tenantID string, cutoff time.Time) (deleted int, err error)
}

// EBPFDeleter is the eBPF L7 edge store erasure seam (ebpfstore memory +
// ClickHouse implement it). The probectl_ebpf_edges plane (workload-to-workload
// topology, dest ports, L7 protocols, byte/packet/connection counts) is tenant
// telemetry and MUST be erased on offboarding too (TENANT-002) — its
// DeleteTenant returns the count-verified REMAINING rows (0 = clean).
type EBPFDeleter interface {
	DeleteTenant(ctx context.Context, tenantID string) (remaining int64, err error)
}

// EBPFRetentionPruner removes one tenant's eBPF aggregates older than cutoff.
type EBPFRetentionPruner interface {
	PruneTenantBefore(ctx context.Context, tenantID string, cutoff time.Time) (deleted int, err error)
}

// PathRetentionPruner removes one tenant's path snapshots older than cutoff.
type PathRetentionPruner interface {
	PruneTenantBefore(ctx context.Context, tenantID string, cutoff time.Time) (deleted int, err error)
}

// SessionRetentionPruner removes inactive tenant-owned session detail while
// preserving the global hash-only replay tombstones.
type SessionRetentionPruner interface {
	PruneInactive(ctx context.Context, tenantID string, replayHorizon time.Duration) (deleted int64, err error)
}

// Engine runs exports, erasures, and retention sweeps.
type Engine struct {
	pool              *pgxpool.Pool
	flows             flowstore.Store
	objects           objectstore.Store
	tsdbW             tsdb.Writer
	paths             PathDeleter // optional (WithPaths)
	topo              TopologyDeleter
	topoRetention     TopologyRetentionPruner
	endpointRetention EndpointRetentionPruner
	endpointEvents    endpointstore.Store
	otel              OtelDeleter // optional (WithOtel) — OTLP trace/log store
	ebpf              EBPFDeleter // optional (WithEBPF) — eBPF L7 edge store
	sessions          SessionRetentionPruner
	sessionReplayTTL  time.Duration
	// aiAnswerRetention is the same tenant-scoped prune seam as the Postgres
	// implementation below. Tests inject it to prove audit ordering without
	// requiring a database; production leaves it nil and uses InTenant.
	aiAnswerRetention  func(context.Context, string, time.Duration) (int64, error)
	audit              AuditSink
	log                *slog.Logger
	now                func() time.Time
	subjectTableExists func(context.Context, tenancy.Scope, string) (bool, error)
	// appendRetentionPolicyAudit is always audit.TenantAppend in production.
	// The unexported seam exists only so package tests can force an append
	// failure and prove the policy upsert rolls back with it.
	appendRetentionPolicyAudit retentionPolicyAuditAppender

	// BackupNote is the operator's backup-retention statement, included
	// verbatim in every attestation (the explicit backup-TTL story).
	backupNote string
	// backupRetentionDays (COMPLY-002): when > 0, the attestation reports a
	// CONCRETE backup-erasure deadline (erased_at + retention) — the bounded
	// window inside which every backup containing the tenant ages out, so
	// erasure provably covers backups. 0 = unquantified (note-only).
	backupRetentionDays int
	// derivedIdentityRetentionDays bounds topology/endpoint identity labels
	// that are rebuilt from higher-volume source stores. 0 disables age pruning.
	derivedIdentityRetentionDays int
}

// New wires the engine. flows/objects/tsdb may be nil (that store absent in
// the deployment — recorded as "not deployed" in attestations, never
// silently skipped). audit may be nil only when no pool exists (tests).
func New(pool *pgxpool.Pool, flows flowstore.Store, objects objectstore.Store, w tsdb.Writer,
	auditSink AuditSink, backupNote string, log *slog.Logger) *Engine {
	return newEngine(pool, flows, objects, w, auditSink, backupNote, 0, log)
}

// NewWithBackupRetention is New plus a concrete backup-retention window
// (days) so the attestation can quantify the backup-erasure deadline
// (COMPLY-002). retentionDays <= 0 falls back to the note-only story.
func NewWithBackupRetention(pool *pgxpool.Pool, flows flowstore.Store, objects objectstore.Store, w tsdb.Writer,
	auditSink AuditSink, backupNote string, retentionDays int, log *slog.Logger) *Engine {
	return newEngine(pool, flows, objects, w, auditSink, backupNote, retentionDays, log)
}

func newEngine(pool *pgxpool.Pool, flows flowstore.Store, objects objectstore.Store, w tsdb.Writer,
	auditSink AuditSink, backupNote string, retentionDays int, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	if backupNote == "" {
		backupNote = "Live-store deletion is attested below. Operator backups/snapshots expire per the deployment's backup policy — state PROBECTL_BACKUP_RETENTION_NOTE to put your TTL on the record."
	}
	return &Engine{pool: pool, flows: flows, objects: objects, tsdbW: w,
		audit: auditSink, backupNote: backupNote, backupRetentionDays: retentionDays,
		log: log, now: time.Now, subjectTableExists: tableExists,
		appendRetentionPolicyAudit: audit.TenantAppend}
}

func tenantObjectStores(objects objectstore.Store, tenantID string) ([]objectstore.TenantStore, error) {
	pooled, err := objectstore.ForTenant(objects, tenantID)
	if err != nil {
		return nil, err
	}
	silo, err := objectstore.ForTenantPrefix(objects, "silo/"+tenantID, tenantID)
	if err != nil {
		return nil, err
	}
	return []objectstore.TenantStore{pooled, silo}, nil
}

// WithPaths attaches the path store for erasure coverage (U-027).
func (e *Engine) WithPaths(p PathDeleter) *Engine { e.paths = p; return e }

// WithTopology attaches the topology store for erasure coverage (U-027) and,
// when implemented, derived identity-cache retention.
func (e *Engine) WithTopology(t TopologyDeleter) *Engine {
	e.topo = t
	if p, ok := t.(TopologyRetentionPruner); ok {
		e.topoRetention = p
	}
	return e
}

// WithEndpointRetention attaches the endpoint/DEM latest-view cache to the
// lifecycle retention sweep. It is not an erasure store because tenant erase
// rebuilds it from empty process state, but age retention still needs an owner.
func (e *Engine) WithEndpointRetention(p EndpointRetentionPruner) *Engine {
	e.endpointRetention = p
	return e
}

// WithEndpointEvents attaches durable endpoint/DEM history for export,
// retention, and count-verified tenant erasure.
func (e *Engine) WithEndpointEvents(store endpointstore.Store) *Engine {
	e.endpointEvents = store
	return e
}

// WithDerivedIdentityRetentionDays sets the deployment default for derived
// topology/endpoint identity caches. A tenant's flow_retention_days override
// can tighten this window, but not loosen it.
func (e *Engine) WithDerivedIdentityRetentionDays(days int) *Engine {
	if days < 0 {
		days = 0
	}
	e.derivedIdentityRetentionDays = days
	return e
}

// WithSessionRetention attaches the bounded cleanup owner for session identity
// detail. replayHorizon is the configured SessionTTL; zero follows the same
// safe default as session issuance.
func (e *Engine) WithSessionRetention(p SessionRetentionPruner, replayHorizon time.Duration) *Engine {
	if replayHorizon <= 0 {
		replayHorizon = auth.DefaultSessionTTL
	}
	e.sessions = p
	e.sessionReplayTTL = replayHorizon
	return e
}

// WithOtel attaches the OTLP trace/log store for erasure coverage (TENANT-008).
func (e *Engine) WithOtel(o OtelDeleter) *Engine { e.otel = o; return e }

// WithEBPF attaches the eBPF L7 edge store for erasure coverage (TENANT-002).
func (e *Engine) WithEBPF(d EBPFDeleter) *Engine { e.ebpf = d; return e }

// WithClock overrides time (tests).
func (e *Engine) WithClock(now func() time.Time) *Engine {
	e.now = now
	return e
}

// tenantOwnedTables derives the live tenant-owned table set (public tables
// with a tenant_id column minus the shared provider-owned deny list).
func (e *Engine) tenantOwnedTables(ctx context.Context) ([]string, error) {
	rows, err := e.pool.Query(ctx, `
		SELECT DISTINCT table_name FROM information_schema.columns
		 WHERE table_schema = 'public' AND column_name = 'tenant_id'
		 ORDER BY table_name`)
	if err != nil {
		return nil, fmt.Errorf("tenantlife: read tenant tables: %w", err)
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		tables = append(tables, t)
	}
	return tenancy.FilterTenantOwned(tables), rows.Err()
}

// --- Verifiable erasure -----------------------------------------------------

// StoreResult is one store's outcome in the attestation.
type StoreResult struct {
	Store        string `json:"store"`
	Deleted      int64  `json:"deleted"`
	VerifiedZero bool   `json:"verified_zero"`
	Notes        string `json:"notes,omitempty"`
}

// Attestation is the deletion report — the proof handed to the offboarded
// customer. Audit-grade: appended to the tamper-evident provider audit chain
// (which survives the tenant's own data) with the report's SHA-256.
type Attestation struct {
	FormatVersion int           `json:"format_version"`
	TenantID      string        `json:"tenant_id"`
	TenantSlug    string        `json:"tenant_slug,omitempty"`
	Actor         string        `json:"actor"`
	StartedAt     time.Time     `json:"started_at"`
	FinishedAt    time.Time     `json:"finished_at"`
	Stores        []StoreResult `json:"stores"`
	BackupPolicy  string        `json:"backup_policy"`
	// COMPLY-002: backups are provably covered within a BOUNDED window. When
	// the deployment states a retention (PROBECTL_BACKUP_RETENTION_DAYS),
	// BackupRetentionDays is that window and BackupErasureDeadline is the
	// instant by which every backup containing this tenant has aged out —
	// after that, no artifact (live or backup) holds the tenant's data.
	BackupRetentionDays   int        `json:"backup_retention_days,omitempty"`
	BackupErasureDeadline *time.Time `json:"backup_erasure_deadline,omitempty"`
	Complete              bool       `json:"complete"`
	ReportSHA256          string     `json:"report_sha256"`
}

// maxDeletePasses bounds the FK-ordering retry loop (intra-tenant foreign
// keys are resolved by repeated passes instead of a dependency graph).
const maxDeletePasses = 6

// Erase deletes one tenant's data from every store, verifies each store
// reads zero afterward, marks the tenant deleted, and appends the
// attestation to the provider audit stream BEFORE returning it. Pooled
// tenants get scoped deletes (RLS-bound); siloed tenants' Postgres deletes
// route into their own schema (the silo container drop itself is the
// provider offboard step and is noted).
func (e *Engine) Erase(ctx context.Context, tenantID, slug, actor string) (Attestation, error) {
	att := Attestation{
		FormatVersion: 1, TenantID: tenantID, TenantSlug: slug, Actor: actor,
		StartedAt: e.now().UTC(), BackupPolicy: e.backupNote, Complete: true,
	}
	fail := func(store, note string) {
		att.Stores = append(att.Stores, StoreResult{Store: store, Deleted: -1, Notes: note})
		att.Complete = false
	}

	// 1) ClickHouse flows (routed: siloed databases are dropped whole).
	if e.flows != nil {
		remaining, err := e.flows.DeleteTenant(ctx, tenantID)
		if err != nil {
			fail("flows", "delete failed: "+err.Error())
		} else {
			att.Stores = append(att.Stores, StoreResult{Store: "flows", VerifiedZero: remaining == 0,
				Notes: "remaining=" + fmt.Sprint(remaining)})
			if remaining != 0 {
				att.Complete = false
			}
		}
	} else {
		att.Stores = append(att.Stores, StoreResult{Store: "flows", VerifiedZero: true, Notes: "store not deployed"})
	}

	// Endpoint event history carries SSIDs, gateway/session targets, and
	// attribution labels; erase it as a first-class tenant store.
	if e.endpointEvents != nil {
		remaining, err := e.endpointEvents.DeleteTenant(ctx, tenantID)
		if err != nil {
			fail("endpoint_events", "delete failed: "+err.Error())
		} else {
			att.Stores = append(att.Stores, StoreResult{Store: "endpoint_events", VerifiedZero: remaining == 0,
				Notes: "remaining=" + fmt.Sprint(remaining)})
			if remaining != 0 {
				att.Complete = false
			}
		}
	} else {
		att.Stores = append(att.Stores, StoreResult{Store: "endpoint_events", VerifiedZero: true, Notes: "store not deployed"})
	}

	// 2) Object store: both the pooled and silo key namespaces.
	if e.objects != nil {
		total := 0
		ok := true
		tenantObjects, err := tenantObjectStores(e.objects, tenantID)
		if err != nil {
			fail("objects", "bind tenant namespace failed: "+err.Error())
			ok = false
		}
		for _, objects := range tenantObjects {
			n, err := objects.DeletePrefix(ctx, "")
			if err != nil {
				fail("objects", "delete tenant namespace failed: "+err.Error())
				ok = false
				break
			}
			total += n
		}
		if ok {
			remaining := 0
			for _, objects := range tenantObjects {
				left, _ := objects.List(ctx, "")
				remaining += len(left)
			}
			verified := remaining == 0
			att.Stores = append(att.Stores, StoreResult{Store: "objects", Deleted: int64(total), VerifiedZero: verified})
			if !verified {
				att.Complete = false
			}
		}
	} else {
		att.Stores = append(att.Stores, StoreResult{Store: "objects", VerifiedZero: true, Notes: "store not deployed"})
	}

	// 3) TSDB series. The prometheus writer automates deletion via the admin
	// API (delete_series + verification, U-027); when that API is disabled it
	// reports ErrAdminAPIDisabled and the documented manual step is recorded
	// honestly, exactly as before.
	switch td := e.tsdbW.(type) {
	case TSDBTenantDeleter:
		n, err := td.DeleteTenant(ctx, tenantID)
		switch {
		case err == nil:
			att.Stores = append(att.Stores, StoreResult{Store: "tsdb", Deleted: int64(n), VerifiedZero: true})
		case errors.Is(err, tsdb.ErrAdminAPIDisabled):
			fail("tsdb", "MANUAL STEP REQUIRED: prometheus admin API disabled — delete series via the admin delete_series API or retention expiry (see docs/runbooks/tenant-offboarding.md)")
		default:
			fail("tsdb", "delete failed: "+err.Error())
		}
	case nil:
		att.Stores = append(att.Stores, StoreResult{Store: "tsdb", VerifiedZero: true, Notes: "store not deployed"})
	default:
		fail("tsdb", "MANUAL STEP REQUIRED: this TSDB mode cannot delete series in place (see docs/runbooks/tenant-offboarding.md)")
	}

	// 3b) ClickHouse path store (U-027): hops + links, count-verified.
	if e.paths != nil {
		deleted, remaining, err := e.paths.DeleteTenant(ctx, tenantID)
		if err != nil {
			fail("paths", "delete failed: "+err.Error())
		} else {
			att.Stores = append(att.Stores, StoreResult{Store: "paths", Deleted: int64(deleted),
				VerifiedZero: remaining == 0, Notes: "remaining=" + fmt.Sprint(remaining)})
			if remaining != 0 {
				att.Complete = false
			}
		}
	} else {
		att.Stores = append(att.Stores, StoreResult{Store: "paths", VerifiedZero: true, Notes: "store not deployed"})
	}

	// 3c) Topology graph — every snapshot/version for the tenant (U-027).
	if e.topo != nil {
		n := e.topo.DeleteTenant(tenantID)
		att.Stores = append(att.Stores, StoreResult{Store: "topology", Deleted: int64(n), VerifiedZero: true})
	} else {
		att.Stores = append(att.Stores, StoreResult{Store: "topology", VerifiedZero: true, Notes: "store not deployed"})
	}

	// 3d) OTLP trace/log store (TENANT-008): externally-ingested traces+logs
	// are tenant PII — erase them too, count-verified like the other planes.
	if e.otel != nil {
		deleted, remaining, err := e.otel.EraseTenant(ctx, tenantID)
		if err != nil {
			fail("otel", "delete failed: "+err.Error())
		} else {
			att.Stores = append(att.Stores, StoreResult{Store: "otel", Deleted: int64(deleted),
				VerifiedZero: remaining == 0, Notes: "remaining=" + fmt.Sprint(remaining)})
			if remaining != 0 {
				att.Complete = false
			}
		}
	} else {
		att.Stores = append(att.Stores, StoreResult{Store: "otel", VerifiedZero: true, Notes: "store not deployed"})
	}

	// 3e) eBPF L7 edge store (TENANT-002): workload-to-workload topology +
	// dest ports + L7 protocols are tenant telemetry — erase them too,
	// count-verified like the other planes. The whole-plane omission here meant
	// the attestation could report Complete:true while probectl_ebpf_edges
	// survived offboarding indefinitely.
	if e.ebpf != nil {
		remaining, err := e.ebpf.DeleteTenant(ctx, tenantID)
		if err != nil {
			fail("ebpf", "delete failed: "+err.Error())
		} else {
			att.Stores = append(att.Stores, StoreResult{Store: "ebpf", VerifiedZero: remaining == 0,
				Notes: "remaining=" + fmt.Sprint(remaining)})
			if remaining != 0 {
				att.Complete = false
			}
		}
	} else {
		att.Stores = append(att.Stores, StoreResult{Store: "ebpf", VerifiedZero: true, Notes: "store not deployed"})
	}

	// 4) Postgres tenant-owned tables — RLS-scoped, silo-routed, multi-pass
	// for intra-tenant FK ordering.
	if e.pool != nil {
		if res, err := e.erasePostgres(ctx, tenantID); err != nil {
			fail("postgres", err.Error())
		} else {
			att.Stores = append(att.Stores, res)
			if !res.VerifiedZero {
				att.Complete = false
			}
		}

		// 5) Provider-plane rows ABOUT the tenant + the tombstone status.
		if res, err := e.eraseProviderRows(ctx, tenantID); err != nil {
			fail("provider_rows", err.Error())
		} else {
			att.Stores = append(att.Stores, res)
			if !res.VerifiedZero {
				att.Complete = false
			}
		}
	} else {
		att.Stores = append(att.Stores, StoreResult{Store: "postgres", VerifiedZero: true, Notes: "store not deployed"})
	}

	// 6) Cryptographic offboarding (S-T6): when a per-tenant keyring is
	// installed, destroy the tenant's keys — every remaining ciphertext
	// (incl. backups within their TTL) becomes permanently unreadable.
	if n, supported, err := tenantcrypto.DestroyKeys(ctx, tenantID); err != nil {
		fail("tenant_keys", "key destruction failed: "+err.Error())
	} else if supported {
		att.Stores = append(att.Stores, StoreResult{Store: "tenant_keys", Deleted: int64(n), VerifiedZero: true,
			Notes: "crypto-shred: key versions destroyed; ciphertexts (incl. in-TTL backups) unreadable"})
	} else {
		att.Stores = append(att.Stores, StoreResult{Store: "tenant_keys", VerifiedZero: true,
			Notes: "no per-tenant keyring installed (byok feature not licensed)"})
	}

	att.FinishedAt = e.now().UTC()
	// COMPLY-002: quantify the backup-coverage window. The live stores are
	// zero NOW; any backup taken before this erasure expires by
	// erased_at + retention, so that instant is when backup coverage is
	// complete. Without a stated retention we leave it unquantified (the
	// note still records the operator's policy).
	if e.backupRetentionDays > 0 {
		att.BackupRetentionDays = e.backupRetentionDays
		deadline := att.FinishedAt.Add(time.Duration(e.backupRetentionDays) * 24 * time.Hour)
		att.BackupErasureDeadline = &deadline
	}
	att.ReportSHA256 = att.hash()

	// The attestation goes on the provider audit chain BEFORE returning —
	// an unrecorded erasure is no erasure (audit-grade, guardrail 7).
	if e.audit != nil {
		if err := e.audit(ctx, actor, "lifecycle.erase", tenantID, map[string]any{
			"slug": slug, "complete": att.Complete, "report_sha256": att.ReportSHA256,
			"stores": len(att.Stores),
		}); err != nil {
			return att, fmt.Errorf("tenantlife: attestation audit append failed: %w", err)
		}
	}
	return att, nil
}

// hash computes the report digest over the canonical JSON minus the hash
// field — through the internal crypto provider (FIPS-swappable, guardrail 3).
func (a Attestation) hash() string {
	cp := a
	cp.ReportSHA256 = ""
	b, _ := json.Marshal(cp)
	return hex.EncodeToString(crypto.Hash(b))
}

// appendOnlyTables are tenant-owned tables the APP ROLE may not delete by
// design (audit_events is append-only for probectl_app — a deliberate
// security property). The erase engine removes them via the PROVIDER role
// instead (an explicit DELETE policy from migration 0029), never by
// weakening the app role.
var appendOnlyTables = map[string]bool{"audit_events": true}

// erasePostgres deletes every tenant-owned row under the tenant's own scope.
// Each table's DELETE runs in ITS OWN transaction: a failed statement aborts
// a Postgres transaction, so per-table isolation is what lets the multi-pass
// loop retry FK orderings without poisoning the rest of the pass.
func (e *Engine) erasePostgres(ctx context.Context, tenantID string) (StoreResult, error) {
	all, err := e.tenantOwnedTables(ctx)
	if err != nil {
		return StoreResult{}, err
	}
	tables := make([]string, 0, len(all))
	for _, t := range all {
		if !appendOnlyTables[t] {
			tables = append(tables, t)
		}
	}
	tctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	var deleted int64
	for pass := 0; pass < maxDeletePasses; pass++ {
		var passDeleted int64
		for _, t := range tables {
			err := tenancy.InTenant(tctx, e.pool, func(ctx context.Context, sc tenancy.Scope) error {
				tag, err := sc.Q.Exec(ctx, `DELETE FROM `+pgIdent(t))
				if err != nil {
					return err
				}
				passDeleted += tag.RowsAffected()
				return nil
			})
			if err != nil {
				continue // FK ordering: a later pass retries this table
			}
		}
		deleted += passDeleted
		if passDeleted == 0 {
			break
		}
	}
	// Append-only tables: erased via the provider role (the explicit S-T5
	// DELETE policy) — the app role stays append-only.
	err = tenancy.InProvider(ctx, e.pool, func(ctx context.Context, q tenancy.Querier) error {
		// TENANT-005: bind the provider verify SELECT policy to THIS tenant.
		// The DELETE policy is USING(true) and is constrained by the explicit
		// WHERE; the GUC scopes the count-verify SELECT below to one tenant so
		// the provider cannot read another tenant's audit rows.
		if _, err := q.Exec(ctx, `SELECT set_config('probectl.tenant_id', $1, true)`, tenantID); err != nil {
			return fmt.Errorf("scope provider erase: %w", err)
		}
		for t := range appendOnlyTables {
			tag, err := q.Exec(ctx, `DELETE FROM `+pgIdent(t)+` WHERE tenant_id = $1`, tenantID)
			if err != nil {
				return fmt.Errorf("delete %s: %w", t, err)
			}
			deleted += tag.RowsAffected()
		}
		return nil
	})
	if err != nil {
		return StoreResult{}, fmt.Errorf("tenantlife: postgres erase (append-only tables): %w", err)
	}
	// Verify: every table reads zero within the tenant's scope (the
	// append-only set is verified through the provider role).
	verified := true
	notes := ""
	verr := tenancy.InTenant(tctx, e.pool, func(ctx context.Context, sc tenancy.Scope) error {
		for _, t := range tables {
			var n int64
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM `+pgIdent(t)).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				verified = false
				notes += fmt.Sprintf("%s:%d ", t, n)
			}
		}
		return nil
	})
	if verr != nil {
		return StoreResult{}, fmt.Errorf("tenantlife: postgres verify: %w", verr)
	}
	if perr := tenancy.InProvider(ctx, e.pool, func(ctx context.Context, q tenancy.Querier) error {
		// TENANT-005: the provider verify SELECT policy is GUC-scoped — set the
		// tenant so the count returns this tenant's append-only rows (and only
		// this tenant's). Without it the scoped policy would read nothing.
		if _, err := q.Exec(ctx, `SELECT set_config('probectl.tenant_id', $1, true)`, tenantID); err != nil {
			return fmt.Errorf("scope provider verify: %w", err)
		}
		for t := range appendOnlyTables {
			var n int64
			if err := q.QueryRow(ctx, `SELECT count(*) FROM `+pgIdent(t)+` WHERE tenant_id = $1`, tenantID).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				verified = false
				notes += fmt.Sprintf("%s:%d ", t, n)
			}
		}
		return nil
	}); perr != nil {
		return StoreResult{}, fmt.Errorf("tenantlife: postgres verify (append-only): %w", perr)
	}
	return StoreResult{Store: "postgres", Deleted: deleted, VerifiedZero: verified,
		Notes: trimNotes(notes, len(all))}, nil
}

// eraseProviderRows removes provider-plane rows about the tenant and marks
// the registry tombstone (status=deleted; the row itself remains so the
// attestation keeps a referent).
func (e *Engine) eraseProviderRows(ctx context.Context, tenantID string) (StoreResult, error) {
	var deleted int64
	verified := true
	err := tenancy.InProvider(ctx, e.pool, func(ctx context.Context, q tenancy.Querier) error {
		for _, t := range tenancy.ProviderOwnedTenantTables() {
			tag, err := q.Exec(ctx, `DELETE FROM `+pgIdent(t)+` WHERE tenant_id = $1`, tenantID)
			if err != nil {
				return fmt.Errorf("delete %s: %w", t, err)
			}
			deleted += tag.RowsAffected()
			var n int64
			if err := q.QueryRow(ctx, `SELECT count(*) FROM `+pgIdent(t)+` WHERE tenant_id = $1`, tenantID).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				verified = false
			}
		}
		_, err := q.Exec(ctx, `UPDATE tenants SET status = 'deleted', updated_at = now() WHERE id = $1`, tenantID)
		return err
	})
	if err != nil {
		return StoreResult{}, fmt.Errorf("tenantlife: provider rows: %w", err)
	}
	return StoreResult{Store: "provider_rows", Deleted: deleted, VerifiedZero: verified,
		Notes: "tenant registry row tombstoned (status=deleted)"}, nil
}

func trimNotes(notes string, tables int) string {
	if notes == "" {
		return fmt.Sprintf("%d tables verified zero", tables)
	}
	return "non-zero: " + notes
}

// pgIdent quotes a table identifier.
func pgIdent(s string) string { return `"` + s + `"` }

// --- Retention ---------------------------------------------------------------

// RetentionPolicy is one tenant's erasure control (nil days = deployment
// default, i.e. the store-level TTL).
type RetentionPolicy struct {
	TenantID                     string `json:"tenant_id,omitempty"`
	FlowRetentionDays            *int   `json:"flow_retention_days"`
	OtelRetentionDays            *int   `json:"otel_retention_days"`
	EBPFRetentionDays            *int   `json:"ebpf_retention_days"`
	PathRetentionDays            *int   `json:"path_retention_days"`
	AuditRetentionDays           *int   `json:"audit_retention_days"`
	AIAnswerRetentionDays        *int   `json:"ai_answer_retention_days"`
	ObjectRetentionDays          *int   `json:"object_retention_days"`
	DerivedIdentityRetentionDays *int   `json:"derived_identity_retention_days"`
	UpdatedBy                    string `json:"updated_by,omitempty"`
}

// RetentionFor reads a tenant's policy within its own scope (RLS).
func (e *Engine) RetentionFor(ctx context.Context, tenantID string) (RetentionPolicy, error) {
	p := RetentionPolicy{TenantID: tenantID}
	tctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	err := tenancy.InTenant(tctx, e.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `
SELECT flow_retention_days, otel_retention_days, ebpf_retention_days,
       path_retention_days, audit_retention_days, ai_answer_retention_days,
       object_retention_days, derived_identity_retention_days, updated_by
  FROM tenant_retention WHERE tenant_id = $1`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			return rows.Scan(&p.FlowRetentionDays, &p.OtelRetentionDays, &p.EBPFRetentionDays,
				&p.PathRetentionDays, &p.AuditRetentionDays, &p.AIAnswerRetentionDays,
				&p.ObjectRetentionDays, &p.DerivedIdentityRetentionDays, &p.UpdatedBy)
		}
		return rows.Err()
	})
	return p, err
}

// SetRetention upserts a tenant's policy and appends exactly one engine-owned,
// tamper-evident audit event in the same RLS-enforced tenant transaction. The
// authoritative tenant must already be present in ctx; policy data can never
// create or replace that scope.
func (e *Engine) SetRetention(ctx context.Context, p RetentionPolicy, actor string) error {
	tenantID, ok := tenancy.FromContext(ctx)
	if !ok {
		return tenancy.ErrNoTenant
	}
	if p.TenantID == "" || tenantID.String() != p.TenantID {
		return fmt.Errorf(
			"tenantlife: retention policy tenant %q does not match caller scope %q",
			p.TenantID,
			tenantID,
		)
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return errors.New("tenantlife: retention policy audit actor is required")
	}
	if len(actor) > maxRetentionAuditActorBytes {
		return fmt.Errorf(
			"tenantlife: retention policy audit actor exceeds %d bytes",
			maxRetentionAuditActorBytes,
		)
	}
	if err := validateRetentionPolicy(p); err != nil {
		return err
	}
	if e.appendRetentionPolicyAudit == nil {
		return errRetentionAuditUnavailable
	}
	return tenancy.InTenant(ctx, e.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := upsertRetentionPolicy(ctx, sc, p); err != nil {
			return err
		}
		if _, err := e.appendRetentionPolicyAudit(
			ctx,
			sc,
			actor,
			retentionPolicyAuditAction,
			p.TenantID,
			retentionPolicyAuditData(p),
		); err != nil {
			return fmt.Errorf("tenantlife: append retention policy audit: %w", err)
		}
		return nil
	})
}

func retentionPolicyAuditData(p RetentionPolicy) map[string]any {
	return map[string]any{
		"flow_retention_days":             p.FlowRetentionDays,
		"otel_retention_days":             p.OtelRetentionDays,
		"ebpf_retention_days":             p.EBPFRetentionDays,
		"path_retention_days":             p.PathRetentionDays,
		"audit_retention_days":            p.AuditRetentionDays,
		"ai_answer_retention_days":        p.AIAnswerRetentionDays,
		"object_retention_days":           p.ObjectRetentionDays,
		"derived_identity_retention_days": p.DerivedIdentityRetentionDays,
	}
}

func upsertRetentionPolicy(ctx context.Context, sc tenancy.Scope, p RetentionPolicy) error {
	if p.TenantID == "" || sc.Tenant.String() != p.TenantID {
		return fmt.Errorf(
			"tenantlife: retention policy tenant %q does not match transaction scope %q",
			p.TenantID,
			sc.Tenant,
		)
	}
	_, err := sc.Q.Exec(ctx, `
			INSERT INTO tenant_retention (
			  tenant_id, flow_retention_days, otel_retention_days, ebpf_retention_days,
			  path_retention_days, audit_retention_days, ai_answer_retention_days,
			  object_retention_days, derived_identity_retention_days, updated_by, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
			ON CONFLICT (tenant_id) DO UPDATE SET
			  flow_retention_days = EXCLUDED.flow_retention_days,
			  otel_retention_days = EXCLUDED.otel_retention_days,
			  ebpf_retention_days = EXCLUDED.ebpf_retention_days,
			  path_retention_days = EXCLUDED.path_retention_days,
			  audit_retention_days = EXCLUDED.audit_retention_days,
			  ai_answer_retention_days = EXCLUDED.ai_answer_retention_days,
			  object_retention_days = EXCLUDED.object_retention_days,
			  derived_identity_retention_days = EXCLUDED.derived_identity_retention_days,
			  updated_by = EXCLUDED.updated_by, updated_at = now()`,
		p.TenantID, p.FlowRetentionDays, p.OtelRetentionDays, p.EBPFRetentionDays,
		p.PathRetentionDays, p.AuditRetentionDays, p.AIAnswerRetentionDays,
		p.ObjectRetentionDays, p.DerivedIdentityRetentionDays, p.UpdatedBy)
	return err
}

func validateRetentionPolicy(p RetentionPolicy) error {
	fields := map[string]*int{
		"flow_retention_days":             p.FlowRetentionDays,
		"otel_retention_days":             p.OtelRetentionDays,
		"ebpf_retention_days":             p.EBPFRetentionDays,
		"path_retention_days":             p.PathRetentionDays,
		"audit_retention_days":            p.AuditRetentionDays,
		"ai_answer_retention_days":        p.AIAnswerRetentionDays,
		"object_retention_days":           p.ObjectRetentionDays,
		"derived_identity_retention_days": p.DerivedIdentityRetentionDays,
	}
	for name, days := range fields {
		if days != nil && *days < 1 {
			return fmt.Errorf("tenantlife: %s must be >= 1 (null = deployment default)", name)
		}
	}
	return nil
}

type retentionSweepPolicy struct {
	tenant string
	days   map[string]int
}

// SweepRetention applies every tenant's retention policy once. Store-level
// TTLs handle high-volume defaults; this enforces per-tenant flow tightening
// and the deployment-owned age clock for derived topology/endpoint identity
// caches. Per-tenant failures are returned after later tenants have had their
// independently scoped sweeps attempted.
func (e *Engine) SweepRetention(ctx context.Context) error {
	if e.pool == nil {
		return nil
	}
	var policies []retentionSweepPolicy
	err := tenancy.InProvider(ctx, e.pool, func(ctx context.Context, q tenancy.Querier) error {
		rows, err := q.Query(ctx, `
				SELECT t.id::text, tr.flow_retention_days, tr.otel_retention_days,
				       tr.ebpf_retention_days, tr.path_retention_days,
				       tr.audit_retention_days, tr.ai_answer_retention_days,
				       tr.object_retention_days, tr.derived_identity_retention_days
				  FROM tenants t
				  LEFT JOIN tenant_retention tr ON tr.tenant_id = t.id
				 WHERE t.status <> 'deleted'
			 ORDER BY t.id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			p := retentionSweepPolicy{days: map[string]int{}}
			var flow, otel, ebpf, path, auditDays, ai, object, derived sql.NullInt64
			if err := rows.Scan(&p.tenant, &flow, &otel, &ebpf, &path, &auditDays, &ai, &object, &derived); err != nil {
				return err
			}
			p.setDays("flows", flow)
			p.setDays("otel", otel)
			p.setDays("ebpf", ebpf)
			p.setDays("path", path)
			p.setDays("audit", auditDays)
			p.setDays("ai_answers", ai)
			p.setDays("objects", object)
			p.setDays("derived_identity", derived)
			policies = append(policies, p)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	return e.sweepRetentionPolicies(ctx, policies)
}

func (e *Engine) sweepRetentionPolicies(ctx context.Context, policies []retentionSweepPolicy) error {
	var sweepErrors []error
	for _, p := range policies {
		err := errors.Join(
			e.sweepSessionRetention(ctx, p),
			e.sweepFlowRetention(ctx, p),
			e.sweepOtelRetention(ctx, p),
			e.sweepEBPFRetention(ctx, p),
			e.sweepPathRetention(ctx, p),
			e.sweepAIAnswerRetention(ctx, p),
			e.receiptDelegatedRetention(ctx, p, "audit", "audit_retention_runner"),
			e.receiptDelegatedRetention(ctx, p, "objects", "object_store_lifecycle"),
			e.pruneDerivedIdentityCaches(ctx, p),
		)
		if err != nil {
			e.log.Warn("retention sweep failed for tenant", "tenant", p.tenant, "error", err.Error())
			sweepErrors = append(sweepErrors, fmt.Errorf("tenant %s retention: %w", p.tenant, err))
		}
	}
	return errors.Join(sweepErrors...)
}

func (e *Engine) sweepSessionRetention(ctx context.Context, p retentionSweepPolicy) error {
	if e.sessions == nil {
		return nil
	}
	cutoff := e.now().Add(-e.sessionReplayTTL)
	return e.runRetentionPrune(
		ctx,
		p.tenant,
		"sessions",
		cutoff,
		0,
		"session_ttl",
		map[string]any{
			"replay_horizon":         e.sessionReplayTTL.String(),
			"replay_horizon_seconds": int64(e.sessionReplayTTL / time.Second),
		},
		func() (int64, error) {
			return e.sessions.PruneInactive(ctx, p.tenant, e.sessionReplayTTL)
		},
	)
}

func (p *retentionSweepPolicy) setDays(name string, days sql.NullInt64) {
	if days.Valid && days.Int64 > 0 {
		p.days[name] = int(days.Int64)
	}
}

func (p retentionSweepPolicy) has(name string) (int, bool) {
	days, ok := p.days[name]
	return days, ok
}

func (e *Engine) derivedIdentityDays(p retentionSweepPolicy) int {
	days := e.derivedIdentityRetentionDays
	if d, ok := p.has("derived_identity"); ok {
		days = d
	}
	if days <= 0 {
		return 0
	}
	if flowDays, ok := p.has("flows"); ok && flowDays < days {
		return flowDays
	}
	return days
}

func (e *Engine) sweepFlowRetention(ctx context.Context, p retentionSweepPolicy) error {
	days, ok := p.has("flows")
	if !ok {
		return nil
	}
	cutoff := e.now().Add(-time.Duration(days) * 24 * time.Hour)
	if e.flows == nil {
		return e.recordRetentionAttempt(ctx, p.tenant, "flows", 0, cutoff, days, "tenant_policy", "not_deployed")
	}
	return e.runRetentionPrune(ctx, p.tenant, "flows", cutoff, days, "tenant_policy", nil,
		func() (int64, error) {
			return 0, e.flows.DeleteTenantBefore(ctx, p.tenant, cutoff)
		})
}

func (e *Engine) sweepOtelRetention(ctx context.Context, p retentionSweepPolicy) error {
	days, ok := p.has("otel")
	if !ok {
		return nil
	}
	cutoff := e.now().Add(-time.Duration(days) * 24 * time.Hour)
	pruner, capable := e.otel.(OtelRetentionPruner)
	if e.otel == nil {
		return e.recordRetentionAttempt(ctx, p.tenant, "otel", 0, cutoff, days, "tenant_policy", "not_deployed")
	}
	if !capable {
		return e.recordRetentionAttempt(ctx, p.tenant, "otel", 0, cutoff, days, "tenant_policy", "not_capable")
	}
	return e.runRetentionPrune(ctx, p.tenant, "otel", cutoff, days, "tenant_policy", nil,
		func() (int64, error) {
			deleted, err := pruner.PruneTenantBefore(ctx, p.tenant, cutoff)
			return int64(deleted), err
		})
}

func (e *Engine) sweepEBPFRetention(ctx context.Context, p retentionSweepPolicy) error {
	days, ok := p.has("ebpf")
	if !ok {
		return nil
	}
	cutoff := e.now().Add(-time.Duration(days) * 24 * time.Hour)
	pruner, capable := e.ebpf.(EBPFRetentionPruner)
	if e.ebpf == nil {
		return e.recordRetentionAttempt(ctx, p.tenant, "ebpf", 0, cutoff, days, "tenant_policy", "not_deployed")
	}
	if !capable {
		return e.recordRetentionAttempt(ctx, p.tenant, "ebpf", 0, cutoff, days, "tenant_policy", "not_capable")
	}
	return e.runRetentionPrune(ctx, p.tenant, "ebpf", cutoff, days, "tenant_policy", nil,
		func() (int64, error) {
			deleted, err := pruner.PruneTenantBefore(ctx, p.tenant, cutoff)
			return int64(deleted), err
		})
}

func (e *Engine) sweepPathRetention(ctx context.Context, p retentionSweepPolicy) error {
	days, ok := p.has("path")
	if !ok {
		return nil
	}
	cutoff := e.now().Add(-time.Duration(days) * 24 * time.Hour)
	pruner, capable := e.paths.(PathRetentionPruner)
	if e.paths == nil {
		return e.recordRetentionAttempt(ctx, p.tenant, "path", 0, cutoff, days, "tenant_policy", "not_deployed")
	}
	if !capable {
		return e.recordRetentionAttempt(ctx, p.tenant, "path", 0, cutoff, days, "tenant_policy", "not_capable")
	}
	return e.runRetentionPrune(ctx, p.tenant, "path", cutoff, days, "tenant_policy", nil,
		func() (int64, error) {
			deleted, err := pruner.PruneTenantBefore(ctx, p.tenant, cutoff)
			return int64(deleted), err
		})
}

func (e *Engine) sweepAIAnswerRetention(ctx context.Context, p retentionSweepPolicy) error {
	days, ok := p.has("ai_answers")
	if !ok {
		return nil
	}
	cutoff := e.now().Add(-time.Duration(days) * 24 * time.Hour)
	if e.pool == nil && e.aiAnswerRetention == nil {
		return e.recordRetentionAttempt(ctx, p.tenant, "ai_answers", 0, cutoff, days, "tenant_policy", "not_deployed")
	}
	return e.runRetentionPrune(ctx, p.tenant, "ai_answers", cutoff, days, "tenant_policy", nil,
		func() (int64, error) {
			if e.aiAnswerRetention != nil {
				return e.aiAnswerRetention(ctx, p.tenant, time.Duration(days)*24*time.Hour)
			}
			tctx := tenancy.WithTenant(ctx, tenancy.ID(p.tenant))
			var deleted int64
			err := tenancy.InTenant(tctx, e.pool, func(ctx context.Context, sc tenancy.Scope) error {
				var err error
				deleted, err = (store.AIAnswers{}).PruneOlderThan(ctx, sc, time.Duration(days)*24*time.Hour)
				return err
			})
			return deleted, err
		})
}

func (e *Engine) receiptDelegatedRetention(ctx context.Context, p retentionSweepPolicy, store, source string) error {
	days, ok := p.has(store)
	if !ok {
		return nil
	}
	cutoff := e.now().Add(-time.Duration(days) * 24 * time.Hour)
	return e.recordRetentionAttempt(ctx, p.tenant, store, 0, cutoff, days, source, "delegated")
}

func (e *Engine) pruneDerivedIdentityCaches(ctx context.Context, p retentionSweepPolicy) error {
	days := e.derivedIdentityDays(p)
	if days <= 0 {
		return nil
	}
	cutoff := e.now().Add(-time.Duration(days) * 24 * time.Hour)
	var pruneErrors []error
	if e.topoRetention != nil {
		pruneErrors = append(pruneErrors, e.runRetentionPrune(
			ctx, p.tenant, "topology", cutoff, days, "derived_identity_cache", nil,
			func() (int64, error) {
				return int64(e.topoRetention.PruneTenantBefore(p.tenant, cutoff)), nil
			},
		))
	}
	if e.endpointRetention != nil {
		pruneErrors = append(pruneErrors, e.runRetentionPrune(
			ctx, p.tenant, "endpoint", cutoff, days, "derived_identity_cache", nil,
			func() (int64, error) {
				return int64(e.endpointRetention.PruneTenantBefore(p.tenant, cutoff)), nil
			},
		))
	}
	if e.endpointEvents != nil {
		pruneErrors = append(pruneErrors, e.runRetentionPrune(
			ctx, p.tenant, "endpoint_events", cutoff, days, "tenant_policy", nil,
			func() (int64, error) {
				deleted, err := e.endpointEvents.PruneTenantBefore(ctx, p.tenant, cutoff)
				return int64(deleted), err
			},
		))
	}
	return errors.Join(pruneErrors...)
}

func (e *Engine) runRetentionPrune(
	ctx context.Context,
	tenant, store string,
	cutoff time.Time,
	days int,
	source string,
	extra map[string]any,
	prune func() (int64, error),
) error {
	attemptID, err := crypto.UUIDv4()
	if err != nil {
		return fmt.Errorf("tenantlife: mint %s retention attempt id: %w", store, err)
	}
	if err := e.recordRetentionEvent(
		ctx, false, tenant, store, attemptID, cutoff, days, source, "intent", nil, extra,
	); err != nil {
		return err
	}

	deleted, pruneErr := prune()
	if pruneErr != nil {
		failureExtra := make(map[string]any, len(extra)+2)
		for key, value := range extra {
			failureExtra[key] = value
		}
		failureExtra["failure"] = "store_prune_failed"
		failureExtra["deleted_count_known"] = false
		auditErr := e.recordRetentionEvent(
			ctx, true, tenant, store, attemptID, cutoff, days, source, "failed", nil, failureExtra,
		)
		return errors.Join(
			fmt.Errorf("tenantlife: %s retention prune: %w", store, pruneErr),
			auditErr,
		)
	}

	return e.recordRetentionEvent(
		ctx, true, tenant, store, attemptID, cutoff, days, source, "enforced", &deleted, extra,
	)
}

func (e *Engine) recordRetentionAttempt(
	ctx context.Context,
	tenant, store string,
	deleted int64,
	cutoff time.Time,
	days int,
	source, status string,
) error {
	return e.recordRetentionEvent(ctx, true, tenant, store, "", cutoff, days, source, status, &deleted, nil)
}

func (e *Engine) recordRetentionEvent(
	ctx context.Context,
	terminal bool,
	tenant, store, attemptID string,
	cutoff time.Time,
	days int,
	source, status string,
	deleted *int64,
	extra map[string]any,
) error {
	if e.audit == nil {
		return errRetentionAuditUnavailable
	}
	data := map[string]any{
		"store":  store,
		"cutoff": cutoff.UTC().Format(time.RFC3339Nano),
		"source": source,
		"status": status,
	}
	if attemptID != "" {
		data["attempt_id"] = attemptID
	}
	if days > 0 {
		data["retention_days"] = days
	}
	if deleted != nil {
		data["deleted"] = *deleted
	}
	for key, value := range extra {
		data[key] = value
	}

	auditParent := ctx
	if terminal {
		// A prune may consume or cancel the request context. Its outcome still
		// needs a bounded durable receipt, so preserve values while giving the
		// append its own finite forensic window.
		auditParent = context.WithoutCancel(ctx)
	}
	auditCtx, cancel := context.WithTimeout(auditParent, retentionAuditTimeout)
	defer cancel()
	if err := e.audit(auditCtx, "probectl-retention", "lifecycle.retention_sweep", tenant, data); err != nil {
		return fmt.Errorf("tenantlife: %s retention %s audit: %w", store, status, err)
	}
	return nil
}

// RunRetention sweeps on the interval until ctx ends.
func (e *Engine) RunRetention(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := e.SweepRetention(ctx); err != nil {
				e.log.Warn("retention sweep failed", "error", err.Error())
			}
		}
	}
}
