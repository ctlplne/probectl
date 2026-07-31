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

	"github.com/jackc/pgx/v5"
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
	irLifecycleReceiptTimeout   = 5 * time.Second
	retentionPolicyAuditAction  = "lifecycle.retention_set"
	maxRetentionAuditActorBytes = 256
	auditRetentionDay           = 24 * time.Hour
	maxAuditRetentionDays       = int64((1<<63 - 1) / int64(auditRetentionDay))
)

var errRetentionAuditUnavailable = errors.New("tenantlife: retention audit sink is unavailable")

// ErrAuditRetentionExceedsMaximum means a tenant tried to retain local audit
// rows longer than the deployment allows. HTTP surfaces map this domain error
// to client validation; direct engine callers fail before either policy or
// audit state is written.
var ErrAuditRetentionExceedsMaximum = errors.New("tenantlife: audit retention exceeds deployment maximum")

type retentionPolicyAuditAppender func(
	context.Context,
	tenancy.Scope,
	string,
	string,
	string,
	map[string]any,
) (audit.Event, error)

type subjectErasureAppender func(
	context.Context,
	tenancy.Scope,
	string,
	string,
	string,
) (audit.Event, error)

type providerAuditTxAppender func(
	context.Context,
	tenancy.Querier,
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

// IRAttributionLifecycle is the tenant-erasure seam for the distinct
// investigation-response attribution key domain. Plan must durably record the
// intent and prove that the encrypted attribution sidecar is fully covered
// before returning a plan ID. Execute performs the tenant-scoped crypto-shred
// and records its successful completion. RecordFailure records a terminal
// receipt when an existing erasure store fails after Plan has succeeded.
// If Plan fails after recording its intent, Plan also owns that attempt's
// terminal failure receipt because tenantlife cannot know how far it got.
//
// Only primitive strings cross this boundary so tenantlife does not depend on
// the audit sidecar implementation (which itself composes lifecycle storage).
type IRAttributionLifecycle interface {
	Plan(ctx context.Context, tenantID, actor string) (planID string, err error)
	Execute(ctx context.Context, tenantID, actor, planID string) error
	RecordFailure(ctx context.Context, tenantID, actor, planID, failure string) error
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
	// appendSubjectErasure is always audit.RecordSubjectErasure in production.
	// The unexported seam lets integration tests force an alias-marker failure
	// and prove every identity deletion and earlier alias marker rolls back in
	// the same tenant transaction.
	appendSubjectErasure subjectErasureAppender
	// appendProviderAuditTx is always audit.ProviderAppendTx in production.
	// Full-erasure fence and tombstone mutations use the caller's transaction
	// so audit failure rolls the provider mutation back.
	appendProviderAuditTx providerAuditTxAppender
	// irAttribution is optional until the encrypted attribution sidecar is
	// composed at the control-plane seam. Nil preserves the core erasure
	// behavior; when present it fails closed before any deletion if planning
	// or coverage verification fails.
	irAttribution IRAttributionLifecycle

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
	// auditRetentionMaximum is the deployment's local audit window. Positive
	// values are a hard upper bound for tenant policy; zero is keep-forever
	// and therefore permits any finite, representable tenant tightening.
	auditRetentionMaximum time.Duration
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
		appendRetentionPolicyAudit: audit.TenantAppend,
		appendSubjectErasure:       audit.RecordSubjectErasure,
		appendProviderAuditTx:      audit.ProviderAppendTx}
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

// WithAuditRetentionMaximum sets the deployment-level upper bound for tenant
// audit retention. A non-positive maximum is the keep-forever default: finite
// tenant values still tighten it and are enforced by the dedicated runner.
func (e *Engine) WithAuditRetentionMaximum(window time.Duration) *Engine {
	e.auditRetentionMaximum = window
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

// WithIRAttributionLifecycle attaches the encrypted IR-attribution key
// lifecycle. Planning runs before any tenant deletion; execution runs only
// after every existing store and tenant keyring reports successful erasure.
func (e *Engine) WithIRAttributionLifecycle(lifecycle IRAttributionLifecycle) *Engine {
	e.irAttribution = lifecycle
	return e
}

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
// route into their own schema, where encrypted IR evidence remains after the
// distinct attribution key is crypto-shredded.
func (e *Engine) Erase(ctx context.Context, tenantID, slug, actor string) (Attestation, error) {
	att := Attestation{
		FormatVersion: 1, TenantID: tenantID, TenantSlug: slug, Actor: actor,
		StartedAt: e.now().UTC(), BackupPolicy: e.backupNote, Complete: true,
	}
	irPlanID, err := e.prepareErasure(ctx, tenantID, actor)
	if err != nil {
		att.Complete = false
		return att, err
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
				left, err := objects.List(ctx, "")
				if err != nil {
					fail("objects", "verify tenant namespace failed: "+err.Error())
					ok = false
					break
				}
				remaining += len(left)
			}
			if ok {
				verified := remaining == 0
				att.Stores = append(att.Stores, StoreResult{Store: "objects", Deleted: int64(total), VerifiedZero: verified})
				if !verified {
					att.Complete = false
				}
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

	irLifecycleErr := e.finalizeIRAttribution(
		ctx,
		tenantID,
		actor,
		irPlanID,
		&att,
	)

	// Provider-owned rows, the registry tombstone, and the successful
	// attestation append commit atomically only after every other store and key
	// domain succeeds. A failed finalization rolls all three back and leaves
	// the tenant offboarding behind the durable fence for an idempotent retry.
	if e.pool != nil && att.Complete && irLifecycleErr == nil {
		finalized, err := e.finalizeSuccessfulErasure(
			ctx,
			tenantID,
			slug,
			actor,
			att,
		)
		if err == nil {
			return finalized, nil
		}
		fail("provider_finalize", err.Error())
		irLifecycleErr = errors.Join(irLifecycleErr, err)
	} else if e.pool != nil {
		fail("provider_rows", "not attempted: tenant erasure incomplete")
		fail("tenant_registry", "not attempted: tenant erasure incomplete")
	}

	e.finishAttestation(&att)
	auditErr := e.appendLifecycleAudit(ctx, actor, tenantID, slug, att)
	return att, errors.Join(irLifecycleErr, auditErr)
}

func (e *Engine) prepareErasure(
	ctx context.Context,
	tenantID, actor string,
) (string, error) {
	if e.pool != nil && e.irAttribution == nil {
		return "", errors.New(
			"tenantlife: database-backed erasure requires the IR crypto-shred lifecycle",
		)
	}
	if e.pool != nil {
		if err := e.fenceTenantAuditWrites(ctx, tenantID, actor); err != nil {
			return "", fmt.Errorf(
				"tenantlife: establish tenant audit write fence: %w",
				err,
			)
		}
	}
	planID := ""
	if e.irAttribution != nil {
		var err error
		planID, err = e.irAttribution.Plan(ctx, tenantID, actor)
		if err != nil {
			return "", fmt.Errorf("tenantlife: plan IR attribution crypto-shred: %w", err)
		}
		if strings.TrimSpace(planID) == "" {
			return "", errors.New("tenantlife: plan IR attribution crypto-shred: empty plan id")
		}
	}
	return planID, nil
}

func (e *Engine) fenceTenantAuditWrites(
	ctx context.Context,
	tenantID, actor string,
) error {
	return tenancy.InProvider(ctx, e.pool, func(ctx context.Context, q tenancy.Querier) error {
		var canonicalTenantID string
		if err := q.QueryRow(
			ctx,
			`SELECT $1::uuid::text`,
			tenantID,
		).Scan(&canonicalTenantID); err != nil {
			return fmt.Errorf("canonicalize tenant id: %w", err)
		}
		if err := audit.LockTenantStream(ctx, q, canonicalTenantID); err != nil {
			return fmt.Errorf("lock tenant audit stream: %w", err)
		}
		var alreadyFenced bool
		var previousStatus string
		if err := q.QueryRow(
			ctx,
			`SELECT status, audit_write_fenced_at IS NOT NULL
			   FROM public.tenants
			  WHERE id = $1::uuid
			  FOR UPDATE`,
			canonicalTenantID,
		).Scan(&previousStatus, &alreadyFenced); err != nil {
			return fmt.Errorf("lock tenant registry row: %w", err)
		}
		if previousStatus == "deleted" {
			return errors.New("tenant is deleted and not eligible for erasure")
		}
		if alreadyFenced && previousStatus != "offboarding" {
			return fmt.Errorf(
				"tenant audit fence has invalid status %q",
				previousStatus,
			)
		}
		tag, err := q.Exec(
			ctx,
			`UPDATE public.tenants
			    SET status = 'offboarding',
			        audit_write_fenced_at =
			            COALESCE(audit_write_fenced_at, now()),
			        updated_at = now()
			  WHERE id = $1::uuid
			    AND status IN ('active', 'suspended', 'offboarding')`,
			canonicalTenantID,
		)
		if err != nil {
			return fmt.Errorf("transition tenant to offboarding: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return errors.New("tenant is absent, deleted, or not eligible for erasure")
		}
		appendTx := e.appendProviderAuditTx
		if appendTx == nil {
			appendTx = audit.ProviderAppendTx
		}
		if _, err := appendTx(
			ctx,
			q,
			actor,
			"lifecycle.erase_fence",
			canonicalTenantID,
			map[string]any{
				"already_fenced":  alreadyFenced,
				"previous_status": previousStatus,
			},
		); err != nil {
			return fmt.Errorf("append tenant audit-fence event: %w", err)
		}
		return nil
	})
}

func (e *Engine) finalizeIRAttribution(
	ctx context.Context,
	tenantID, actor, planID string,
	att *Attestation,
) error {
	if e.irAttribution == nil {
		return nil
	}
	if !att.Complete {
		return e.recordIRAttributionFailure(
			ctx,
			tenantID,
			actor,
			planID,
			"store_erasure_incomplete",
		)
	}
	if err := e.irAttribution.Execute(ctx, tenantID, actor, planID); err != nil {
		att.Stores = append(att.Stores, StoreResult{
			Store: "ir_attribution_keys", Deleted: -1,
			Notes: "crypto-shred failed",
		})
		att.Complete = false
		return errors.Join(
			fmt.Errorf("tenantlife: execute IR attribution crypto-shred: %w", err),
			e.recordIRAttributionFailure(
				ctx,
				tenantID,
				actor,
				planID,
				"crypto_shred_failed",
			),
		)
	}
	att.Stores = append(att.Stores, StoreResult{
		Store:        "ir_attribution_keys",
		VerifiedZero: true,
		Notes:        "crypto-shred complete; encrypted attribution evidence retained",
	})
	return nil
}

func (e *Engine) recordIRAttributionFailure(
	ctx context.Context,
	tenantID, actor, planID, failure string,
) error {
	// A store or keyring may return after consuming/cancelling the caller's
	// request context. Preserve values but give the forensic failure receipt a
	// separate, finite window.
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), irLifecycleReceiptTimeout)
	defer cancel()
	if err := e.irAttribution.RecordFailure(auditCtx, tenantID, actor, planID, failure); err != nil {
		return fmt.Errorf("tenantlife: record IR attribution crypto-shred failure: %w", err)
	}
	return nil
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
// design. Raw audit events and their hash-only subject-erasure projection are
// durable evidence; the erase engine removes them via the routed PROVIDER
// maintenance role only during verified full-tenant erasure.
var appendOnlyTables = map[string]bool{
	"audit_events":           true,
	"audit_subject_erasures": true,
}

// retainedCryptoShreddedEvidenceTables remain as encrypted, tamper-evident
// proof after tenant deletion. Their distinct tenant IR key is destroyed by
// IRAttributionLifecycle; deleting these rows would erase the proof itself and
// break the WORM companion chain.
var retainedCryptoShreddedEvidenceTables = map[string]bool{
	"ir_attribution_records": true,
	"ir_attribution_heads":   true,
}

func appRoleEraseTables(all []string) []string {
	tables := make([]string, 0, len(all))
	for _, table := range all {
		if !appendOnlyTables[table] && !retainedCryptoShreddedEvidenceTables[table] {
			tables = append(tables, table)
		}
	}
	return tables
}

// erasePostgres deletes every tenant-owned row under the tenant's own scope.
// Each table's DELETE runs in ITS OWN transaction: a failed statement aborts
// a Postgres transaction, so per-table isolation is what lets the multi-pass
// loop retry FK orderings without poisoning the rest of the pass.
func (e *Engine) erasePostgres(ctx context.Context, tenantID string) (StoreResult, error) {
	all, err := e.tenantOwnedTables(ctx)
	if err != nil {
		return StoreResult{}, err
	}
	tables := appRoleEraseTables(all)
	retainedEvidenceTables := 0
	for _, table := range all {
		if retainedCryptoShreddedEvidenceTables[table] {
			retainedEvidenceTables++
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
	// Verify ordinary tables before touching append-only evidence. A retryable
	// ordinary-table failure must not erase the audit trail or tombstone the
	// tenant.
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
	if !verified {
		notes = trimNotes(notes, len(tables))
		if retainedEvidenceTables > 0 {
			notes += fmt.Sprintf("; %d encrypted IR evidence tables retained for crypto-shred", retainedEvidenceTables)
		}
		return StoreResult{
			Store: "postgres", Deleted: deleted, VerifiedZero: false, Notes: notes,
		}, nil
	}

	// Append-only evidence is deleted and exactly verified in ONE routed
	// provider-maintenance transaction while holding the canonical audit lock.
	// Migration 0083 makes status=offboarding a storage-layer INSERT fence, so
	// the barrier remains in force after this transaction and through the later
	// provider-row tombstone.
	if perr := tenancy.InTenantProviderMaintenance(tctx, e.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, tenantID); err != nil {
			return fmt.Errorf("lock tenant audit stream: %w", err)
		}
		var fenced bool
		var status string
		if err := sc.Q.QueryRow(
			ctx,
			`SELECT status, audit_write_fenced_at IS NOT NULL
			   FROM public.tenants
			  WHERE id = $1::uuid
			  FOR KEY SHARE`,
			tenantID,
		).Scan(&status, &fenced); err != nil {
			return fmt.Errorf("read tenant write-fence status: %w", err)
		}
		if !fenced || status == "deleted" {
			return fmt.Errorf(
				"tenant audit write fence invalid: status=%q fenced=%t",
				status,
				fenced,
			)
		}
		for t := range appendOnlyTables {
			tag, err := sc.Q.Exec(
				ctx,
				`DELETE FROM `+pgIdent(t)+` WHERE tenant_id = $1::uuid`,
				tenantID,
			)
			if err != nil {
				return fmt.Errorf("delete %s: %w", t, err)
			}
			deleted += tag.RowsAffected()
		}
		for t := range appendOnlyTables {
			var n int64
			if err := sc.Q.QueryRow(
				ctx,
				`SELECT count(*) FROM `+pgIdent(t)+` WHERE tenant_id = $1::uuid`,
				tenantID,
			).Scan(&n); err != nil {
				return fmt.Errorf("verify %s: %w", t, err)
			}
			if n != 0 {
				return fmt.Errorf("verify %s: %d rows remain", t, n)
			}
		}
		return nil
	}); perr != nil {
		return StoreResult{}, fmt.Errorf("tenantlife: postgres erase and verify (append-only): %w", perr)
	}
	notes = trimNotes(notes, len(tables)+len(appendOnlyTables))
	if retainedEvidenceTables > 0 {
		notes += fmt.Sprintf("; %d encrypted IR evidence tables retained for crypto-shred", retainedEvidenceTables)
	}
	return StoreResult{Store: "postgres", Deleted: deleted, VerifiedZero: verified, Notes: notes}, nil
}

func (e *Engine) finalizeSuccessfulErasure(
	ctx context.Context,
	tenantID, slug, actor string,
	att Attestation,
) (Attestation, error) {
	finalized := att
	tctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	err := tenancy.InTenantProviderMaintenance(
		tctx,
		e.pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			if err := audit.LockTenantStream(ctx, sc.Q, tenantID); err != nil {
				return fmt.Errorf("lock tenant audit stream: %w", err)
			}
			var fenced bool
			var status string
			if err := sc.Q.QueryRow(
				ctx,
				`SELECT status, audit_write_fenced_at IS NOT NULL
				   FROM public.tenants
				  WHERE id = $1::uuid
				  FOR UPDATE`,
				tenantID,
			).Scan(&status, &fenced); err != nil {
				return fmt.Errorf("read tenant registry: %w", err)
			}
			if !fenced || status != "offboarding" {
				return fmt.Errorf(
					"tenant finalization fence invalid: status=%q fenced=%t",
					status,
					fenced,
				)
			}
			for table := range appendOnlyTables {
				var remaining int64
				if err := sc.Q.QueryRow(
					ctx,
					`SELECT count(*) FROM `+pgIdent(table)+
						` WHERE tenant_id = $1::uuid`,
					tenantID,
				).Scan(&remaining); err != nil {
					return fmt.Errorf("verify %s before tombstone: %w", table, err)
				}
				if remaining != 0 {
					return fmt.Errorf(
						"refuse tombstone: %s has %d tenant rows",
						table,
						remaining,
					)
				}
			}
			providerResult, err := eraseProviderRowsTx(
				ctx,
				sc.Q,
				tenantID,
			)
			if err != nil {
				return err
			}
			finalized.Stores = append(
				finalized.Stores,
				providerResult,
				StoreResult{
					Store:        "tenant_registry",
					VerifiedZero: true,
					Notes:        "tenant registry row tombstoned (status=deleted)",
				},
			)
			e.finishAttestation(&finalized)
			tag, err := sc.Q.Exec(
				ctx,
				`UPDATE public.tenants
				    SET status = 'deleted',
				        updated_at = now()
				  WHERE id = $1::uuid
				    AND status = 'offboarding'
				    AND audit_write_fenced_at IS NOT NULL`,
				tenantID,
			)
			if err != nil {
				return fmt.Errorf("mark tenant deleted: %w", err)
			}
			if tag.RowsAffected() != 1 {
				return errors.New("mark tenant deleted: registry row missing")
			}
			appendTx := e.appendProviderAuditTx
			if appendTx == nil {
				appendTx = audit.ProviderAppendTx
			}
			if _, err := appendTx(
				ctx,
				sc.Q,
				actor,
				"lifecycle.erase",
				tenantID,
				lifecycleAuditData(slug, finalized),
			); err != nil {
				return fmt.Errorf("append successful erasure attestation: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		return att, fmt.Errorf("tenantlife: finalize provider erasure: %w", err)
	}
	return finalized, nil
}

func eraseProviderRowsTx(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
) (StoreResult, error) {
	var deleted int64
	for _, table := range tenancy.ProviderOwnedTenantTables() {
		qualified := `public.` + pgIdent(table)
		tag, err := q.Exec(
			ctx,
			`DELETE FROM `+qualified+` WHERE tenant_id = $1::uuid`,
			tenantID,
		)
		if err != nil {
			return StoreResult{}, fmt.Errorf("delete %s: %w", table, err)
		}
		deleted += tag.RowsAffected()
		var remaining int64
		if err := q.QueryRow(
			ctx,
			`SELECT count(*) FROM `+qualified+` WHERE tenant_id = $1::uuid`,
			tenantID,
		).Scan(&remaining); err != nil {
			return StoreResult{}, fmt.Errorf("verify %s: %w", table, err)
		}
		if remaining != 0 {
			return StoreResult{}, fmt.Errorf(
				"verify %s: %d rows remain",
				table,
				remaining,
			)
		}
	}
	return StoreResult{
		Store:        "provider_rows",
		Deleted:      deleted,
		VerifiedZero: true,
		Notes:        "provider-owned tenant rows verified zero",
	}, nil
}

func (e *Engine) finishAttestation(att *Attestation) {
	att.FinishedAt = e.now().UTC()
	// COMPLY-002: quantify the backup-coverage window. The live stores are
	// zero NOW; any backup taken before this erasure expires by
	// erased_at + retention, so that instant is when backup coverage is
	// complete. Without a stated retention we leave it unquantified.
	if e.backupRetentionDays > 0 {
		att.BackupRetentionDays = e.backupRetentionDays
		deadline := att.FinishedAt.Add(
			time.Duration(e.backupRetentionDays) * 24 * time.Hour,
		)
		att.BackupErasureDeadline = &deadline
	}
	att.ReportSHA256 = att.hash()
}

func lifecycleAuditData(slug string, att Attestation) map[string]any {
	return map[string]any{
		"slug":          slug,
		"complete":      att.Complete,
		"report_sha256": att.ReportSHA256,
		"stores":        len(att.Stores),
	}
}

func (e *Engine) appendLifecycleAudit(
	ctx context.Context,
	actor, tenantID, slug string,
	att Attestation,
) error {
	var err error
	switch {
	case e.audit != nil:
		err = e.audit(
			ctx,
			actor,
			"lifecycle.erase",
			tenantID,
			lifecycleAuditData(slug, att),
		)
	case e.pool != nil:
		_, err = audit.ProviderAppend(
			ctx,
			e.pool,
			actor,
			"lifecycle.erase",
			tenantID,
			lifecycleAuditData(slug, att),
		)
	}
	if err != nil {
		return fmt.Errorf("tenantlife: attestation audit append failed: %w", err)
	}
	return nil
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

// ProviderAuditRetentionWindowFor returns one tenant's requested finite audit
// window from the provider-owned policy table. It is intentionally a provider
// maintenance read rather than RetentionFor's caller-scoped read: the scheduler
// enumerates tenants across the deployment, while the restricted provider role
// remains unable to read any tenant telemetry or audit payloads.
//
// Zero means "inherit the deployment default". The audit runner applies the
// deployment bound again at the deletion boundary, so stale rows written under
// an older configuration cannot loosen a newly tightened maximum.
func (e *Engine) ProviderAuditRetentionWindowFor(ctx context.Context, tenantID string) (time.Duration, error) {
	var days *int
	err := tenancy.InProvider(ctx, e.pool, func(ctx context.Context, q tenancy.Querier) error {
		return q.QueryRow(
			ctx,
			`SELECT audit_retention_days
			   FROM public.tenant_retention
			  WHERE tenant_id = $1`,
			tenantID,
		).Scan(&days)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if days == nil {
		return 0, nil
	}
	return storedAuditRetentionWindow(*days, e.auditRetentionMaximum)
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
	if err := validateRetentionPolicy(p, e.auditRetentionMaximum); err != nil {
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

func validateRetentionPolicy(p RetentionPolicy, auditMaximum time.Duration) error {
	if p.AuditRetentionDays != nil {
		requested, err := auditRetentionWindow(*p.AuditRetentionDays)
		if err != nil {
			return err
		}
		if auditMaximum > 0 && requested > auditMaximum {
			return fmt.Errorf(
				"%w: requested %d days, deployment maximum %s",
				ErrAuditRetentionExceedsMaximum,
				*p.AuditRetentionDays,
				auditMaximum,
			)
		}
	}
	fields := map[string]*int{
		"flow_retention_days":             p.FlowRetentionDays,
		"otel_retention_days":             p.OtelRetentionDays,
		"ebpf_retention_days":             p.EBPFRetentionDays,
		"path_retention_days":             p.PathRetentionDays,
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

func auditRetentionWindow(days int) (time.Duration, error) {
	if days < 1 {
		return 0, errors.New("tenantlife: audit_retention_days must be >= 1 (null = deployment default)")
	}
	if int64(days) > maxAuditRetentionDays {
		return 0, fmt.Errorf(
			"%w: requested %d days exceeds the supported duration",
			ErrAuditRetentionExceedsMaximum,
			days,
		)
	}
	return time.Duration(days) * auditRetentionDay, nil
}

func storedAuditRetentionWindow(days int, deploymentMaximum time.Duration) (time.Duration, error) {
	// Existing rows can outlive a configuration change or predate the write
	// bound. Legacy non-positive rows inherit; clamp oversized positive rows
	// before multiplying so neither case can disable a finite deployment run.
	if days <= 0 {
		return 0, nil
	}
	if deploymentMaximum > 0 &&
		int64(days) > int64(deploymentMaximum/auditRetentionDay) {
		return deploymentMaximum, nil
	}
	return auditRetentionWindow(days)
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
