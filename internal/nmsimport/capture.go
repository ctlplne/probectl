// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"errors"
	"io"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// ErrPlanUnavailable hides whether a plan belongs to another tenant/context,
// has expired, or cannot accept capture pages. A handler maps it to one 404.
var ErrPlanUnavailable = errors.New("nmsimport: capture plan unavailable")

// ErrCaptureAuditUnavailable refuses a mutation that cannot append its tenant
// audit event in the same transaction. A handler must inject the actor-bound
// audit writer; the source payload cannot supply or suppress it.
var ErrCaptureAuditUnavailable = errors.New("nmsimport: capture audit unavailable")

// CaptureAudit appends an actor-bound tenant audit event through the current
// tenant transaction; returning an error rolls back the corresponding write.
type CaptureAudit func(context.Context, tenancy.Scope, string, string, map[string]any) error

// CaptureStore records only normalized, redacted source pages. The caller must
// authorize the operator's selected routing context before invoking it; the
// source payload cannot select a tenant, context, credential or destination.
type CaptureStore struct {
	pool  *pgxpool.Pool
	audit CaptureAudit
}

func NewCaptureStore(pool *pgxpool.Pool, audit CaptureAudit) CaptureStore {
	return CaptureStore{pool: pool, audit: audit}
}

type captureMeta struct {
	source        Kind
	instance      string
	generation    string
	configVersion int64
	policy        int
	state         string
	snapshotHash  string
	rowCount      int64
	expires       time.Time
}

const capturePolicyVersion = 1

// This is a transaction/page budget, not a cap on an import's total rows.
// Streaming export adapters split larger inventories into more pages.
const maxCaptureRowsPerPage = 10_000

// StartPlan binds a source instance and one capture plan to the operator's
// selected routing context. This does not read the source or import a device.
// A handler must check the actor's import permission before calling it.
func (s CaptureStore) StartPlan(ctx context.Context, contextID string,
	source Kind, instanceRef, generationHash string) (string, error) {
	if s.pool == nil || s.audit == nil {
		return "", ErrCaptureAuditUnavailable
	}
	contextUUID, err := uuid.Parse(contextID)
	if err != nil || contextUUID == uuid.Nil || !knownSource(source) ||
		!safeInstanceRef(instanceRef) || len(generationHash) != 64 || !lowerHex(generationHash) {
		return "", ErrInvalidPage
	}
	contextID = contextUUID.String()
	sourceID, err := captureUUID()
	if err != nil {
		return "", err
	}
	planID, err := captureUUID()
	if err != nil {
		return "", err
	}
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		tenantUUID, err := uuid.Parse(sc.Tenant.String())
		if err != nil || tenantUUID == uuid.Nil {
			return ErrPlanUnavailable
		}
		tenantID := tenantUUID.String()
		digest, err := newPlanDigest(tenantID, contextID, instanceRef,
			generationHash, source, capturePolicyVersion)
		if err != nil {
			return ErrInvalidPage
		}
		initialHash, err := digest.hexSum()
		if err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO nms_import_sources
			(tenant_id,context_id,id,source_kind,instance_ref) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (tenant_id,context_id,source_kind,instance_ref) DO NOTHING`,
			tenantID, contextID, sourceID, string(source), instanceRef); err != nil {
			return captureStartErr(err)
		}
		var configVersion int64
		if err := sc.Q.QueryRow(ctx, `SELECT id::text,config_version FROM nms_import_sources
			WHERE tenant_id=$1 AND context_id=$2 AND source_kind=$3 AND instance_ref=$4`,
			tenantID, contextID, string(source), instanceRef).Scan(&sourceID, &configVersion); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO nms_import_plans
			(tenant_id,context_id,id,source_id,snapshot_hash,source_generation_hash,
			 policy_version,row_count,source_config_version,expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,0,$8,clock_timestamp()+interval '24 hours')`,
			tenantID, contextID, planID, sourceID, initialHash,
			generationHash, capturePolicyVersion, configVersion); err != nil {
			return captureStartErr(err)
		}
		return s.audit(ctx, sc, "nms_import.capture_started", planID,
			map[string]any{"context_id": contextID, "source_kind": source,
				"source_id": sourceID, "generation_hash": generationHash})
	})
	if err != nil {
		return "", err
	}
	return planID, nil
}

func captureUUID() (string, error) {
	raw, err := crypto.Random(16)
	if err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	id, err := uuid.FromBytes(raw)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// AppendPage parses one bounded source page, then commits its redacted rows
// and receipt in the same tenant transaction. An exact retry is harmless; a
// changed retry, skipped ordinal or duplicate source identity fails closed.
// No entity, rule, credential or agent registration is changed here.
func (s CaptureStore) AppendPage(ctx context.Context, contextID, planID string,
	pageNumber int64, resource string, firstRow int64, raw io.Reader) (string, error) {
	if s.pool == nil || s.audit == nil {
		return "", ErrCaptureAuditUnavailable
	}
	contextUUID, err := uuid.Parse(contextID)
	if err != nil || contextUUID == uuid.Nil {
		return "", ErrPlanUnavailable
	}
	planUUID, err := uuid.Parse(planID)
	if err != nil || planUUID == uuid.Nil || pageNumber < 0 || firstRow < 0 || raw == nil {
		return "", ErrInvalidPage
	}
	contextID, planID = contextUUID.String(), planUUID.String()
	var tenantID string
	var meta captureMeta
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		tenantID = sc.Tenant.String()
		var readErr error
		meta, readErr = loadCaptureMeta(ctx, sc, contextID, planID, false)
		return readErr
	})
	if err != nil {
		return "", err
	}
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil || tenantUUID == uuid.Nil {
		return "", ErrPlanUnavailable
	}
	tenantID = tenantUUID.String()
	if meta.state != "capturing" || !knownResource(meta.source, resource) {
		return "", ErrPlanUnavailable
	}
	snapshot, err := parseCapturePage(meta.source, resource, raw)
	if err != nil {
		return "", ErrInvalidPage
	}
	return s.appendSnapshot(ctx, contextID, planID, pageNumber, resource, firstRow, tenantID, meta, snapshot)
}

// appendSnapshot is shared by bounded source pages and the unpaged LibreNMS
// stream. The caller has loaded the plan through FORCE RLS; the locked write
// transaction below rechecks that exact tenant, context and plan state.
func (s CaptureStore) appendSnapshot(ctx context.Context, contextID, planID string,
	pageNumber int64, resource string, firstRow int64, tenantID string,
	meta captureMeta, snapshot Snapshot) (string, error) {
	if len(snapshot.Rows) > maxCaptureRowsPerPage {
		return "", ErrInvalidPage
	}
	rows, err := normalizePlanPage(tenantID, contextID, meta.instance, meta.generation,
		meta.source, snapshot, firstRow)
	if err != nil {
		return "", ErrInvalidPage
	}
	pageHash, err := normalizedPageHash(tenantID, contextID, meta.instance, meta.generation,
		meta.source, meta.policy, resource, pageNumber, firstRow, rows)
	if err != nil {
		return "", ErrInvalidPage
	}
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		locked, err := loadCaptureMeta(ctx, sc, contextID, planID, true)
		if err != nil {
			return err
		}
		if locked.source != meta.source || locked.instance != meta.instance ||
			locked.generation != meta.generation || locked.configVersion != meta.configVersion ||
			locked.policy != meta.policy ||
			locked.snapshotHash != meta.snapshotHash || locked.rowCount != meta.rowCount ||
			!locked.expires.Equal(meta.expires) || locked.state != "capturing" {
			return ErrPlanUnavailable
		}
		var lastPage, lastFirst, lastCount int64
		err = sc.Q.QueryRow(ctx, `SELECT page_number,first_row,row_count
			FROM nms_import_pages WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
			ORDER BY page_number DESC LIMIT 1`, tenantID, contextID, planID).
			Scan(&lastPage, &lastFirst, &lastCount)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if pageNumber != 0 || firstRow != 0 {
				return ErrInvalidPage
			}
		case err != nil:
			return err
		case pageNumber <= lastPage:
			var storedResource, storedHash string
			var storedFirst, storedCount int64
			err := sc.Q.QueryRow(ctx, `SELECT resource_kind,first_row,row_count,page_hash
				FROM nms_import_pages WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3 AND page_number=$4`,
				tenantID, contextID, planID, pageNumber).
				Scan(&storedResource, &storedFirst, &storedCount, &storedHash)
			if err != nil || storedResource != resource || storedFirst != firstRow ||
				storedCount != int64(len(rows)) || storedHash != pageHash {
				return ErrInvalidPage
			}
			return nil
		case lastPage == math.MaxInt64 || pageNumber != lastPage+1 ||
			lastFirst > math.MaxInt64-lastCount || firstRow != lastFirst+lastCount:
			return ErrInvalidPage
		}
		if firstRow > math.MaxInt64-int64(len(rows)) {
			return ErrInvalidPage
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO nms_import_pages
			(tenant_id,context_id,plan_id,page_number,resource_kind,first_row,row_count,page_hash)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			tenantID, contextID, planID, pageNumber, resource, firstRow, len(rows), pageHash); err != nil {
			return captureWriteErr(err)
		}
		for _, row := range rows {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO nms_import_rows
				(tenant_id,context_id,plan_id,row_number,object_kind,external_id,label,address,hostname,
				 parent_external_id,location_id,location_label,group_ids,poll_seconds,severity,unmapped_codes)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
				tenantID, contextID, planID, row.RowNumber, row.ObjectKind, row.ExternalID,
				nullText(row.Label), nullText(row.Address), nullText(row.Hostname),
				nullText(row.ParentID), nullText(row.LocationID), nullText(row.LocationLabel),
				nonNilStrings(row.GroupIDs), nullPositive(row.PollSeconds), nullText(row.Severity),
				nonNilStrings(row.UnmappedCodes)); err != nil {
				return captureWriteErr(err)
			}
		}
		return s.audit(ctx, sc, "nms_import.page_captured", planID,
			map[string]any{"context_id": contextID, "page_number": pageNumber,
				"resource_kind": resource, "first_row": firstRow,
				"row_count": len(rows), "page_hash": pageHash})
	})
	if err != nil {
		return "", err
	}
	return pageHash, nil
}

func loadCaptureMeta(ctx context.Context, sc tenancy.Scope, contextID, planID string, lock bool) (captureMeta, error) {
	query := `SELECT s.source_kind,s.instance_ref,p.source_generation_hash,
		p.source_config_version,s.config_version,p.policy_version,p.state,
		p.snapshot_hash,p.row_count,p.expires_at
		FROM nms_import_plans p JOIN nms_import_sources s
		  ON s.tenant_id=p.tenant_id AND s.context_id=p.context_id AND s.id=p.source_id
		WHERE p.tenant_id=$1 AND p.context_id=$2 AND p.id=$3 AND p.expires_at>clock_timestamp()`
	if lock {
		// A source reconfiguration cannot race this page or seal write. The
		// plan and source versions are checked under both row locks.
		query += ` FOR UPDATE OF p, s`
	}
	var meta captureMeta
	var kind string
	var currentConfigVersion int64
	err := sc.Q.QueryRow(ctx, query, sc.Tenant.String(), contextID, planID).
		Scan(&kind, &meta.instance, &meta.generation, &meta.configVersion,
			&currentConfigVersion, &meta.policy, &meta.state,
			&meta.snapshotHash, &meta.rowCount, &meta.expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return captureMeta{}, ErrPlanUnavailable
	}
	if err == nil && meta.configVersion != currentConfigVersion {
		return captureMeta{}, ErrPlanUnavailable
	}
	meta.source = Kind(kind)
	return meta, err
}

func parseCapturePage(source Kind, resource string, raw io.Reader) (Snapshot, error) {
	switch {
	case source == LibreNMS && resource == "devices":
		return parseLibreNMSDevices(raw)
	case source == LibreNMS && resource == "locations":
		return parseLibreNMSLocations(raw)
	case source == LibreNMS && resource == "groups":
		return parseLibreNMSGroups(raw)
	case source == LibreNMS && resource == "rules":
		return parseLibreNMSRules(raw)
	case source == Zabbix && resource == "hosts":
		return parseZabbixHosts(raw)
	case source == Orion && resource == "nodes":
		return parseOrionNodes(raw)
	case source == Orion && resource == "groups":
		return parseOrionGroups(raw)
	case source == Orion && resource == "rules":
		return parseOrionRules(raw)
	case source == PRTG && resource == "devices":
		return parsePRTGDevices(raw)
	case source == PRTG && resource == "groups":
		return parsePRTGGroups(raw)
	case source == PRTG && resource == "probes":
		return parsePRTGProbes(raw)
	default:
		return Snapshot{}, ErrInvalidPage
	}
}

func captureWriteErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "23503" || pgErr.Code == "23505" || pgErr.Code == "23514") {
		return ErrInvalidPage
	}
	return err
}

func captureStartErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if pgErr.Code == "23503" {
			return ErrPlanUnavailable
		}
		if pgErr.Code == "23505" || pgErr.Code == "23514" {
			return ErrInvalidPage
		}
	}
	return err
}

func nullText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullPositive(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

func nonNilStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return values
}
