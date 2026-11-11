// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// PostgresCapacityAgreements retains immutable operator revisions. All reads
// bind the tenant before decoding terms; current target refs are storage-bound
// to that tenant's inventory. No revision is a telemetry read grant.
type PostgresCapacityAgreements struct {
	pool                               *pgxpool.Pool
	fence                              tenancy.WriterFence
	audit                              QueryConfigAudit
	stateBytes, memoryBytes, workUnits int64
	executionLimit                     time.Duration
	authorize                          func(context.Context, tenancy.Scope, string, bool) error
}

func NewPostgresCapacityAgreements(pool *pgxpool.Pool, stateBytes, memoryBytes, workUnits int64, record QueryConfigAudit) *PostgresCapacityAgreements {
	return &PostgresCapacityAgreements{pool: pool, fence: tenancy.NewPostgresWriterFence(pool), audit: record, stateBytes: stateBytes, memoryBytes: memoryBytes, workUnits: workUnits, executionLimit: time.Minute}
}

// WithExecutionLimit configures a finite operation deadline before serving.
// Invalid/unlimited values fail closed when an operation is attempted.
func (s *PostgresCapacityAgreements) WithExecutionLimit(limit time.Duration) *PostgresCapacityAgreements {
	s.executionLimit = limit
	return s
}

// WithAuthorization installs the serving caller's current credential/user
// authorization inside the same tenant snapshot as the terms. The repository
// itself grants no access; private storage/lifecycle callers own authorization.
// Configure once before use, never concurrently with an operation.
func (s *PostgresCapacityAgreements) WithAuthorization(authorize func(context.Context, tenancy.Scope, string, bool) error) *PostgresCapacityAgreements {
	s.authorize = authorize
	return s
}

func (s *PostgresCapacityAgreements) inScope(ctx context.Context, actor string, readOnly, mutation bool, fn func(context.Context, tenancy.Scope) error) error {
	if _, ok := tenancy.FromContext(ctx); !ok {
		return tenancy.ErrNoTenant
	}
	if s == nil || s.pool == nil || s.stateBytes <= 0 || s.memoryBytes < 1<<20 || s.workUnits < 4096 || s.executionLimit <= 0 || !capacityAgreementText(actor, true) {
		return ErrCapacityAgreementInvalid
	}
	ctx, cancel := context.WithTimeout(tenancy.WithSiloTableLock(ctx), s.executionLimit)
	defer cancel()
	work := func(ctx context.Context, sc tenancy.Scope) error {
		if s.authorize != nil {
			if err := s.authorize(ctx, sc, actor, mutation); err != nil {
				return err
			}
		}
		return fn(ctx, sc)
	}
	if readOnly {
		return tenancy.InTenantReadSnapshot(ctx, s.pool, work)
	}
	return tenancy.InTenant(ctx, s.pool, work)
}

func capacityAgreementStorageError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrCapacityAgreementNotFound
	}
	var database *pgconn.PgError
	if errors.As(err, &database) {
		switch database.Code {
		case "23503":
			return ErrCapacityAgreementNotFound
		case "23505":
			return ErrCapacityAgreementConflict
		case "23514", "22P02", "22003":
			return ErrCapacityAgreementInvalid
		}
		return errors.New("capacity agreement storage is unavailable")
	}
	return err
}

func capacityAgreementVersion(value string) (int64, error) {
	version, err := strconv.ParseInt(value, 10, 64)
	if err != nil || version <= 0 || strconv.FormatInt(version, 10) != value {
		return 0, ErrCapacityAgreementConflict
	}
	return version, nil
}

func capacityAgreementNanos(at time.Time) string {
	seconds := new(big.Int).Mul(big.NewInt(at.Unix()), big.NewInt(1_000_000_000))
	return seconds.Add(seconds, big.NewInt(int64(at.Nanosecond()))).String()
}

const capacityAgreementColumns = `a.id::text,a.version,a.created_at,a.updated_at,r.version,r.created_at,
CASE WHEN octet_length(r.definition::text)<=$4::bigint THEN r.definition ELSE NULL END,
octet_length(r.definition::text),r.valid_from_nanos::text,
COALESCE(ref.target_kind,''),COALESCE(ref.context_id::text,''),COALESCE(ref.interface_id::text,''),COALESCE(ref.tag_id::text,'')`

func (s *PostgresCapacityAgreements) read(ctx context.Context, sc tenancy.Scope, id string, version int64, asOf string) (CapacityAgreement, error) {
	var result CapacityAgreement
	var head, selected, storedBytes int64
	var body []byte
	var effective, kind, contextID, interfaceID, tagID string
	// The explicit tenant predicate and FORCE-RLS both precede the CASE body
	// projection. An oversized/corrupt row is refused without fetching its body.
	query := `SELECT ` + capacityAgreementColumns + ` FROM flow_capacity_agreements a
JOIN LATERAL (SELECT revision.* FROM flow_capacity_agreement_revisions revision
 WHERE revision.tenant_id=a.tenant_id AND revision.agreement_id=a.id
 AND (($3::bigint=0 AND $5='' AND revision.version=a.version)
   OR ($3::bigint>0 AND revision.version=$3)
   OR ($5<>'' AND revision.valid_from_nanos<=NULLIF($5,'')::numeric))
 ORDER BY revision.valid_from_nanos DESC,revision.version DESC LIMIT 1) r ON true
LEFT JOIN flow_capacity_agreement_refs ref ON ref.tenant_id=r.tenant_id AND ref.agreement_id=r.agreement_id AND ref.version=r.version
WHERE a.tenant_id=$1::uuid AND a.id=$2::uuid`
	err := sc.Q.QueryRow(ctx, query, sc.Tenant.String(), id, version, s.memoryBytes/64, asOf).Scan(&result.ID, &head, &result.CreatedAt, &result.UpdatedAt, &selected, &result.RecordedAt, &body, &storedBytes, &effective, &kind, &contextID, &interfaceID, &tagID)
	if err != nil {
		return CapacityAgreement{}, capacityAgreementStorageError(err)
	}
	if storedBytes > s.memoryBytes/64 || body == nil {
		return CapacityAgreement{}, ErrCapacityAgreementBudget
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result.Definition); err != nil {
		return CapacityAgreement{}, ErrCapacityAgreementInvalid
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return CapacityAgreement{}, ErrCapacityAgreementInvalid
	}
	definition, err := NormalizeCapacityAgreement(ctx, result.Definition, s.memoryBytes, s.workUnits)
	if err != nil {
		return CapacityAgreement{}, err
	}
	from, err := time.Parse(time.RFC3339Nano, definition.ValidFrom)
	if err != nil || capacityAgreementNanos(from) != effective {
		return CapacityAgreement{}, ErrCapacityAgreementInvalid
	}
	if kind != "" && (kind != definition.Target.Kind || contextID != definition.Target.ContextID || interfaceID != definition.Target.InterfaceID || tagID != definition.Target.TagID) {
		return CapacityAgreement{}, ErrCapacityAgreementInvalid
	}
	result.TenantID, result.Version, result.CurrentVersion, result.Definition, result.TargetPresent = sc.Tenant.String(), strconv.FormatInt(selected, 10), strconv.FormatInt(head, 10), definition, kind != ""
	return result, nil
}

func (s *PostgresCapacityAgreements) GetCapacityAgreement(ctx context.Context, actor, id, version string) (CapacityAgreement, error) {
	if !capacityAgreementUUID(id) {
		return CapacityAgreement{}, ErrCapacityAgreementInvalid
	}
	var selected int64
	if version != "" {
		var err error
		selected, err = capacityAgreementVersion(version)
		if err != nil {
			return CapacityAgreement{}, err
		}
	}
	var result CapacityAgreement
	err := s.inScope(ctx, actor, true, false, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		result, err = s.read(ctx, sc, id, selected, "")
		return err
	})
	if err != nil {
		return CapacityAgreement{}, capacityAgreementStorageError(err)
	}
	return result, nil
}

func (s *PostgresCapacityAgreements) CapacityAgreementAt(ctx context.Context, actor, id string, at time.Time) (CapacityAgreement, error) {
	if !capacityAgreementUUID(id) {
		return CapacityAgreement{}, ErrCapacityAgreementInvalid
	}
	var result CapacityAgreement
	err := s.inScope(ctx, actor, true, false, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		result, err = s.read(ctx, sc, id, 0, capacityAgreementNanos(at))
		return err
	})
	if err != nil {
		return CapacityAgreement{}, capacityAgreementStorageError(err)
	}
	return result, nil
}

func (s *PostgresCapacityAgreements) SaveCapacityAgreement(ctx context.Context, actor string, input SaveCapacityAgreement) (CapacityAgreement, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return CapacityAgreement{}, tenancy.ErrNoTenant
	}
	if s == nil || s.pool == nil || s.stateBytes <= 0 || s.executionLimit <= 0 {
		return CapacityAgreement{}, ErrCapacityAgreementInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, s.executionLimit)
	defer cancel()
	definition, err := NormalizeCapacityAgreement(ctx, input.Definition, s.memoryBytes, s.workUnits)
	if err != nil {
		return CapacityAgreement{}, err
	}
	var expected int64
	if input.ID != "" {
		if !capacityAgreementUUID(input.ID) {
			return CapacityAgreement{}, ErrCapacityAgreementInvalid
		}
		expected, err = capacityAgreementVersion(input.Version)
		if err != nil {
			return CapacityAgreement{}, err
		}
	} else if input.Version != "" {
		return CapacityAgreement{}, ErrCapacityAgreementConflict
	}
	body, err := json.Marshal(definition)
	if err != nil {
		return CapacityAgreement{}, ErrCapacityAgreementInvalid
	}
	var result CapacityAgreement
	err = tenancy.FencedWrite(ctx, s.fence, []string{tenant.String()}, func(value string) string { return value }, tenancy.ErrNoTenant, func(ctx context.Context) error {
		return s.inScope(ctx, actor, false, true, func(ctx context.Context, sc tenancy.Scope) error {
			if err := tenancy.LockTenantAuditStream(ctx, sc.Q, tenant.String()); err != nil {
				return err
			}
			id := input.ID
			if id != "" {
				var current int64
				if err := sc.Q.QueryRow(ctx, `SELECT version FROM flow_capacity_agreements WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant.String(), id).Scan(&current); err != nil {
					return err
				}
				if current != expected || current == math.MaxInt64 {
					return ErrCapacityAgreementConflict
				}
			} else {
				var err error
				id, err = crypto.UUIDv4()
				if err != nil {
					return err
				}
			}
			var used, needed string
			if err := sc.Q.QueryRow(ctx, `SELECT (COALESCE((SELECT sum(octet_length(definition::text)+1024) FROM flow_capacity_agreement_revisions WHERE tenant_id=$1),0)
 +256*(SELECT count(*) FROM flow_capacity_agreements WHERE tenant_id=$1))::text`, tenant.String()).Scan(&used); err != nil {
				return err
			}
			var parentBytes int64
			if input.ID == "" {
				parentBytes = 256
			}
			if err := sc.Q.QueryRow(ctx, `SELECT (octet_length($1::jsonb::text)+1024+$2::bigint)::text`, string(body), parentBytes).Scan(&needed); err != nil {
				return err
			}
			usedValue, usedOK := new(big.Int).SetString(used, 10)
			added, addedOK := new(big.Int).SetString(needed, 10)
			if !usedOK || !addedOK || usedValue.Sign() < 0 || added.Sign() < 0 {
				return ErrCapacityAgreementInvalid
			}
			if new(big.Int).Add(usedValue, added).Cmp(big.NewInt(s.stateBytes)) > 0 {
				return ErrCapacityAgreementBudget
			}
			if input.ID == "" {
				if _, err := sc.Q.Exec(ctx, `INSERT INTO flow_capacity_agreements(tenant_id,id,version) VALUES($1,$2,1)`, tenant.String(), id); err != nil {
					return err
				}
			} else {
				command, err := sc.Q.Exec(ctx, `UPDATE flow_capacity_agreements SET version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND version=$3`, tenant.String(), id, expected)
				if err != nil {
					return err
				}
				if command.RowsAffected() != 1 {
					return ErrCapacityAgreementConflict
				}
			}
			from, err := time.Parse(time.RFC3339Nano, definition.ValidFrom)
			if err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO flow_capacity_agreement_revisions(tenant_id,agreement_id,version,definition,valid_from_nanos) VALUES($1,$2,$3,$4::jsonb,$5::numeric)`, tenant.String(), id, expected+1, string(body), capacityAgreementNanos(from)); err != nil {
				return err
			}
			if err := recordQueryConfig(ctx, sc, s.audit, actor, "flow.capacity.agreement.save", id, map[string]any{"version": strconv.FormatInt(expected+1, 10), "definition_hash": fmt.Sprintf("%x", crypto.Hash(body))}); err != nil {
				return err
			}
			result, err = s.read(ctx, sc, id, expected+1, "")
			return err
		})
	})
	if err != nil {
		return CapacityAgreement{}, capacityAgreementStorageError(err)
	}
	return result, nil
}

func (s *PostgresCapacityAgreements) DeleteCapacityAgreement(ctx context.Context, actor, id, version string) error {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return tenancy.ErrNoTenant
	}
	if s == nil || s.pool == nil || s.stateBytes <= 0 || s.executionLimit <= 0 || !capacityAgreementUUID(id) {
		return ErrCapacityAgreementInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, s.executionLimit)
	defer cancel()
	expected, err := capacityAgreementVersion(version)
	if err != nil {
		return err
	}
	err = tenancy.FencedWrite(ctx, s.fence, []string{tenant.String()}, func(value string) string { return value }, tenancy.ErrNoTenant, func(ctx context.Context) error {
		return s.inScope(ctx, actor, false, true, func(ctx context.Context, sc tenancy.Scope) error {
			if err := tenancy.LockTenantAuditStream(ctx, sc.Q, tenant.String()); err != nil {
				return err
			}
			var current int64
			if err := sc.Q.QueryRow(ctx, `SELECT version FROM flow_capacity_agreements WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant.String(), id).Scan(&current); err != nil {
				return err
			}
			if current != expected {
				return ErrCapacityAgreementConflict
			}
			if _, err := sc.Q.Exec(ctx, `DELETE FROM flow_capacity_agreements WHERE tenant_id=$1 AND id=$2 AND version=$3`, tenant.String(), id, expected); err != nil {
				return err
			}
			return recordQueryConfig(ctx, sc, s.audit, actor, "flow.capacity.agreement.delete", id, map[string]any{"version": version})
		})
	})
	return capacityAgreementStorageError(err)
}
