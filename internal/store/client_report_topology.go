// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/hex"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// A physical adjacency is an observation at capture, not a discovery or
// reachability assertion. RemoteEvidenceID identifies the exact independent
// SNMP receipt which supported that canonical endpoint in the capture snapshot.
type ClientReportPhysicalLink struct {
	TenantID, ContextID, LinkID                 string
	FromEntityID, ToEntityID                    string
	EvidenceID, ObservationID, RemoteEvidenceID string
	RemoteObservationID                         string
	Source, RemoteSource                        entity.SourceKey
	Protocol, LocalPort, RemotePort, Chassis    string
	DeviceName, ManagementAddress               string
	LocalIfIndex                                uint32
	ObservedAt, RemoteObservedAt, CapturedAt    time.Time
	OriginalsDigest                             string
}

// These are private identity/content requirements, never access grants. They
// preserve both original receipts rather than rerunning today's alias resolver
// and silently substituting a new remote poll into an old report.
type ReportPhysicalLinkRef struct {
	ContextID        string    `json:"context_id"`
	LinkID           string    `json:"link_id"`
	FromEntityID     string    `json:"from_entity_id"`
	ToEntityID       string    `json:"to_entity_id"`
	EvidenceID       string    `json:"evidence_id"`
	RemoteEvidenceID string    `json:"remote_evidence_id"`
	CapturedAt       time.Time `json:"captured_at"`
	OriginalsDigest  string    `json:"originals_digest"`
}

var reportEvidenceAlias = regexp.MustCompile(`\be\.`)

func reportNeighborHistoricalSQL() (string, error) {
	query := currentEntityEvidenceSourceSQL(false)
	// The exact frozen remote support is checked separately below. The live
	// predicate intentionally continues to resolve complete current support.
	for _, pair := range [][2]string{
		{currentPhysicalNeighborSQL, "TRUE"},
		{"e.observed_at <= statement_timestamp()", "e.observed_at <= requested.captured_at"},
		{"(e.expires_at IS NULL OR e.expires_at > statement_timestamp())", "(e.expires_at IS NULL OR e.expires_at > requested.captured_at)"},
		{"sender.not_after > statement_timestamp()", "sender.not_after > e.observed_at"},
	} {
		if strings.Count(query, pair[0]) != 1 {
			return "", entity.ErrInvalidClaim
		}
		query = strings.Replace(query, pair[0], pair[1], 1)
	}
	query += ` AND requested.captured_at<=transaction_timestamp()
 AND EXISTS (SELECT 1 FROM agent_identities active
 WHERE active.tenant_id=e.tenant_id AND active.agent_id=e.agent_id
 AND active.spiffe_id='spiffe://probectl/tenant/'||e.tenant_id::text||'/entity/'||e.agent_id
 AND active.revoked_at IS NULL AND active.issued_at<=transaction_timestamp()
 AND active.not_after>transaction_timestamp())`
	return strings.ReplaceAll(query, "statement_timestamp()", "transaction_timestamp()"), nil
}

const reportPhysicalSelect = `SELECT e.tenant_id::text,e.context_id::text,l.id::text,l.from_entity_id::text,l.to_entity_id::text,
 e.id::text,e.observation_id::text,remote.id::text,remote.observation_id::text,
 e.agent_id,e.configured_ref,remote.agent_id,remote.configured_ref,
 e.neighbor_protocol,e.neighbor_local_if_index,COALESCE(e.neighbor_local_port_id,''),COALESCE(e.neighbor_remote_port_id,''),
 COALESCE(e.neighbor_chassis_id,''),COALESCE(e.neighbor_device_name,''),COALESCE(e.neighbor_management_address,''),
 e.observed_at,remote.observed_at,requested.captured_at,
 CASE WHEN octet_length(jsonb_build_array(to_jsonb(l),to_jsonb(e)-'expires_at',to_jsonb(remote)-'expires_at')::text)<=$4
 THEN jsonb_build_array(to_jsonb(l),to_jsonb(e)-'expires_at',to_jsonb(remote)-'expires_at')::text END `

const reportPhysicalLocalJoin = ` JOIN entity_evidence e ON
 (e.tenant_id,e.context_id,e.id)=(l.tenant_id,l.context_id,l.evidence_id) `

const reportPhysicalLocalGuard = `e.tenant_id=$1 AND l.tenant_id=$1 AND l.kind='physical'
 AND e.source_kind='device_target' AND e.alias_kind='physical_neighbor_id'
 AND e.support_evidence_id IS NULL AND l.from_entity_id=e.entity_id
 AND l.observed_at=e.observed_at AND `

const reportPhysicalRemoteGuard = `remote.tenant_id=e.tenant_id AND remote.context_id=e.context_id
 AND remote.source_kind='device_target' AND remote.support_evidence_id IS NULL
 AND remote.alias_kind=CASE WHEN e.neighbor_management_address IS NOT NULL THEN 'address' ELSE 'snmp_device_id' END
 AND remote.alias_value=COALESCE(e.neighbor_management_address,e.neighbor_device_name)
 AND n.kind IN ('device','interface') AND COALESCE(n.parent_entity_id,n.id)=l.to_entity_id AND `

// Capture uses the complete live source/support predicates, including unique
// canonical remote resolution across the full current support population.
// A deterministic supporting receipt is a citation, not a cap on graph edges.
func (*EntityRegistry) ClientReportPhysicalLinksInScope(ctx context.Context, sc tenancy.Scope, memory int64, authorize func(context.Context, entity.ContextRecord, string, string) error) ([]ClientReportPhysicalLink, error) {
	return currentPhysicalLinksInScope(ctx, sc, "", memory, authorize)
}

// CurrentPhysicalLinksInContext reads the original physical links in one
// routing context. It uses the same current source and independent neighbor
// support checks as client reports. The context is part of the storage query.
func (*EntityRegistry) CurrentPhysicalLinksInContext(ctx context.Context, sc tenancy.Scope, scope entity.Scope, memory int64, authorize func(context.Context, entity.ContextRecord, string, string) error) ([]ClientReportPhysicalLink, error) {
	normalized, err := scope.Normalize()
	if err != nil || normalized != scope || scope.TenantID != sc.Tenant.String() {
		return nil, entity.ErrScopeMismatch
	}
	return currentPhysicalLinksInScope(ctx, sc, scope.ContextID, memory, authorize)
}

func currentPhysicalLinksInScope(ctx context.Context, sc tenancy.Scope, contextID string, memory int64, authorize func(context.Context, entity.ContextRecord, string, string) error) ([]ClientReportPhysicalLink, error) {
	if err := reportPhysicalReadScope(ctx, sc, memory); err != nil {
		return nil, err
	}
	if authorize == nil {
		return nil, entity.ErrScopeMismatch
	}
	predicate := currentEntityEvidenceSnapshotSQL(false)
	remote := reportEvidenceAlias.ReplaceAllString(predicate, "remote.")
	var captured time.Time
	if err := sc.Q.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&captured); err != nil {
		return nil, err
	}
	query := `WITH requested AS (SELECT $2::timestamptz AS captured_at) ` + reportPhysicalSelect + `
 FROM requested JOIN entity_links l ON l.tenant_id=$1 ` + reportPhysicalLocalJoin + `
 JOIN LATERAL (SELECT remote.* FROM entity_evidence remote
 JOIN entities n ON (n.tenant_id,n.context_id,n.id)=(remote.tenant_id,remote.context_id,remote.entity_id)
 WHERE ` + reportPhysicalRemoteGuard + remote + ` ORDER BY remote.id LIMIT 1) remote ON TRUE
 WHERE ` + reportPhysicalLocalGuard + predicate
	args := []any{pgx.QueryExecModeDescribeExec, sc.Tenant.String(), captured, memory/4096 + 1, memory / 16}
	if contextID != "" {
		query += ` AND l.context_id=$5::uuid`
		args = append(args, contextID)
	}
	query += ` ORDER BY l.context_id,l.id LIMIT $3`
	rows, err := sc.Q.Query(ctx, query, args...)
	items, err := scanReportPhysicalLinks(ctx, rows, err, memory)
	if err != nil {
		return nil, err
	}
	if err := authorizeReportPhysicalLinks(ctx, sc, items, authorize); err != nil {
		return nil, err
	}
	return items, ctx.Err()
}

func reportPhysicalReadScope(ctx context.Context, sc tenancy.Scope, memory int64) error {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil {
		return entity.ErrScopeMismatch
	}
	if memory < 8192 {
		return ErrClientReportBudget
	}
	return requireReportSourceReadScope(ctx, sc)
}

func scanReportPhysicalLinks(ctx context.Context, rows pgx.Rows, queryErr error, memory int64) ([]ClientReportPhysicalLink, error) {
	if queryErr != nil {
		return nil, queryErr
	}
	defer rows.Close()
	items := []ClientReportPhysicalLink{}
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var item ClientReportPhysicalLink
		var index int64
		var originals *string
		item.Source.Kind, item.RemoteSource.Kind = entity.DeviceTarget, entity.DeviceTarget
		if err := rows.Scan(&item.TenantID, &item.ContextID, &item.LinkID, &item.FromEntityID, &item.ToEntityID,
			&item.EvidenceID, &item.ObservationID, &item.RemoteEvidenceID, &item.RemoteObservationID,
			&item.Source.AgentID, &item.Source.SourceRef, &item.RemoteSource.AgentID, &item.RemoteSource.SourceRef,
			&item.Protocol, &index, &item.LocalPort, &item.RemotePort, &item.Chassis, &item.DeviceName, &item.ManagementAddress,
			&item.ObservedAt, &item.RemoteObservedAt, &item.CapturedAt, &originals); err != nil {
			return nil, err
		}
		if index <= 0 || index > 4294967295 || (item.Protocol != "lldp" && item.Protocol != "cdp") {
			return nil, entity.ErrInvalidClaim
		}
		if originals == nil || int64(len(*originals)) > (memory-8192)/16 {
			return nil, ErrClientReportBudget
		}
		memory -= 8192 + 16*int64(len(*originals))
		item.LocalIfIndex = uint32(index)
		item.ObservedAt, item.RemoteObservedAt, item.CapturedAt = item.ObservedAt.UTC(), item.RemoteObservedAt.UTC(), item.CapturedAt.UTC()
		item.OriginalsDigest = hex.EncodeToString(crypto.Hash(append([]byte("probectl.report.physical.v1:"), []byte(*originals)...)))
		items = append(items, item)
	}
	return items, rows.Err()
}

func authorizeReportPhysicalLinks(ctx context.Context, sc tenancy.Scope, items []ClientReportPhysicalLink, authorize func(context.Context, entity.ContextRecord, string, string) error) error {
	contexts := map[string]entity.ContextRecord{}
	for _, item := range items {
		if item.TenantID != sc.Tenant.String() {
			return entity.ErrScopeMismatch
		}
		record, ok := contexts[item.ContextID]
		if !ok {
			var err error
			record, err = NewEntityRegistry(nil).GetEntityContextInScope(ctx, sc, item.ContextID)
			if err != nil {
				return err
			}
			contexts[item.ContextID] = record
		}
		if err := authorize(ctx, record, item.FromEntityID, item.ToEntityID); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func ClientReportPhysicalLinkRefs(items []ClientReportPhysicalLink) []ReportPhysicalLinkRef {
	refs := make([]ReportPhysicalLinkRef, 0, len(items))
	for _, item := range items {
		refs = append(refs, ReportPhysicalLinkRef{ContextID: item.ContextID, LinkID: item.LinkID,
			FromEntityID: item.FromEntityID, ToEntityID: item.ToEntityID, EvidenceID: item.EvidenceID,
			RemoteEvidenceID: item.RemoteEvidenceID, CapturedAt: item.CapturedAt, OriginalsDigest: item.OriginalsDigest})
	}
	return refs
}
