// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrEntityAgentNotRegistered = errors.New("entity: source agent is not registered in this tenant")

func newRegistryID() (string, error) {
	b, err := crypto.Random(16)
	if err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	id, err := uuid.FromBytes(b)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// namedContextID gives one tenant a repeatable opaque UUID for a site or VRF
// label without asking the operator to invent an ID. The hash goes through
// internal/crypto, and the tenant/kind separators prevent cross-tenant reuse
// or a site label colliding with a VRF label.
func namedContextID(tenant, kind, label string) (string, error) {
	hash := crypto.Default.Hash([]byte("probectl:entity-context:v1\x00" + tenant + "\x00" + kind + "\x00" + label))
	if len(hash) < 16 {
		return "", errors.New("entity: crypto provider returned a short identity hash")
	}
	b := append([]byte(nil), hash[:16]...)
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	id, err := uuid.FromBytes(b)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func validContextLabel(raw string) (string, error) {
	label := strings.TrimSpace(raw)
	if label == "" || len(label) > 128 || strings.IndexFunc(label, unicode.IsControl) >= 0 {
		return "", entity.ErrInvalidClaim
	}
	return label, nil
}

// EntityContextAttributes derives the exact stored site/VRF attributes before
// an operator creates a context. Authorization uses these canonical values,
// so padding in a request cannot evade a label- or ID-scoped deny policy.
func EntityContextAttributes(tenantID, siteLabel, vrfLabel string) (entity.ContextRecord, error) {
	tenant, err := uuid.Parse(tenantID)
	if err != nil || tenant == uuid.Nil {
		return entity.ContextRecord{}, entity.ErrInvalidScope
	}
	siteLabel, err = validContextLabel(siteLabel)
	if err != nil {
		return entity.ContextRecord{}, err
	}
	vrfLabel, err = validContextLabel(vrfLabel)
	if err != nil {
		return entity.ContextRecord{}, err
	}
	siteID, err := namedContextID(tenant.String(), "site", siteLabel)
	if err != nil {
		return entity.ContextRecord{}, err
	}
	vrfID, err := namedContextID(tenant.String(), "vrf", vrfLabel)
	if err != nil {
		return entity.ContextRecord{}, err
	}
	return entity.ContextRecord{TenantID: tenant.String(), SiteID: siteID,
		VRFID: vrfID, SiteLabel: siteLabel, VRFLabel: vrfLabel}, nil
}

func validRegistryUUID(raw string) (string, error) {
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil {
		return "", entity.ErrInvalidScope
	}
	return id.String(), nil
}

// CreateEntityContext records an operator-named site/VRF pair. IDs are minted
// here, repeatably within this tenant, and never taken from a packet or
// collector. The context UUID is fresh; its compound tenant key is the outer
// storage boundary, while labels are display-only.
func (s *EntityRegistry) CreateEntityContext(ctx context.Context, sc tenancy.Scope, siteLabel, vrfLabel string) (entity.ContextRecord, error) {
	if s == nil || s.pool == nil {
		return entity.ContextRecord{}, ErrEntityRegistryUnavailable
	}
	record, err := EntityContextAttributes(sc.Tenant.String(), siteLabel, vrfLabel)
	if err != nil {
		return entity.ContextRecord{}, err
	}
	id, err := newRegistryID()
	if err != nil {
		return entity.ContextRecord{}, err
	}
	record.ContextID = id
	if err := sc.Q.QueryRow(ctx, `INSERT INTO entity_contexts
		(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING created_at`,
		sc.Tenant.String(), id, record.SiteID, record.VRFID,
		record.SiteLabel, record.VRFLabel).Scan(&record.CreatedAt); err != nil {
		return entity.ContextRecord{}, err
	}
	return record, nil
}

// CreateCanonicalEntity creates an operator-owned node in one existing
// context. The compound FK rejects a context from another tenant even when
// the caller supplies a syntactically valid UUID.
func (s *EntityRegistry) CreateCanonicalEntity(ctx context.Context, sc tenancy.Scope, contextID string, kind entity.Kind, label string) (entity.Record, error) {
	if s == nil || s.pool == nil {
		return entity.Record{}, ErrEntityRegistryUnavailable
	}
	contextID, err := validRegistryUUID(contextID)
	if err != nil {
		return entity.Record{}, err
	}
	if err := entity.ValidateKind(kind); err != nil {
		return entity.Record{}, err
	}
	label = strings.TrimSpace(label)
	if label == "" || len(label) > 1024 || strings.IndexFunc(label, unicode.IsControl) >= 0 {
		return entity.Record{}, entity.ErrInvalidClaim
	}
	id, err := newRegistryID()
	if err != nil {
		return entity.Record{}, err
	}
	record := entity.Record{Scope: entity.Scope{
		TenantID: sc.Tenant.String(), ContextID: contextID},
		ID: id, Kind: kind, Label: label,
	}
	err = sc.Q.QueryRow(ctx, `INSERT INTO entities
		(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,$4,$5)
		RETURNING created_at,updated_at`, sc.Tenant.String(), contextID, id,
		string(kind), label).Scan(&record.CreatedAt, &record.UpdatedAt)
	if err != nil {
		return entity.Record{}, err
	}
	return record, nil
}

// AssignEntitySource binds a registered agent/configured source to exactly
// one context and an optional canonical anchor. The caller holds agent.write
// and appends the tenant audit event in this same transaction. A different
// existing agent context is refused rather than silently moving every source.
func (s *EntityRegistry) AssignEntitySource(ctx context.Context, sc tenancy.Scope,
	source entity.SourceKey, contextID, anchorID string) error {
	if s == nil || s.pool == nil {
		return ErrEntityRegistryUnavailable
	}
	key, err := source.Normalize()
	if err != nil {
		return err
	}
	agent, err := validRegistryUUID(key.AgentID)
	if err != nil {
		return err
	}
	contextID, err = validRegistryUUID(contextID)
	if err != nil {
		return err
	}
	if anchorID != "" {
		anchorID, err = validRegistryUUID(anchorID)
		if err != nil {
			return err
		}
	}
	var status string
	err = sc.Q.QueryRow(ctx, `SELECT status FROM agents
		WHERE tenant_id=$1 AND id=$2
		  AND NOT EXISTS (SELECT 1 FROM agent_identities i
		                   WHERE i.tenant_id=$1 AND i.agent_id=$3
		                   AND i.revoked_at IS NOT NULL
		                   AND i.revoked_by IS DISTINCT FROM 'entity_registry_delete')
		FOR SHARE`, sc.Tenant.String(), agent, agent).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) || status == "revoked" {
		return ErrEntityAgentNotRegistered
	}
	if err != nil {
		return err
	}
	if anchorID != "" {
		var kind string
		if err := sc.Q.QueryRow(ctx, `SELECT kind FROM entities
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
			sc.Tenant.String(), contextID, anchorID).Scan(&kind); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return entity.ErrScopeMismatch
			}
			return err
		}
		if (key.Kind == entity.AgentSite && kind != string(entity.Site)) ||
			(key.Kind != entity.AgentSite && kind != string(entity.Device)) {
			return entity.ErrInvalidClaim
		}
	}
	if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
		(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)
		ON CONFLICT (tenant_id,agent_id) DO NOTHING`,
		sc.Tenant.String(), agent, contextID); err != nil {
		return err
	}
	var boundContext string
	if err := sc.Q.QueryRow(ctx, `SELECT context_id::text FROM entity_agent_contexts
		WHERE tenant_id=$1 AND agent_id=$2 FOR UPDATE`,
		sc.Tenant.String(), agent).Scan(&boundContext); err != nil {
		return err
	}
	if boundContext != contextID {
		return entity.ErrScopeMismatch
	}
	// A concurrent identity revocation may have committed while this call
	// waited for the agent-context row. Re-read it after acquiring the row lock
	// so an operator cannot report a reactivated source as successfully bound.
	var revoked bool
	if err := sc.Q.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM agent_identities
		WHERE tenant_id=$1 AND agent_id=$2 AND revoked_at IS NOT NULL
		  AND revoked_by IS DISTINCT FROM 'entity_registry_delete')`,
		sc.Tenant.String(), agent).Scan(&revoked); err != nil {
		return err
	}
	if revoked {
		return ErrEntityAgentNotRegistered
	}
	if _, err := sc.Q.Exec(ctx, `UPDATE entity_agent_contexts
		SET assigned_at=CASE WHEN expires_at IS NOT NULL
		                     THEN statement_timestamp() ELSE assigned_at END,
		    expires_at=NULL
		WHERE tenant_id=$1 AND agent_id=$2`, sc.Tenant.String(), agent); err != nil {
		return err
	}
	_, err = sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
		(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
		VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')::uuid)
		ON CONFLICT (tenant_id,agent_id,source_kind,source_ref)
		DO UPDATE SET anchor_entity_id=EXCLUDED.anchor_entity_id,
		              assigned_at=CASE
		                  WHEN entity_source_contexts.anchor_entity_id IS DISTINCT FROM EXCLUDED.anchor_entity_id
		                    OR entity_source_contexts.expires_at IS NOT NULL
		                  THEN statement_timestamp()
		                  ELSE entity_source_contexts.assigned_at END,
		              expires_at=NULL`,
		sc.Tenant.String(), agent, string(key.Kind), key.SourceRef,
		contextID, anchorID)
	return err
}
