// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrTagSubjectFactsAmbiguous = errors.New("tag subject has conflicting current facts")

// TagSubjectReference names owned state, never caller-supplied observations.
// Exporters use their registered pair; all other kinds use one exact ID.
type TagSubjectReference struct {
	Kind, ID                           string
	ExporterAgentID, ExporterSourceRef string
}

// ResolvedTagSubject intentionally omits raw names, addresses and inventory.
// A transport must still authorize its current routing context and project
// exporter identifiers according to its existing metadata disclosure policy.
type ResolvedTagSubject struct {
	Scope    tags.Scope
	Kind, ID string
	Revision int64
	AsOf     time.Time
	Items    []tags.Resolved
}

func normalizeTagSubjectReference(ref TagSubjectReference) (TagSubjectReference, error) {
	if ref.Kind == "exporter" {
		if ref.ID != "" {
			return TagSubjectReference{}, tags.ErrInvalid
		}
		key, err := (entity.SourceKey{AgentID: ref.ExporterAgentID, Kind: entity.FlowExporter, SourceRef: ref.ExporterSourceRef}).Normalize()
		if err != nil || key.AgentID != ref.ExporterAgentID || key.SourceRef != ref.ExporterSourceRef {
			return TagSubjectReference{}, tags.ErrInvalid
		}
		return ref, nil
	}
	if ref.ExporterAgentID != "" || ref.ExporterSourceRef != "" {
		return TagSubjectReference{}, tags.ErrInvalid
	}
	switch ref.Kind {
	case "device", "interface", "prefix", "test", "agent":
		id, err := validRegistryUUID(ref.ID)
		if err != nil {
			return TagSubjectReference{}, tags.ErrInvalid
		}
		ref.ID = id
	default:
		return TagSubjectReference{}, tags.ErrInvalid
	}
	return ref, nil
}

// ResolveSubject reads ownership, current facts and all tag state in one
// FORCE-RLS repeatable-read transaction. It does not expose a public route or
// infer a missing fact from a label. Agent-address and live prefix producers
// still need their separate source proof before full six-kind CIDR closure.
func (s *TagSnapshots) ResolveSubject(ctx context.Context, scope tags.Scope, ref TagSubjectReference, maxBytes int64) (ResolvedTagSubject, error) {
	if err := ctx.Err(); err != nil {
		return ResolvedTagSubject{}, err
	}
	if s == nil || s.pool == nil {
		return ResolvedTagSubject{}, ErrTagSnapshotUnavailable
	}
	if maxBytes <= 0 {
		return ResolvedTagSubject{}, ErrTagSnapshotBudget
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant.String() != scope.TenantID {
		return ResolvedTagSubject{}, tags.ErrScopeMismatch
	}
	ownedScope, err := (entity.Scope{TenantID: scope.TenantID, ContextID: scope.ContextID}).Normalize()
	if err != nil {
		return ResolvedTagSubject{}, tags.ErrScopeMismatch
	}
	scope = tags.Scope{TenantID: ownedScope.TenantID, ContextID: ownedScope.ContextID}
	ref, err = normalizeTagSubjectReference(ref)
	if err != nil {
		return ResolvedTagSubject{}, err
	}
	var out ResolvedTagSubject
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		used := int64(0)
		charge := func(parts ...string) error {
			amount := int64(2048)
			for _, part := range parts {
				amount += int64(len(part))
			}
			if amount > maxBytes-used {
				return ErrTagSnapshotBudget
			}
			used += amount
			return nil
		}
		var revision int64
		var asOf time.Time
		if err := sc.Q.QueryRow(ctx, `SELECT COALESCE((SELECT revision FROM tenant_tag_revisions WHERE tenant_id=$1),1),transaction_timestamp()`, scope.TenantID).Scan(&revision, &asOf); err != nil {
			return err
		}
		definitions, err := loadTagDefinitions(ctx, sc, scope, charge)
		if err != nil {
			return err
		}
		snapshot, err := loadTagContextSnapshot(ctx, sc, scope, revision, definitions, charge)
		if err != nil {
			return err
		}
		subject, err := loadOwnedTagSubject(ctx, sc, scope, ref, maxBytes, charge)
		if err != nil {
			return err
		}
		items, err := snapshot.ResolveContext(ctx, subject)
		if err != nil {
			return err
		}
		for _, item := range items {
			if err := charge(item.TagID, item.Key, item.Value, item.Source, item.SourceID); err != nil {
				return err
			}
		}
		out = ResolvedTagSubject{Scope: scope, Kind: subject.Kind, ID: subject.ID, Revision: revision, AsOf: asOf, Items: items}
		return nil
	})
	if err != nil {
		return ResolvedTagSubject{}, err
	}
	return out, nil
}

func loadOwnedTagSubject(ctx context.Context, sc tenancy.Scope, scope tags.Scope, ref TagSubjectReference, maxBytes int64, charge func(...string) error) (tags.Subject, error) {
	subject := tags.Subject{Scope: scope, Kind: ref.Kind, ID: ref.ID, AddressSide: ref.Kind}
	switch ref.Kind {
	case "device", "interface", "prefix":
		var parent string
		if err := sc.Q.QueryRow(ctx, `SELECT label,COALESCE(parent_entity_id::text,'') FROM entities
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND kind=$4`, scope.TenantID, scope.ContextID, ref.ID, ref.Kind).Scan(&subject.Name, &parent); err != nil {
			return tags.Subject{}, err
		}
		if err := charge(subject.ID, subject.Name, parent); err != nil {
			return tags.Subject{}, err
		}
		if err := loadCurrentTagEntityFacts(ctx, sc, &subject, parent, maxBytes, charge); err != nil {
			return tags.Subject{}, err
		}
	case "test":
		var target string
		if err := sc.Q.QueryRow(ctx, `SELECT t.name,t.target FROM tests t JOIN entity_test_contexts c
			ON c.tenant_id=t.tenant_id AND c.test_id=t.id WHERE t.tenant_id=$1 AND c.tenant_id=$1 AND c.context_id=$2 AND t.id=$3
			AND c.assigned_at<=transaction_timestamp()`, scope.TenantID, scope.ContextID, ref.ID).Scan(&subject.Name, &target); err != nil {
			return tags.Subject{}, err
		}
		if err := charge(subject.ID, subject.Name, target); err != nil {
			return tags.Subject{}, err
		}
		if address, err := netip.ParseAddr(path.TargetHost(target)); err == nil && address.Zone() == "" {
			subject.Address = address.Unmap()
		}
	case "agent":
		var hostname string
		if err := sc.Q.QueryRow(ctx, `SELECT a.name,a.hostname FROM agents a JOIN entity_agent_contexts c
			ON c.tenant_id=a.tenant_id AND c.agent_id=a.id::text WHERE a.tenant_id=$1 AND c.tenant_id=$1 AND c.context_id=$2 AND a.id=$3
			AND c.assigned_at<=transaction_timestamp() AND (c.expires_at IS NULL OR c.expires_at>transaction_timestamp())
			AND EXISTS(SELECT 1 FROM agent_identities i WHERE i.tenant_id=a.tenant_id AND i.agent_id=a.id::text AND i.spiffe_id=a.spiffe_id
			 AND i.revoked_at IS NULL AND i.issued_at<=transaction_timestamp() AND i.not_after>transaction_timestamp())`, scope.TenantID, scope.ContextID, ref.ID).Scan(&subject.Name, &hostname); err != nil {
			return tags.Subject{}, err
		}
		if err := charge(subject.ID, subject.Name, hostname); err != nil {
			return tags.Subject{}, err
		}
		if hostname != "" {
			subject.Names = []string{hostname}
		}
		// Hostnames and labels are never treated as agent-address evidence.
	case "exporter":
		var anchorLabel string
		if err := sc.Q.QueryRow(ctx, `SELECT COALESCE(n.label,'') FROM entity_source_contexts s JOIN entity_agent_contexts a
			ON a.tenant_id=s.tenant_id AND a.agent_id=s.agent_id AND a.context_id=s.context_id
			LEFT JOIN entities n ON n.tenant_id=s.tenant_id AND n.context_id=s.context_id AND n.id=s.anchor_entity_id AND n.kind='device'
			WHERE s.tenant_id=$1 AND a.tenant_id=$1 AND s.context_id=$2 AND s.agent_id=$3 AND s.source_kind='flow_exporter' AND s.source_ref=$4
			AND s.assigned_at<=transaction_timestamp() AND (s.expires_at IS NULL OR s.expires_at>transaction_timestamp())
			AND a.assigned_at<=transaction_timestamp() AND (a.expires_at IS NULL OR a.expires_at>transaction_timestamp())`, scope.TenantID, scope.ContextID, ref.ExporterAgentID, ref.ExporterSourceRef).Scan(&anchorLabel); err != nil {
			return tags.Subject{}, err
		}
		id, err := tags.ExporterTargetID(ref.ExporterAgentID, ref.ExporterSourceRef)
		if err != nil {
			return tags.Subject{}, err
		}
		subject.ID, subject.Name = id, anchorLabel
		if err := charge(id, anchorLabel, ref.ExporterAgentID, ref.ExporterSourceRef); err != nil {
			return tags.Subject{}, err
		}
		if address, err := netip.ParseAddr(ref.ExporterSourceRef); err == nil && address.Zone() == "" {
			subject.Address = address.Unmap()
		}
		// This explicit owned pair is not the raw-flow address-only association.
	}
	return subject, nil
}
