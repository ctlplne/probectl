// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"net/netip"
	"sort"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestTagSnapshot contains only current owned test annotations and the owned
// context attributes needed for disclosure policy. It does not attest a raw
// result's test ID, infer one from its target or add labels to stored telemetry.
type TestTagSnapshot struct {
	tenantID    string
	revision    int64
	asOf        time.Time
	contexts    []entity.ContextRecord
	subjects    map[string]ResolvedTagSubject
	definitions []tags.Definition
}

func (s *TestTagSnapshot) valid() error {
	if s == nil || s.tenantID == "" || s.revision <= 0 || s.asOf.IsZero() {
		return ErrTagSnapshotUnavailable
	}
	return nil
}

func (s *TestTagSnapshot) Clock() (int64, time.Time, error) {
	if err := s.valid(); err != nil {
		return 0, time.Time{}, err
	}
	return s.revision, s.asOf, nil
}

// Contexts returns independent copies from the same RLS snapshot as the tags.
// A transport must authorize tags.read and the test source for each context.
func (s *TestTagSnapshot) Contexts() ([]entity.ContextRecord, error) {
	if err := s.valid(); err != nil {
		return nil, err
	}
	return append([]entity.ContextRecord(nil), s.contexts...), nil
}

// ResolveContext withholds an unknown or denied test. A missing policy map,
// foreign tenant, cancellation or budget refusal never yields partial tags.
func (s *TestTagSnapshot) ResolveContext(ctx context.Context, tenantID, testID string, allowed map[string]bool, maxBytes int64) (*ResolvedTagSubject, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.valid(); err != nil {
		return nil, err
	}
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenantID || tenantID != s.tenantID || allowed == nil {
		return nil, tags.ErrScopeMismatch
	}
	if maxBytes <= 0 {
		return nil, ErrTagSnapshotBudget
	}
	id, err := validRegistryUUID(testID)
	if err != nil {
		return nil, nil
	}
	item, found := s.subjects[id]
	if !found || !allowed[item.Scope.ContextID] {
		return nil, nil
	}
	if item.Scope.TenantID != tenantID || item.Kind != "test" || item.ID != id || item.Revision != s.revision || !item.AsOf.Equal(s.asOf) {
		return nil, tags.ErrScopeMismatch
	}
	used := int64(2048 + len(item.Scope.ContextID) + len(item.ID))
	if used > maxBytes {
		return nil, ErrTagSnapshotBudget
	}
	for _, value := range item.Items {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		amount := int64(2048 + len(value.TagID) + len(value.Key) + len(value.Value) + len(value.Source) + len(value.SourceID))
		if amount > maxBytes-used {
			return nil, ErrTagSnapshotBudget
		}
		used += amount
	}
	item.Items = append([]tags.Resolved(nil), item.Items...)
	return &item, nil
}

func ownedTestTagSubject(scope tags.Scope, id, name, target string) tags.Subject {
	subject := tags.Subject{Scope: scope, Kind: "test", ID: id, Name: name, AddressSide: "test"}
	if address, err := netip.ParseAddr(path.TargetHost(target)); err == nil && address.Zone() == "" {
		subject.Address = address.Unmap()
	}
	return subject
}

// LoadTests captures requested owned test identities, current contexts and all
// relevant tag state under one tenant repeatable-read snapshot. Reusing each
// compiled context avoids per-result transactions and mixed tag revisions.
func (s *TagSnapshots) LoadTests(ctx context.Context, testIDs []string, maxBytes int64) (*TestTagSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || s.pool == nil {
		return nil, ErrTagSnapshotUnavailable
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return nil, tags.ErrScopeMismatch
	}
	if maxBytes <= 0 || int64(len(testIDs)) > maxBytes/256 {
		return nil, ErrTagSnapshotBudget
	}
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
	unique := map[string]bool{}
	for _, candidate := range testIDs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Account for the input map, normalized ID and sorted-ID vector,
		// without charging a full database row for duplicate/unknown hints.
		amount := int64(256 + len(candidate))
		if amount > maxBytes-used {
			return nil, ErrTagSnapshotBudget
		}
		used += amount
		id, err := validRegistryUUID(candidate)
		if err == nil {
			unique[id] = true
		}
	}
	ids := make([]string, 0, len(unique))
	for id := range unique {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := &TestTagSnapshot{tenantID: tenant.String(), subjects: map[string]ResolvedTagSubject{}}
	err := tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := sc.Q.QueryRow(ctx, `SELECT COALESCE((SELECT revision FROM tenant_tag_revisions WHERE tenant_id=$1),1),transaction_timestamp()`, tenant.String()).Scan(&result.revision, &result.asOf); err != nil {
			return err
		}
		definitions, err := loadTagDefinitions(ctx, sc, tags.Scope{TenantID: tenant.String()}, charge)
		if err != nil {
			return err
		}
		result.definitions = definitions
		if len(ids) == 0 {
			return nil
		}
		limit := maxBytes/2048 + 1
		rows, err := sc.Q.Query(ctx, `SELECT t.id::text,t.name,t.target,c.context_id::text,
			e.site_id::text,e.vrf_id::text,e.site_label,e.vrf_label,e.created_at
			FROM tests t JOIN entity_test_contexts c ON c.tenant_id=t.tenant_id AND c.test_id=t.id
			JOIN entity_contexts e ON e.tenant_id=c.tenant_id AND e.id=c.context_id
			WHERE t.tenant_id=$1 AND c.tenant_id=$1 AND e.tenant_id=$1 AND t.id=ANY($2::uuid[])
			AND c.assigned_at<=transaction_timestamp() ORDER BY t.id LIMIT $3`, tenant.String(), ids, limit)
		if err != nil {
			return err
		}
		var candidates []tags.Subject
		contexts := map[string]entity.ContextRecord{}
		for rows.Next() {
			if int64(len(candidates))+1 >= limit {
				rows.Close()
				return ErrTagSnapshotBudget
			}
			var id, name, target string
			record := entity.ContextRecord{TenantID: tenant.String()}
			if err := rows.Scan(&id, &name, &target, &record.ContextID, &record.SiteID, &record.VRFID, &record.SiteLabel, &record.VRFLabel, &record.CreatedAt); err != nil {
				rows.Close()
				return err
			}
			if err := charge(id, name, target, record.ContextID, record.SiteID, record.VRFID, record.SiteLabel, record.VRFLabel); err != nil {
				rows.Close()
				return err
			}
			subject := ownedTestTagSubject(tags.Scope{TenantID: tenant.String(), ContextID: record.ContextID}, id, name, target)
			candidates = append(candidates, subject)
			contexts[record.ContextID] = record
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(candidates) == 0 {
			return ctx.Err()
		}
		compiled := map[string]*tags.Snapshot{}
		for _, subject := range candidates {
			if err := ctx.Err(); err != nil {
				return err
			}
			snapshot := compiled[subject.ContextID]
			if snapshot == nil {
				snapshot, err = loadTagContextSnapshot(ctx, sc, subject.Scope, result.revision, definitions, charge)
				if err != nil {
					return err
				}
				compiled[subject.ContextID] = snapshot
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
			result.subjects[subject.ID] = ResolvedTagSubject{Scope: subject.Scope, Kind: "test", ID: subject.ID, Revision: result.revision, AsOf: result.asOf, Items: items}
		}
		contextIDs := make([]string, 0, len(contexts))
		for id := range contexts {
			contextIDs = append(contextIDs, id)
		}
		sort.Strings(contextIDs)
		for _, id := range contextIDs {
			result.contexts = append(result.contexts, contexts[id])
		}
		return ctx.Err()
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
