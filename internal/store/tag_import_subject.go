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
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrTagImportFactsUnavailable = errors.New("tags: current owned import facts are unavailable")

// TagImportFacts stays inside the request. No raw fact or hash is included in
// NetBoxTagTarget, persisted review state, audit properties or public previews.
type TagImportFacts struct {
	Addresses []netip.Addr `json:"-"`
	Prefix    netip.Prefix `json:"-"`
	Hostname  string       `json:"-"`
}

// NetBoxSubjectTarget must run in a tenant snapshot. It resolves all target
// kinds using storage ownership and current source authority, never a label.
func (s TagAssignments) NetBoxSubjectTarget(ctx context.Context, sc tenancy.Scope, contextID, tagID string, ref TagSubjectReference, maxBytes int64) (NetBoxTagTarget, TagImportFacts, error) {
	for _, raw := range []string{contextID, tagID} {
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil || id.String() != raw {
			return NetBoxTagTarget{}, TagImportFacts{}, tags.ErrInvalid
		}
	}
	tenant, scoped := tenancy.FromContext(ctx)
	if !scoped || tenant != sc.Tenant || sc.Tenant == "" {
		return NetBoxTagTarget{}, TagImportFacts{}, tags.ErrScopeMismatch
	}
	ref, err := normalizeTagSubjectReference(ref)
	if err != nil {
		return NetBoxTagTarget{}, TagImportFacts{}, err
	}
	used := int64(0)
	charge := func(parts ...string) error {
		amount := int64(2048)
		for _, part := range parts {
			amount += int64(len(part))
		}
		if maxBytes <= 0 || amount > maxBytes-used {
			return ErrTagSnapshotBudget
		}
		used += amount
		return nil
	}
	if err := charge(contextID, tagID, ref.ID, ref.ExporterAgentID, ref.ExporterSourceRef); err != nil {
		return NetBoxTagTarget{}, TagImportFacts{}, err
	}
	if ref.Kind == "exporter" {
		target, err := s.NetBoxExporterTarget(ctx, sc, contextID, tagID, ref.ExporterAgentID, ref.ExporterSourceRef)
		if err != nil {
			return NetBoxTagTarget{}, TagImportFacts{}, err
		}
		return target, TagImportFacts{Addresses: []netip.Addr{netip.MustParseAddr(target.ExporterSourceRef)}}, nil
	}
	target := NetBoxTagTarget{ContextID: contextID, TagID: tagID, TargetKind: ref.Kind, TargetID: ref.ID}
	var revision int64
	if err := sc.Q.QueryRow(ctx, `SELECT d.key,r.revision FROM tenant_tag_definitions d
		JOIN tenant_tag_revisions r ON r.tenant_id=d.tenant_id
		WHERE d.tenant_id=$1 AND r.tenant_id=$1 AND d.id=$2`, sc.Tenant.String(), tagID).Scan(&target.TagKey, &revision); err != nil {
		return NetBoxTagTarget{}, TagImportFacts{}, tagAssignmentError(err)
	}
	if err := charge(target.TagKey); err != nil {
		return NetBoxTagTarget{}, TagImportFacts{}, err
	}
	scope := tags.Scope{TenantID: sc.Tenant.String(), ContextID: contextID}
	subject, err := loadOwnedTagSubject(ctx, sc, scope, ref, maxBytes, charge)
	if err != nil {
		return NetBoxTagTarget{}, TagImportFacts{}, err
	}
	facts, err := tagImportSubjectFacts(ctx, sc, subject, charge)
	if err != nil {
		return NetBoxTagTarget{}, TagImportFacts{}, err
	}
	target.TagRevision = strconv.FormatInt(revision, 10)
	return target, facts, nil
}

func tagImportSubjectFacts(ctx context.Context, sc tenancy.Scope, subject tags.Subject, charge func(...string) error) (TagImportFacts, error) {
	facts := TagImportFacts{Addresses: subject.Addresses}
	if subject.Address.IsValid() {
		facts.Addresses = append(facts.Addresses, subject.Address)
	}
	switch subject.Kind {
	case "prefix":
		var network string
		if err := sc.Q.QueryRow(ctx, `SELECT COALESCE(network_prefix::text,'') FROM entities
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND kind='prefix'`, sc.Tenant.String(), subject.ContextID, subject.ID).Scan(&network); err != nil {
			return TagImportFacts{}, err
		}
		if err := charge(network); err != nil {
			return TagImportFacts{}, err
		}
		prefix, err := netip.ParsePrefix(network)
		if err != nil || prefix != prefix.Masked() {
			return TagImportFacts{}, ErrTagImportFactsUnavailable
		}
		return TagImportFacts{Prefix: prefix}, nil
	case "test":
		var target string
		if err := sc.Q.QueryRow(ctx, `SELECT t.target FROM tests t JOIN entity_test_contexts c
			ON c.tenant_id=t.tenant_id AND c.test_id=t.id
			WHERE t.tenant_id=$1 AND c.tenant_id=$1 AND t.id=$3 AND c.context_id=$2
			AND c.assigned_at<=transaction_timestamp()`, sc.Tenant.String(), subject.ContextID, subject.ID).Scan(&target); err != nil {
			return TagImportFacts{}, err
		}
		if err := charge(target); err != nil {
			return TagImportFacts{}, err
		}
		if len(facts.Addresses) == 0 {
			facts.Hostname = strings.ToLower(path.TargetHost(target))
		}
	}
	if len(facts.Addresses) == 0 && facts.Hostname == "" {
		return TagImportFacts{}, ErrTagImportFactsUnavailable
	}
	return facts, nil
}
