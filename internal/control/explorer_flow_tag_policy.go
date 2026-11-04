// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
)

// The fourth quarter of the query envelope bounds policy maps and encoding.
// Only disclosure outcomes enter the digest, never mutable tag values. Related
// subject permission changes invalidate materialized metadata as base context
// changes do. The version change requires old pages to be queried afresh.
func (s *Server) flowTagContextAuthorization(ctx context.Context, p *auth.Principal, snapshot *store.TenantTagSnapshot, limit int64, subjects ...string) (map[string]bool, map[string]map[string]bool, string, error) {
	if p == nil || p.TenantID == "" || limit <= 0 {
		return nil, nil, "", apierror.Unauthorized("tenant identity required for tag policy")
	}
	selected := append([]string{}, subjects...)
	slices.Sort(selected)
	selected = slices.Compact(selected)
	for _, kind := range selected {
		if kind != "device" && kind != "agent" && kind != "interface" && kind != "prefix" {
			return nil, nil, "", apierror.Unavailable("tag policy dependency is unavailable")
		}
	}
	records, err := snapshot.Contexts()
	if err != nil {
		return nil, nil, "", flowTagQueryError(err)
	}
	if int64(len(records)) > limit/1024 {
		return nil, nil, "", flowTagQueryError(store.ErrTagSnapshotBudget)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ContextID < records[j].ContextID })
	type contextDecision struct {
		ID       string `json:"id"`
		Exporter bool   `json:"exporter"`
		Device   bool   `json:"device"`
		Agent    bool   `json:"agent"`
		Prefix   bool   `json:"prefix"`
	}
	decisions := make([]contextDecision, 0, len(records))
	allowed := make(map[string]bool, len(records))
	related := map[string]map[string]bool{"device": {}, "agent": {}, "prefix": {}}
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return nil, nil, "", err
		}
		if record.TenantID != p.TenantID {
			return nil, nil, "", apierror.Unavailable("tag policy scope is unavailable")
		}
		resource := entityContextResource(record)
		disclose := true
		for _, permission := range []string{permTagsRead, permFlowRead} {
			decision, err := s.decide(ctx, p, permission, auth.RBACGlobal, resource)
			if err != nil {
				return nil, nil, "", err
			}
			disclose = disclose && decision == auth.DecisionAllowed
		}
		allowed[record.ContextID] = disclose
		for _, subject := range []struct{ kind, permission string }{{"device", "metrics.read"}, {"agent", "agent.read"}, {"prefix", "entities.read"}} {
			if !selectedTagPolicySubject(selected, subject.kind) {
				continue
			}
			decision, err := s.decide(ctx, p, subject.permission, auth.RBACGlobal, resource)
			if err != nil {
				return nil, nil, "", err
			}
			related[subject.kind][record.ContextID] = disclose && decision == auth.DecisionAllowed
		}
		decisions = append(decisions, contextDecision{record.ContextID, disclose, related["device"][record.ContextID], related["agent"][record.ContextID], related["prefix"][record.ContextID]})
	}
	// Interface metadata has the same effective source grant as devices;
	// both remain covered by the metrics.read decision already in the digest.
	related["interface"] = related["device"]
	encoded, err := json.Marshal(struct {
		Domain   string            `json:"domain"`
		Tenant   string            `json:"tenant"`
		Subjects []string          `json:"subjects"`
		Contexts []contextDecision `json:"contexts"`
	}{"flow-tag-context-authorization/v4", p.TenantID, selected, decisions})
	if err != nil || int64(len(encoded)) > limit {
		return nil, nil, "", flowTagQueryError(store.ErrTagSnapshotBudget)
	}
	if err := captureReportContextRequirements(ctx, p, records, allowed, related, selected); err != nil {
		return nil, nil, "", err
	}
	return allowed, related, hex.EncodeToString(crypto.Hash(encoded)), nil
}

// Interface metadata uses the owning device's source permission.
func selectedTagPolicySubject(selected []string, kind string) bool {
	return slices.Contains(selected, kind) || kind == "device" && slices.Contains(selected, "interface")
}
