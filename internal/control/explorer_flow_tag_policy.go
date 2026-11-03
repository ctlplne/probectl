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
	"sort"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
)

// The fourth quarter of the existing query memory envelope bounds policy
// indexes/encoding. The other three hold snapshot, projection and lookup.
// Only effective disclosure outcomes enter the digest: changing a rule value
// alone must not alter the meaning of an already materialized private page.
func (s *Server) flowTagContextAuthorization(ctx context.Context, p *auth.Principal, snapshot *store.TenantTagSnapshot, limit int64) (map[string]bool, string, error) {
	if p == nil || p.TenantID == "" || limit <= 0 {
		return nil, "", apierror.Unauthorized("tenant identity required for tag policy")
	}
	records, err := snapshot.Contexts()
	if err != nil {
		return nil, "", flowTagQueryError(err)
	}
	if int64(len(records)) > limit/512 {
		return nil, "", flowTagQueryError(store.ErrTagSnapshotBudget)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ContextID < records[j].ContextID })
	type contextDecision struct {
		ID      string `json:"id"`
		Allowed bool   `json:"allowed"`
	}
	decisions := make([]contextDecision, 0, len(records))
	allowed := make(map[string]bool, len(records))
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		if record.TenantID != p.TenantID {
			return nil, "", apierror.Unavailable("tag policy scope is unavailable")
		}
		resource := entityContextResource(record)
		disclose := true
		for _, permission := range []string{permTagsRead, permFlowRead} {
			decision, err := s.decide(ctx, p, permission, auth.RBACGlobal, resource)
			if err != nil {
				return nil, "", err
			}
			disclose = disclose && decision == auth.DecisionAllowed
		}
		allowed[record.ContextID] = disclose
		decisions = append(decisions, contextDecision{ID: record.ContextID, Allowed: disclose})
	}
	encoded, err := json.Marshal(struct {
		Domain   string            `json:"domain"`
		Tenant   string            `json:"tenant"`
		Contexts []contextDecision `json:"contexts"`
	}{"flow-tag-context-authorization/v1", p.TenantID, decisions})
	if err != nil || int64(len(encoded)) > limit {
		return nil, "", flowTagQueryError(store.ErrTagSnapshotBudget)
	}
	return allowed, hex.EncodeToString(crypto.Hash(encoded)), nil
}
