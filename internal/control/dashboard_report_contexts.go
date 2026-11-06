// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Requirements describe the actual captured scope; they grant no authority to
// a future reader. Every recipient must pass fresh source and context checks.
type reportContextRequirement struct {
	ContextID   string            `json:"context_id"`
	Resource    map[string]string `json:"resource"`
	Permissions []string          `json:"permissions"`
}

// Role results can coexist with arbitrary user tags. Merge their actual
// captured contexts/permissions without replacing the tag requirements. A
// repeated current-authority read is idempotent, not another retained grant.
func captureReportRoleContextRequirements(ctx context.Context, p *auth.Principal, records []entity.ContextRecord, allowed map[string]bool) error {
	sink, _ := ctx.Value(reportContextCaptureKey{}).(*reportContextCapture)
	if sink == nil {
		return nil
	}
	bound, present := tenancy.FromContext(ctx)
	if p == nil || !present || bound.String() != sink.tenant || p.TenantID != sink.tenant || sink.remaining <= 0 {
		return apierror.Forbidden("report interface role context scope is unavailable")
	}
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if record.TenantID != sink.tenant || record.ContextID == "" {
			return apierror.Forbidden("report interface role context scope is unavailable")
		}
		if !allowed[record.ContextID] {
			continue
		}
		resource := entityContextResource(record)
		found := -1
		for i, existing := range sink.contexts {
			if existing.ContextID == record.ContextID {
				if !maps.Equal(existing.Resource, resource) {
					return apierror.Forbidden("report interface role context changed during capture")
				}
				found = i
				break
			}
		}
		permissions := []string{permFlowRead, "entities.read", "metrics.read", "events.read"}
		cost := int64(0)
		if found >= 0 {
			permissions = slices.Clone(sink.contexts[found].Permissions)
			for _, permission := range []string{permFlowRead, "entities.read", "metrics.read", "events.read"} {
				if !slices.Contains(permissions, permission) {
					permissions = append(permissions, permission)
					cost += 64
				}
			}
		} else {
			cost = int64(256 + len(record.ContextID)*2 + len(permissions)*64)
			for key, value := range resource {
				cost += int64(len(key)+len(value))*2 + 128
			}
		}
		if cost > sink.remaining {
			return apierror.Validation("report interface role context budget exceeded")
		}
		sort.Strings(permissions)
		if found >= 0 {
			sink.contexts[found].Permissions = permissions
		} else {
			sink.contexts = append(sink.contexts, reportContextRequirement{record.ContextID, maps.Clone(resource), permissions})
		}
		sink.remaining -= cost
	}
	sink.captured = true
	return nil
}

type reportContextCaptureKey struct{}
type reportContextCapture struct {
	tenant    string
	remaining int64
	captured  bool
	contexts  []reportContextRequirement
}

func captureReportContextRequirements(ctx context.Context, p *auth.Principal, records []entity.ContextRecord, allowed map[string]bool, related map[string]map[string]bool, selected []string) error {
	sink, _ := ctx.Value(reportContextCaptureKey{}).(*reportContextCapture)
	if sink == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	bound, ok := tenancy.FromContext(ctx)
	if p == nil || !ok || bound.String() != sink.tenant || p.TenantID != sink.tenant || sink.captured || sink.remaining <= 0 {
		return apierror.Forbidden("report metadata capture scope is unavailable")
	}
	remaining := sink.remaining
	contexts := make([]reportContextRequirement, 0)
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if record.TenantID != sink.tenant || record.ContextID == "" {
			return apierror.Forbidden("report metadata context scope is unavailable")
		}
		if !allowed[record.ContextID] {
			continue
		}
		permissions := []string{permFlowRead, permTagsRead}
		for _, subject := range []struct{ kind, permission string }{{"device", "metrics.read"}, {"agent", "agent.read"}, {"prefix", "entities.read"}} {
			if selectedTagPolicySubject(selected, subject.kind) && related[subject.kind][record.ContextID] {
				permissions = append(permissions, subject.permission)
			}
		}
		sort.Strings(permissions)
		resource := entityContextResource(record)
		cost := int64(256 + len(record.ContextID)*2 + len(permissions)*64)
		for key, value := range resource {
			cost += int64(len(key)+len(value))*2 + 128
		}
		if cost < 0 || cost > remaining {
			return apierror.Validation("report metadata requirement budget exceeded")
		}
		remaining -= cost
		captured := make(map[string]string, len(resource))
		for key, value := range resource {
			captured[strings.Clone(key)] = strings.Clone(value)
		}
		contexts = append(contexts, reportContextRequirement{ContextID: strings.Clone(record.ContextID), Resource: captured, Permissions: permissions})
	}
	sink.contexts, sink.remaining, sink.captured = contexts, remaining, true
	return nil
}
