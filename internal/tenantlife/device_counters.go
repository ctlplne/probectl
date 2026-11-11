// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// WithCounterHistory attaches the independent exact-observation plane. Its
// retention follows the existing flow policy, falling back to the deployment's
// flow-retention default. Zero is the operator's explicit keep-forever choice.
func (e *Engine) WithCounterHistory(history flowstore.CounterHistory, retentionDays int) *Engine {
	e.counterHistory, e.counterRetentionDays = history, retentionDays
	return e
}

func (e *Engine) eraseTenantCounters(ctx context.Context, tenant string, att *Attestation) {
	if e.counterHistory == nil {
		return
	}
	remaining, err := e.counterHistory.DeleteCounterTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), tenant)
	if err != nil {
		att.Stores = append(att.Stores, StoreResult{Store: "device_counters", Deleted: -1, Notes: err.Error()})
		att.Complete = false
		return
	}
	att.Stores = append(att.Stores, StoreResult{Store: "device_counters", VerifiedZero: remaining == 0, Notes: "remaining=" + fmt.Sprint(remaining)})
	if remaining != 0 {
		att.Complete = false
	}
}

func (e *Engine) exportSubjectCounters(x *subjectExportContext) error {
	if e.counterHistory == nil {
		return nil
	}
	aliases := x.counterAliases
	if len(aliases) == 0 {
		aliases = []string{x.subject}
	}
	n, err := streamPlaneToTar(x.tw, "device_counters.jsonl", x.man.ExportedAt, x.redact, x.pol, func(w io.Writer) (int64, error) {
		return e.counterHistory.ExportCounterSubjects(tenancy.WithTenant(x.ctx, tenancy.ID(x.tenantID)), x.tenantID, aliases, w)
	})
	if err != nil {
		return fmt.Errorf("tenantlife: subject export device counters: %w", err)
	}
	x.man.Planes = append(x.man.Planes, SubjectPlaneResult{Plane: "device_counters", Status: SubjectStatusExported, Rows: n})
	return nil
}

func (e *Engine) sweepCounterRetention(ctx context.Context, policy retentionSweepPolicy) error {
	if e.counterHistory == nil {
		return nil
	}
	days := e.counterRetentionDays
	if configured, ok := policy.has("flows"); ok {
		days = configured
	}
	if days <= 0 {
		return nil
	}
	cutoff := e.now().Add(-time.Duration(days) * 24 * time.Hour)
	ctx = tenancy.WithTenant(ctx, tenancy.ID(policy.tenant))
	return e.runRetentionPrune(ctx, policy.tenant, "device_counters", cutoff, days, "flow_retention_policy", nil, func() (int64, error) {
		mutate := func(ctx context.Context) error {
			if err := e.counterHistory.DeleteCountersBefore(ctx, policy.tenant, cutoff); err != nil {
				return err
			}
			if e.pool == nil {
				return nil
			}
			return tenancy.InTenant(ctx, e.pool, func(ctx context.Context, scope tenancy.Scope) error {
				if err := tenancy.LockTenantAuditStream(ctx, scope.Q, policy.tenant); err != nil {
					return err
				}
				_, err := scope.Q.Exec(ctx, `DELETE FROM device_counter_capture_sources WHERE tenant_id=$1 AND poll_started_unix_nanos<$2`, policy.tenant, cutoff.UnixNano())
				return err
			})
		}
		if e.pool == nil && e.flowSnapshots == nil {
			return 0, mutate(ctx)
		}
		lifecycle := e.flowSnapshots
		if lifecycle == nil {
			lifecycle = flowsnapshot.NewLifecycle(e.pool, e.objects, tenancy.NewPostgresWriterFence(e.pool))
		}
		return 0, lifecycle.Invalidate(ctx, policy.tenant, mutate)
	})
}

// The stable directory aliases were captured before the same PostgreSQL
// erasure transaction removed them. Apply one OR selector under the source
// barrier, so matching several aliases never duplicates rows or misses an old
// username after its directory row has disappeared.
func (e *Engine) eraseSubjectCounters(ctx context.Context, tenant string, aliases []string, rep *SubjectErasureReport) {
	if e.counterHistory == nil {
		return
	}
	deleted, remaining, err := e.counterHistory.DeleteCounterSubjects(tenancy.WithTenant(ctx, tenancy.ID(tenant)), tenant, aliases)
	if err != nil {
		rep.Planes = append(rep.Planes, SubjectPlaneResult{Plane: "device_counters", Status: SubjectStatusFailed, Remaining: -1, Notes: err.Error()})
		rep.Complete = false
		return
	}
	rep.Planes = append(rep.Planes, SubjectPlaneResult{Plane: "device_counters", Status: SubjectStatusDeleted, Deleted: deleted, Remaining: remaining})
	if remaining != 0 {
		rep.Complete = false
	}
}
