// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"log/slog"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// refuseMisroutedShared reports whether msg, read from the SHARED lane, must
// be refused because the isolation router sends its tenant (named by the bus
// key, which every publisher sets with bus.TenantKey) to that tenant's OWN
// lane: a siloed or hybrid tenant. Every producer routes through the same
// router, so such a record came from a misrouting control plane, a stale
// producer or a forger; it is refused (fail closed, docs/guardrails.md G7-1)
// rather than accepted under its key. A pooled tenant routes to the shared
// lane and passes, even though it also owns a collector lane for strict-lane
// mode (DPR-049).
//
// The cost is the records already in flight on the shared lane when a tenant
// moves from pooled to its own lane: they are refused and counted, never
// silently rehomed. When the router cannot answer (a key that names no
// tenant, a registry outage) this layer abstains and the consumer's own
// tenant verification, which fails closed, decides. A refusal is logged and
// counted in probectl_pipeline_tenant_rejected_total.
func refuseMisroutedShared(ctx context.Context, log *slog.Logger, consumer string, msg bus.Message) bool {
	tenant := bus.TenantFromKey(msg.Key)
	if tenant == "" {
		return false
	}
	targets, err := tenancy.CurrentRouter().TargetsFor(ctx, tenant)
	if err != nil || targets.BusNamespace == "" {
		return false
	}
	noteTenantRejection()
	if log == nil {
		log = slog.Default()
	}
	log.Error("REJECTED record: its tenant is routed to its own bus lane but it arrived on the shared lane (fail closed)",
		"consumer", consumer, "tenant_id", tenant, "isolation_model", string(targets.Model),
		"own_lane_namespace", targets.BusNamespace, "topic", msg.Topic)
	return true
}
