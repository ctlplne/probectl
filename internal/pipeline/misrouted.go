// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"errors"
	"fmt"
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
	if errors.Is(err, tenancy.ErrTenantQuarantined) {
		// DPR-369: a quarantined tenant's routing refusal is a verdict, not
		// "the router cannot answer": its record is refused (no write, no
		// export), acknowledged and counted, on every consumer.
		noteQuarantineDrop(consumer, tenant)
		return true
	}
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

// ErrLaneQuarantined holds a record on a quarantined tenant's OWN lane on the
// bus: it is returned instead of acknowledging, so the record is not
// committed and is consumed again once the tenant is released (DPR-389).
var ErrLaneQuarantined = errors.New("pipeline: the lane's tenant is quarantined; record left on the bus")

// refuseSharedOrQuarantined is the per-record lane gate every consumer runs
// first. On a tenant's own lane a quarantined tenant's record is HELD
// (ErrLaneQuarantined, no ack): the lane is normally not subscribed at all,
// and after a runtime quarantine the lane supervisor drops it at once, so
// this covers the moment in between without losing the record. On the
// shared lane it applies refuseMisroutedShared, which refuses (acks and
// counts) a quarantined tenant's record. refuse=true means acknowledge and
// count; a non-nil error means leave it unacknowledged.
func refuseSharedOrQuarantined(ctx context.Context, log *slog.Logger, consumer string, msg bus.Message, laneTenant string) (bool, error) {
	if laneTenant != "" {
		if tenancy.CheckQuarantine(laneTenant) != nil {
			return false, fmt.Errorf("%w (consumer %s, tenant %s)", ErrLaneQuarantined, consumer, laneTenant)
		}
		return false, nil
	}
	return refuseMisroutedShared(ctx, log, consumer, msg), nil
}
