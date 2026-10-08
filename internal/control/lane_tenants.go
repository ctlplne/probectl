// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"log/slog"

	"github.com/ctlplne/probectl/internal/bus"
	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
	ebpfv1 "github.com/ctlplne/probectl/internal/gen/probectl/ebpf/v1"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
)

// bindResultTenant settles the tenant of one decoded result or RUM event
// before any consumer acts on it (docs/guardrails.md G7-1, ING-03). A
// tenant-namespaced lane names its tenant and always wins. On the shared
// pooled lane the authority is the bus key: the control plane sets it from the
// agent certificate or RUM app key, and per-principal broker ACLs scope it to
// one tenant. Any bus-credential holder can write the shared topic, so a record
// whose payload tenant differs from its key, or that carries no key, is
// refused: a key for tenant A must never place a record in tenant B's views,
// signals or incidents. The storage pipeline and the OTLP export consumer
// already made this check; every other consumer of the topic now does too.
// It reports false when the record must be dropped.
func bindResultTenant(r *resultv1.Result, msg bus.Message, laneTenant string) bool {
	if r == nil {
		return false
	}
	if laneTenant != "" {
		r.TenantId = laneTenant
		return true
	}
	key := bus.TenantFromKey(msg.Key)
	return key != "" && r.GetTenantId() == key
}

// logUnboundResult records a result bindResultTenant refused.
func logUnboundResult(log *slog.Logger, consumer string, r *resultv1.Result, msg bus.Message) {
	log.Error("REJECTED result: payload tenant disagrees with the bus key on the shared lane (ING-03, fail closed)",
		"consumer", consumer, "claimed_tenant", r.GetTenantId(), "key_tenant", bus.TenantFromKey(msg.Key), "topic", msg.Topic)
}

func stampFlowBatchLaneTenant(batch *flowv1.FlowBatch, tenant string) {
	if tenant == "" || batch == nil {
		return
	}
	for _, f := range batch.GetFlows() {
		f.TenantId = tenant
	}
}

func stampEBPFBatchLaneTenant(batch *ebpfv1.FlowBatch, tenant string) {
	if tenant == "" || batch == nil {
		return
	}
	for _, f := range batch.GetFlows() {
		f.TenantId = tenant
	}
	for _, e := range batch.GetEdges() {
		e.TenantId = tenant
	}
	for _, c := range batch.GetL7Calls() {
		c.TenantId = tenant
	}
}

func stampDeviceBatchLaneTenant(batch *devicev1.DeviceMetricBatch, tenant string) {
	if tenant == "" || batch == nil {
		return
	}
	for _, m := range batch.GetMetrics() {
		m.TenantId = tenant
	}
}

func stampDeviceCollectionOutcomeBatchLaneTenant(batch *devicev1.DeviceCollectionOutcomeBatch, tenant string) {
	if tenant == "" || batch == nil {
		return
	}
	for _, outcome := range batch.GetOutcomes() {
		outcome.TenantId = tenant
	}
}
