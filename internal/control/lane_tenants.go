// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	devicev1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/device/v1"
	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
)

func stampResultLaneTenant(r *resultv1.Result, tenant string) {
	if tenant != "" && r != nil {
		r.TenantId = tenant
	}
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
