// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
)

func TestClientReportVerdictRetentionChargesCompleteOriginalDocuments(t *testing.T) {
	snapshot := &incidentVerdictSnapshot{}
	base, err := clientReportVerdictRetainedBytes(snapshot, incident.FaultVerdict{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	measurement := &entity.ICMPMeasurement{Version: 2, Requested: 100000, NetworkErrors: make([]entity.ICMPNetworkError, 100000)}
	for index := range measurement.NetworkErrors {
		measurement.NetworkErrors[index] = entity.ICMPNetworkError{Sequence: uint32(index), Responder: "2001:db8::1", PacketDigest: strings.Repeat("a", 64)}
	}
	snapshot.outcomes = []store.IncidentTestMeasurement{{TenantID: "tenant", ICMP: measurement}}
	charged, err := clientReportVerdictRetainedBytes(snapshot, incident.FaultVerdict{}, 0)
	if err != nil || charged-base < 64<<20 || len(snapshot.outcomes[0].ICMP.NetworkErrors) != 100000 {
		t.Fatal("private snapshot or complete network-error population disappeared from retained admission", charged-base, err)
	}
}
