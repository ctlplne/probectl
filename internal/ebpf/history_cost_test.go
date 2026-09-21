// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf_test

import (
	"encoding/json"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	ebpfv1 "github.com/ctlplne/probectl/internal/gen/probectl/ebpf/v1"
	"github.com/ctlplne/probectl/internal/threat"
)

// TestRawHistoryCostFixture keeps the raw-history decision's byte assumptions
// reproducible. It deliberately measures encoded application-call history
// against one privacy-minimized latest-posture record; it is not a production
// compression or calls-per-target benchmark.
func TestRawHistoryCostFixture(t *testing.T) {
	at := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	raw, err := proto.Marshal(&ebpfv1.L7Call{
		TenantId: "tenant-scope", AgentId: "agent-01", Source: "checkout",
		Destination: "payments", DestinationPort: 443, Protocol: "http2",
		Method: "POST", Resource: "/v1/charge", Status: "200", Encrypted: true,
		StartUnixNano: at.UnixNano(), LatencyNano: int64(18 * time.Millisecond),
		RequestBytes: 812, ResponseBytes: 2048, TlsVisibility: "observed",
		TlsVersion: "1.3", TlsCipher: "TLS_AES_128_GCM_SHA256",
		TlsServerName: "payments.internal", TlsVerification: "verified",
		TlsObservationSource: "fixture", TlsHandshakeUnixNano: at.UnixNano(), TlsConfidence: 95,
	})
	if err != nil {
		t.Fatal(err)
	}
	derived, err := json.Marshal(threat.Posture{
		Target: "payments.internal:443", Source: "ebpf", TLSVersion: "1.3",
		Cipher: "TLS_AES_128_GCM_SHA256", Severity: threat.SeverityInfo,
		ObservedAt: at, State: threat.PostureObserved, Visibility: "observed",
		Capture: "fixture", Confidence: 95, Freshness: "current",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || len(derived) == 0 {
		t.Fatal("fixture encodings must be non-empty")
	}
	t.Logf("raw_l7_protobuf_bytes=%d derived_latest_posture_json_bytes=%d", len(raw), len(derived))
}
