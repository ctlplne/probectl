// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/a2a"
	"github.com/ctlplne/probectl/internal/canary"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
)

// CORRECT-002: the per-result id is minted before buffering and carried through
// the JSON buffer onto the proto, so a redelivered frame keeps the SAME id
// (the dedup key). A fresh mint each send would defeat dedup.
func TestResultIDSurvivesBufferRoundTrip(t *testing.T) {
	env := resultEnvelope{
		TenantID: "t-a", AgentID: "agent-1", ResultID: newResultID(),
		Result: canary.Result{Type: "icmp", Target: "10.0.0.1", Success: true},
	}
	if env.ResultID == "" {
		t.Fatal("newResultID produced an empty id")
	}

	// Buffer (JSON) → reload → proto, twice (simulating a resend): same id.
	frame, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var first, second resultEnvelope
	_ = json.Unmarshal(frame, &first)
	_ = json.Unmarshal(frame, &second)
	if envToResult(&first).GetResultId() != env.ResultID {
		t.Fatal("result id lost between buffer and proto")
	}
	if envToResult(&first).GetResultId() != envToResult(&second).GetResultId() {
		t.Fatal("resend produced a different id — dedup would fail")
	}

	// Distinct results get distinct minted ids.
	a, b := newResultID(), newResultID()
	if a == b {
		t.Fatal("newResultID must be unique per call")
	}
}

func TestA2AMeshReportKeepsExactBufferReplay(t *testing.T) {
	buffer, err := openBuffer(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	co := &Coordinator{buffer: buffer, tenantID: "t-blue", agentID: "agent-blue", log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	key := bytes.Repeat([]byte{0x42}, a2a.MeshResultKeyBytes)
	siblingKey := bytes.Repeat([]byte{0x43}, a2a.MeshResultKeyBytes)
	const session = "b0cc0a7ba6c543938485d60085b37201"
	task := &agentv1.A2ATask{SessionId: session, MeshResultKey: key}
	interrupted, cancel := context.WithCancel(t.Context())
	cancel()
	co.enqueue(interrupted, task, canary.Result{Type: "a2a", Metrics: map[string]float64{"loss.ratio": 1}})
	co.enqueue(t.Context(), task, canary.Result{
		Type: "a2a", Target: "agent-peer", Success: true, StartedAt: time.Now().UTC(),
		Metrics:    map[string]float64{"packets.received": 4, "loss.ratio": 0},
		Attributes: map[string]string{"a2a.role": "initiator", "a2a.mode": "udp"},
	})
	frames, err := buffer.peekAll()
	if err != nil || len(frames) != 1 {
		t.Fatalf("expected one stored signed report: %d, %v", len(frames), err)
	}
	if bytes.Contains(frames[0], []byte(base64.StdEncoding.EncodeToString(key))) {
		t.Fatal("task signing key leaked into the buffered result")
	}
	if bytes.Contains(frames[0], []byte(session)) {
		t.Fatal("probe credential leaked into the buffered result")
	}
	first, err := frameToRequest(frames[0])
	if err != nil {
		t.Fatal(err)
	}
	retry, err := frameToRequest(frames[0])
	if err != nil || !proto.Equal(first, retry) {
		t.Fatal("retry changed the signed request", err)
	}
	proof := first.GetA2AMeshProof()
	handle := a2a.MeshSessionHandle(session)
	if proof.GetSessionId() != handle || !a2a.VerifyMeshResult(key, handle, first.GetPayload(), proof.GetMac()) ||
		a2a.VerifyMeshResult(siblingKey, handle, first.GetPayload(), proof.GetMac()) ||
		a2a.VerifyMeshResult(key, handle, append(bytes.Clone(first.GetPayload()), 0), proof.GetMac()) {
		t.Fatal("the signature did not bind the original result and assigned reporter")
	}
	var result resultv1.Result
	if err := proto.Unmarshal(first.GetPayload(), &result); err != nil || result.GetTenantId() != co.tenantID ||
		result.GetAgentId() != co.agentID || result.GetResultId() == "" || result.GetAttributes()["a2a.role"] != "initiator" {
		t.Fatal("the signed buffer lost the reporter or original result identity", err)
	}
}
