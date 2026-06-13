// SPDX-License-Identifier: LicenseRef-probectl-TBD

package agent

import (
	"encoding/json"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/canary"
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
	if newResultID() == newResultID() {
		t.Fatal("newResultID must be unique per call")
	}
}
