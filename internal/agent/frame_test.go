// SPDX-License-Identifier: LicenseRef-probectl-TBD

package agent

import (
	"encoding/json"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/canary"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
)

func TestResultEnvelopeVersionedAndLegacyDecodes(t *testing.T) {
	current := testResultEnvelope("tenant-1", "agent-1", "current-result")
	frame := mustMarshalResultEnvelope(t, current)

	var raw map[string]any
	if err := json.Unmarshal(frame, &raw); err != nil {
		t.Fatal(err)
	}
	gotRaw, ok := raw["schema_version"].(float64)
	if !ok {
		t.Fatalf("schema_version missing or not numeric in %v", raw)
	}
	if got := uint32(gotRaw); got != resultEnvelopeSchemaVersion {
		t.Fatalf("schema_version = %d, want %d", got, resultEnvelopeSchemaVersion)
	}
	currentResult := decodeFrameResult(t, frame)
	if currentResult.GetTenantId() != "tenant-1" || currentResult.GetAgentId() != "agent-1" || currentResult.GetResultId() != "current-result" {
		t.Fatalf("current frame decoded to %+v", currentResult)
	}

	legacy := current
	legacy.SchemaVersion = 0
	legacy.ResultID = "legacy-result"
	legacyFrame := mustMarshalResultEnvelope(t, legacy)
	raw = map[string]any{}
	if err := json.Unmarshal(legacyFrame, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["schema_version"]; ok {
		t.Fatal("legacy frame unexpectedly emitted schema_version")
	}
	legacyResult := decodeFrameResult(t, legacyFrame)
	if legacyResult.GetResultId() != "legacy-result" || legacyResult.GetCanaryType() != "noop" {
		t.Fatalf("legacy frame decoded to %+v", legacyResult)
	}
}

func TestFrameToRequestRejectsFutureVersion(t *testing.T) {
	future := testResultEnvelope("tenant-1", "agent-1", "future-result")
	future.SchemaVersion = resultEnvelopeSchemaVersion + 1

	_, err := frameToRequest(mustMarshalResultEnvelope(t, future))
	if !errors.Is(err, errUnsupportedResultEnvelopeVersion) {
		t.Fatalf("future version error = %v, want %v", err, errUnsupportedResultEnvelopeVersion)
	}
}

func TestFrameRequestsPrefixStopsBeforeMalformedFrame(t *testing.T) {
	first := mustMarshalResultEnvelope(t, testResultEnvelope("tenant-1", "agent-1", "first-result"))
	bad := testResultEnvelope("tenant-1", "agent-1", "future-result")
	bad.SchemaVersion = resultEnvelopeSchemaVersion + 1
	badFrame := mustMarshalResultEnvelope(t, bad)
	later := mustMarshalResultEnvelope(t, testResultEnvelope("tenant-1", "agent-1", "later-result"))

	requests, badIndex, err := frameRequestsPrefix([][]byte{first, badFrame, later})
	if !errors.Is(err, errUnsupportedResultEnvelopeVersion) {
		t.Fatalf("prefix error = %v, want unsupported version", err)
	}
	if badIndex != 1 {
		t.Fatalf("bad index = %d, want 1", badIndex)
	}
	if len(requests) != 1 {
		t.Fatalf("converted prefix length = %d, want 1", len(requests))
	}

	buffer, err := OpenBuffer(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, frame := range [][]byte{first, badFrame, later} {
		if err := buffer.Enqueue(frame); err != nil {
			t.Fatal(err)
		}
	}
	if err := buffer.Remove(len(requests)); err != nil {
		t.Fatal(err)
	}
	remaining, err := buffer.PeekAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 2 {
		t.Fatalf("remaining frames = %d, want 2", len(remaining))
	}
	if string(remaining[0]) != string(badFrame) || string(remaining[1]) != string(later) {
		t.Fatal("buffer removed something other than the successfully converted prefix")
	}
}

func testResultEnvelope(tenantID, agentID, resultID string) resultEnvelope {
	return resultEnvelope{
		SchemaVersion: resultEnvelopeSchemaVersion,
		TenantID:      tenantID,
		AgentID:       agentID,
		ResultID:      resultID,
		Result: canary.Result{
			Type:    "noop",
			Target:  "target-1",
			Success: true,
		},
	}
}

func mustMarshalResultEnvelope(t testing.TB, env resultEnvelope) []byte {
	t.Helper()
	frame, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func decodeFrameResult(t *testing.T, frame []byte) *resultv1.Result {
	t.Helper()
	req, err := frameToRequest(frame)
	if err != nil {
		t.Fatal(err)
	}
	var result resultv1.Result
	if err := proto.Unmarshal(req.GetPayload(), &result); err != nil {
		t.Fatal(err)
	}
	return &result
}
