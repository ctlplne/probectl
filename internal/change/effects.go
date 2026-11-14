// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package change

import "time"

// EffectAt preserves a routing receipt's original clock. The timeline's
// PostgreSQL observation index can be coarser than the retained source receipt;
// neither the public original row nor its source metadata is rewritten.
func EffectAt(original Event) time.Time {
	if original.Routing != nil {
		return original.Routing.ObservedAt.UTC()
	}
	return original.OccurredAt.UTC()
}

// EffectTest compares only the explicitly anchored configured source. It never
// converts a shared name/address into entity membership or a source grant.
type EffectTest struct {
	ContextID string           `json:"context_id"`
	EntityID  string           `json:"entity_id"`
	TestID    string           `json:"test_id"`
	AgentID   string           `json:"agent_id"`
	Before    EffectTestPeriod `json:"before"`
	After     EffectTestPeriod `json:"after"`
}

type EffectTestPeriod struct {
	From                  time.Time               `json:"from"`
	To                    time.Time               `json:"to"`
	Observations          []EffectTestObservation `json:"observations"`
	LossCoverage          string                  `json:"loss_coverage"`
	LatencyCoverage       string                  `json:"latency_coverage"`
	CompleteExecutions    int                     `json:"complete_executions"`
	UnavailableExecutions int                     `json:"unavailable_executions"`
	Packets               *EffectPackets          `json:"packets,omitempty"`
	LossRatio             *string                 `json:"loss_ratio,omitempty"` // exact rational over observed complete executions
	Latency               *EffectLatency          `json:"latency,omitempty"`
}

type EffectPackets struct {
	Transmitted string `json:"transmitted"`
	Replies     string `json:"replies"`
	Lost        string `json:"lost"`
}

type EffectLatency struct {
	Samples      string `json:"samples"`
	SumNanos     string `json:"sum_nanos"`
	MinimumNanos string `json:"minimum_nanos"`
	MaximumNanos string `json:"maximum_nanos"`
	MeanNanos    string `json:"mean_nanos"` // exact integer/rational, never rounded binary floating point
	TimingSource string `json:"timing_source"`
}

type EffectTestObservation struct {
	EvidenceID    string                    `json:"evidence_id"`
	ObservationID string                    `json:"observation_id"`
	CaptureDigest string                    `json:"capture_digest"`
	ObservedAt    time.Time                 `json:"observed_at"`
	Available     bool                      `json:"available"`
	Reason        string                    `json:"reason"`
	Packets       *EffectPackets            `json:"packets,omitempty"`
	RoundTrips    *EffectOriginalRoundTrips `json:"round_trips,omitempty"`
}

type EffectOriginalRoundTrips struct {
	Nanos          []string `json:"nanos"`
	ExecutionNanos string   `json:"execution_nanos"`
}
