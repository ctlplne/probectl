// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHTTPResponseEvidenceKeepsVersionedShapeAndOriginalReceipt(t *testing.T) {
	end := time.Now().UTC().Add(-time.Second)
	id := uuid.NewString()
	original := Observation{ID: uuid.NewString(), Source: SourceKey{AgentID: "owned-agent", Kind: PathAgent, SourceRef: id}, Alias: AliasKey{Kind: ConfiguredTestAlias, Value: id}, SourceRef: "probe:configured-test", ObservedAt: end,
		Outcome: &ProbeOutcome{Version: 2, DefinitionHash: strings.Repeat("a", 64), CanaryType: "http", StartedAt: end.Add(-time.Second), CompletedAt: end, HTTPResponse: &ProbeHTTPResponse{StatusCode: 503, TLSVerified: true, SameOrigin: true}}}
	got, err := original.Normalize(time.Now())
	if err != nil || got.Outcome.HTTPResponse == nil || got.Outcome.HTTPResponse == original.Outcome.HTTPResponse || got.Outcome.HTTPResponse.StatusCode != 503 {
		t.Fatal("HTTP receipt lost its version or independent body", got, err)
	}
	original.Outcome.HTTPResponse.StatusCode = 777
	if got.Outcome.HTTPResponse.StatusCode != 503 {
		t.Fatal("caller changed a normalized original response")
	}
	if _, err := original.Normalize(time.Now()); err != nil {
		t.Fatal("observed nonstandard HTTP response was narrowed", err)
	}
	for name, mutate := range map[string]func(*ProbeOutcome){
		"legacy carrying response": func(o *ProbeOutcome) { o.Version = 1 },
		"missing primary response": func(o *ProbeOutcome) { o.HTTPResponse = nil },
		"other canary type":        func(o *ProbeOutcome) { o.CanaryType = "dns" },
		"too low status":           func(o *ProbeOutcome) { o.HTTPResponse.StatusCode = 99 },
		"too high status":          func(o *ProbeOutcome) { o.HTTPResponse.StatusCode = 1000 },
		"negative status":          func(o *ProbeOutcome) { o.HTTPResponse.StatusCode = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := original
			outcome := *original.Outcome
			response := *original.Outcome.HTTPResponse
			outcome.HTTPResponse = &response
			changed.Outcome = &outcome
			mutate(&outcome)
			if _, err := changed.Normalize(time.Now()); !errors.Is(err, ErrInvalidClaim) {
				t.Fatal("invalid versioned HTTP evidence was accepted", err)
			}
		})
	}
	legacy := original
	outcome := *original.Outcome
	outcome.Version = 1
	outcome.HTTPResponse = nil
	legacy.Outcome = &outcome
	if _, err := legacy.Normalize(time.Now()); err != nil {
		t.Fatal("legacy outcome compatibility changed", err)
	}
	body, err := json.Marshal(outcome)
	if err != nil || strings.Contains(string(body), "http_response") {
		t.Fatal("legacy immutable receipt gained a new body member", err)
	}
}
