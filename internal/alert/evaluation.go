// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package alert

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

const EvaluationReceiptVersion = "probectl.alert-evaluation/v1"

// EvaluationState is the deterministic evaluator state recorded when a rule
// or series changes state. It is deliberately smaller than a generic event
// model: the receipt explains alert math; it is not a log platform.
type EvaluationState string

const (
	EvaluationNoData   EvaluationState = "no_data"
	EvaluationWarming  EvaluationState = "warming"
	EvaluationNormal   EvaluationState = "normal"
	EvaluationPending  EvaluationState = "pending"
	EvaluationFiring   EvaluationState = "firing"
	EvaluationSteady   EvaluationState = "steady"
	EvaluationResolved EvaluationState = "resolved"
)

// EvaluationExpectation describes the local comparison that was enforced.
// Baseline bands carry mean/stddev/lower/upper; threshold rules carry the
// comparison and threshold. Pointers preserve meaningful zero values.
type EvaluationExpectation struct {
	Kind       RuleType   `json:"kind"`
	Comparison Comparison `json:"comparison,omitempty"`
	Threshold  *float64   `json:"threshold,omitempty"`
	Mean       *float64   `json:"mean,omitempty"`
	StdDev     *float64   `json:"stddev,omitempty"`
	Lower      *float64   `json:"lower,omitempty"`
	Upper      *float64   `json:"upper,omitempty"`
}

// EvaluationReceipt is a bounded, tenant-local explanation of one evaluator
// transition. Tenant identity is intentionally absent: the persistence sink is
// tenant-bound before this value reaches storage.
type EvaluationReceipt struct {
	ContractVersion  string                `json:"contract_version"`
	Fingerprint      string                `json:"fingerprint"`
	RuleID           string                `json:"rule_id"`
	RuleRevision     string                `json:"rule_revision"`
	State            EvaluationState       `json:"state"`
	ObservedAt       time.Time             `json:"observed_at"`
	ObservedValue    *float64              `json:"observed_value,omitempty"`
	Expectation      EvaluationExpectation `json:"expectation"`
	BreachCount      int                   `json:"breach_count"`
	RequiredBreaches int                   `json:"required_breaches"`
	WarmupSamples    int                   `json:"warmup_samples,omitempty"`
	WarmupRequired   int                   `json:"warmup_required,omitempty"`
	Reason           string                `json:"reason"`
	Labels           map[string]string     `json:"labels,omitempty"`
}

// EvaluationSink persists one receipt. Implementations are attached at the
// already tenant-bound evaluator construction seam.
type EvaluationSink func(context.Context, EvaluationReceipt) error

type evaluationDecision struct {
	breached      bool
	warming       bool
	reason        string
	expectation   EvaluationExpectation
	warmupSamples int
	warmupNeeded  int
}

func ruleRevision(rule Rule) string {
	if rule.UpdatedAt.IsZero() {
		return "unversioned"
	}
	return rule.UpdatedAt.UTC().Format(time.RFC3339Nano)
}

func receiptLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(labels))
	for key, value := range labels {
		if key == "tenant_id" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// evaluationFingerprint is a bounded opaque handle that is stable inside one
// rule. The digest input omits the ambient tenant label, and hashing goes
// through the FIPS-swappable crypto boundary. Tenant routing happens before the
// handle is ever accepted by an API or store.
func evaluationFingerprint(ruleID string, labels map[string]string) string {
	return evaluationFingerprintForKey(stateKey(ruleID, receiptLabels(labels)))
}

func noDataEvaluationFingerprint(ruleID string) string {
	return evaluationFingerprintForKey(ruleID + "|no-data")
}

func evaluationFingerprintForKey(key string) string {
	return "eval:" + hex.EncodeToString(crypto.Hash([]byte(key)))
}

func requiredBreaches(rule Rule) int {
	if rule.ForN < 1 {
		return 1
	}
	return rule.ForN
}

func floatRef(value float64) *float64 {
	return &value
}
