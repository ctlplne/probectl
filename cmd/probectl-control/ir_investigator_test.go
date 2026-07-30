// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build !probectl_core

package main

import (
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/control"
)

func TestIRInvestigationAuditProjectionUsesProtectedBoundedVocabulary(
	t *testing.T,
) {
	for _, outcome := range []control.IRAttemptOutcome{
		control.IRAttemptDenied,
		control.IRAttemptIntent,
		control.IRAttemptOpenFailed,
		control.IRAttemptSucceeded,
	} {
		receipt := control.IRInvestigationReceipt{
			TenantID: "00000000-0000-0000-0000-0000000000a1",
			Actor:    "investigator@example.test",
			EventRef: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Reason:   "investigate privileged abuse",
			Outcome:  outcome,
		}
		if outcome == control.IRAttemptOpenFailed {
			receipt.ErrorClass = "key_unavailable"
		}
		target, data, attribution, err := irInvestigationAuditProjection(
			receipt,
		)
		if err != nil {
			t.Fatalf("%s projection: %v", outcome, err)
		}
		if target != receipt.EventRef ||
			data["tenant"] != receipt.TenantID ||
			data["surface"] != "audit.ir.reveal" ||
			data["outcome"] != string(outcome) ||
			attribution.TenantID != receipt.TenantID ||
			attribution.Operator != receipt.Actor ||
			attribution.Grant != receipt.EventRef ||
			attribution.Surface != "audit.ir.reveal" ||
			attribution.Outcome != string(outcome) {
			t.Fatalf("%s projection differs: target=%q data=%#v attribution=%#v",
				outcome, target, data, attribution)
		}
		wantConsent := "ir-investigator-authorized"
		if outcome == control.IRAttemptDenied {
			wantConsent = "denied"
		}
		if attribution.Consent != wantConsent ||
			data["consent"] != wantConsent {
			t.Fatalf("%s consent = %q/%v, want %q",
				outcome, attribution.Consent, data["consent"], wantConsent)
		}
	}
}

func TestIRInvestigationAuditProjectionRejectsUnboundedClassifiers(t *testing.T) {
	base := control.IRInvestigationReceipt{
		TenantID: "00000000-0000-0000-0000-0000000000a1",
		Actor:    "investigator@example.test",
		EventRef: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Reason:   "investigate privileged abuse",
		Outcome:  control.IRAttemptOpenFailed,
	}
	for name, mutate := range map[string]func(*control.IRInvestigationReceipt){
		"unknown outcome": func(receipt *control.IRInvestigationReceipt) {
			receipt.Outcome = control.IRAttemptOutcome("dependency-error-text")
		},
		"unknown error class": func(receipt *control.IRInvestigationReceipt) {
			receipt.ErrorClass = "raw postgres connection failure"
		},
		"missing actor": func(receipt *control.IRInvestigationReceipt) {
			receipt.Actor = ""
		},
		"missing tenant": func(receipt *control.IRInvestigationReceipt) {
			receipt.TenantID = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			receipt := base
			mutate(&receipt)
			if _, _, _, err := irInvestigationAuditProjection(
				receipt,
			); err == nil {
				t.Fatal("invalid investigation receipt was accepted")
			}
		})
	}
}
