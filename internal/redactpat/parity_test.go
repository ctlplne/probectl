// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package redactpat_test holds the CORPUS PARITY proof for probectl's two
// redaction engines (Foundation-Loop S-e5e1b903).
//
// The finding this closes: two engines carried parallel regex sets for the same
// shapes, so a masking fix could land in one and the other keep leaking. Sharing
// the patterns removes the drift at the source; this test is the construction
// that keeps it removed — it feeds one corpus through BOTH engines and requires
// them to agree on what is sensitive.
//
// It lives in an external test package because it must import both consumers,
// and neither consumer should ever import the other.
package redactpat_test

import (
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/redactpat"
)

// redactAI runs the remote-egress engine at its default policy.
func redactAI(s string) string {
	return ai.RedactTextForTenant(s, ai.DefaultRedaction, "tenant-parity")
}

// redactGovern runs the governance/support engine at the given policy.
func redactGovern(s string, pol govern.Policy) string {
	return govern.RedactTelemetryText(pol, s)
}

type sample struct {
	// text is the line fed to both engines, in a shape real telemetry uses.
	text string
	// secret is the substring that must not survive on either path.
	secret string
	// governPolicy is the governance policy under which this shape must be
	// masked. Parity is a claim about RECOGNITION — that both engines see the
	// same shapes — not about policy: the two boundaries are different (remote
	// egress vs. persistence inside the operator's network) and are entitled to
	// different thresholds. Zero value means the default PII floor.
	governPolicy *govern.Policy
}

func (s sample) govPolicy() govern.Policy {
	if s.governPolicy != nil {
		return *s.governPolicy
	}
	return govern.DefaultPIIPolicy()
}

// secretCorpus maps every always-masked shape to a sample of what it
// recognizes, keyed by redactpat.SecretShape.Name. The test below proves the
// corpus covers redactpat.Secrets() exhaustively: adding a new always-masked
// shape without a parity sample fails this test rather than silently shipping a
// shape proven on neither path.
var secretCorpus = map[string]sample{
	"pem_block": {
		text:   "agent config held cert -----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkq\n-----END PRIVATE KEY----- inline",
		secret: "MIIBVQIBADANBgkq",
	},
	"bearer": {
		text:   "collector rejected us: authorization: Bearer sk-live-abcdef123456789 expired",
		secret: "sk-live-abcdef123456789",
	},
	"credential_kv": {
		text:   "exporter env api_key=AKxyzSECRET9val and password: hunter22seven set",
		secret: "AKxyzSECRET9val",
	},
	"aws_access_key_id": {
		text:   "cloud importer used AKIAIOSFODNN7EXAMPLE for the metric pull",
		secret: "AKIAIOSFODNN7EXAMPLE",
	},
}

// TestSecretCorpusCoversEverySharedSecretPattern is the anti-drift half: the
// corpus must name every pattern the shared primitive declares always-masked.
func TestSecretCorpusCoversEverySharedSecretPattern(t *testing.T) {
	for _, shape := range redactpat.Secrets() {
		if _, ok := secretCorpus[shape.Name]; !ok {
			t.Fatalf("redactpat.Secrets() contains %q (%s) with no parity sample: "+
				"a new always-masked shape must be proven masked on BOTH the AI egress path "+
				"and the governance/support path before it ships", shape.Name, shape.Pattern)
		}
	}
	if len(secretCorpus) != len(redactpat.Secrets()) {
		t.Fatalf("corpus has %d samples for %d shared secret shapes: a sample outlived its shape",
			len(secretCorpus), len(redactpat.Secrets()))
	}
}

// TestSecretsMaskedByBothEngines is the parity half.
func TestSecretsMaskedByBothEngines(t *testing.T) {
	for name, s := range secretCorpus {
		t.Run(name, func(t *testing.T) {
			assertMaskedByBoth(t, s)
		})
	}
}

// identifierCorpus covers the identifier/PII classes where BOTH engines are
// required to agree. These are not policy-optional on either path: the AI
// default masks them before remote egress, and the governance PII floor masks
// them before untrusted telemetry is persisted.
var identifierCorpus = map[string]sample{
	"email": {
		text:   "alert routed to oncall@acme.example.com after the flap",
		secret: "oncall@acme.example.com",
	},
	// MAC is the one class whose THRESHOLD differs: governance classifies a
	// hardware address as Confidential, below its PII floor, while the egress
	// path masks it as PII (AIRCA-002). Recognition is identical — asserted
	// here at the policy that covers Confidential.
	"mac": {
		text:         "neighbor aa:bb:cc:dd:ee:ff aged out of the table",
		secret:       "aa:bb:cc:dd:ee:ff",
		governPolicy: &govern.Policy{RedactFrom: govern.ClassConfidential},
	},
	"ipv4": {
		text:   "loss between 10.1.2.3 and the gateway rose to 4%",
		secret: "10.1.2.3",
	},
	"ipv6": {
		text:   "edge 2001:db8::1 stopped responding to probes",
		secret: "2001:db8::1",
	},
}

func TestIdentifiersMaskedByBothEngines(t *testing.T) {
	for name, s := range identifierCorpus {
		t.Run(name, func(t *testing.T) {
			assertMaskedByBoth(t, s)
		})
	}
}

// benignCorpus is the false-positive half of parity: both engines must leave
// these intact. An engine that masks everything passes every test above and is
// useless — a support bundle with no measurements in it answers no question, and
// an RCA prompt with no evidence in it produces no root cause.
var benignCorpus = []string{
	"packet loss rose sharply after the maintenance window",
	"p99_latency_ms 412 over 15m",
	"AS64512 withdrew the prefix",
	"the change landed at 12:30 and the alarm cleared at 13:05",
	"std::vector::iterator in the stack trace",
}

func TestBenignTextSurvivesBothEngines(t *testing.T) {
	for _, text := range benignCorpus {
		t.Run(text[:min(len(text), 24)], func(t *testing.T) {
			if got := redactAI(text); got != text {
				t.Errorf("AI egress path altered benign text\n  in:  %q\n  out: %q", text, got)
			}
			if got := redactGovern(text, govern.DefaultPIIPolicy()); got != text {
				t.Errorf("governance path altered benign text\n  in:  %q\n  out: %q", text, got)
			}
		})
	}
}

// TestParityDivergesOnlyWhereTheBoundaryDiffers records the ONE class where the
// two engines are deliberately not equal, with the reason. The AI path is an
// egress boundary — an internal FQDN leaving to a third party is a service
// inventory disclosure. The governance path is a persistence boundary INSIDE the
// operator's network — masking the operator's own hostnames in their own store
// would delete the product's subject matter. Sharing the pattern and diverging
// on the policy is exactly the split internal/redactpat is built for; this test
// makes the divergence deliberate rather than accidental.
func TestParityDivergesOnlyWhereTheBoundaryDiffers(t *testing.T) {
	const host = "payments-db-3.prod.acme.internal"
	line := "latency to " + host + " doubled"

	if strings.Contains(redactAI(line), host) {
		t.Errorf("AI egress path must mask hostnames at the default policy: %q", redactAI(line))
	}
	if got := redactGovern(line, govern.DefaultPIIPolicy()); !strings.Contains(got, host) {
		t.Errorf("governance path must NOT mask bare hostnames — the operator's own telemetry "+
			"loses its subject: %q", got)
	}
}

func assertMaskedByBoth(t *testing.T, s sample) {
	t.Helper()
	if got := redactAI(s.text); strings.Contains(got, s.secret) {
		t.Errorf("AI egress path leaked %q\n  in:  %q\n  out: %q", s.secret, s.text, got)
	}
	if got := redactGovern(s.text, s.govPolicy()); strings.Contains(got, s.secret) {
		t.Errorf("governance path leaked %q\n  in:  %q\n  out: %q", s.secret, s.text, got)
	}
}
