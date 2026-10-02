// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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
	"provider_token": {
		text:   "deploy cloned with ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789 ok",
		secret: "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
	},
	"jwt": {
		text:   "session eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c set",
		secret: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
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
	// AI-03: the dotted Cisco MAC form. Like the colon form, governance treats a
	// hardware address as Confidential (below its PII floor), so recognition is
	// asserted at the policy that covers Confidential.
	"mac_dotted": {
		text:         "cisco neighbor 001a.2b3c.4d5e learned on gi0/1",
		secret:       "001a.2b3c.4d5e",
		governPolicy: &govern.Policy{RedactFrom: govern.ClassConfidential},
	},
	// AI-03: SSN and PAN are an always-mask PII floor on BOTH paths — neither
	// leaves to a remote model nor persists verbatim in a support bundle.
	"ssn": {
		text:   "employee record ssn 123-45-6789 flagged for review",
		secret: "123-45-6789",
	},
	"pan": {
		text:   "gateway declined card 4111 1111 1111 1111 on retry",
		secret: "4111 1111 1111 1111",
	},
	// AI-03 reopen: American Express uses a 15-digit 4-6-5 grouping, not the
	// 16-digit 4-4-4-4 the first PAN pattern assumed.
	"pan_amex": {
		text:   "gateway declined card 3782 822463 10005 on retry",
		secret: "3782 822463 10005",
	},
	// AI-03 reopen #2: JCB (3528-3589, 16-digit) and Diners Club (36, 14-digit
	// 4-6-4) are two more PCI major networks the first branch set missed.
	"pan_jcb": {
		text:   "declined JCB card 3530 1113 3330 0000 at checkout",
		secret: "3530 1113 3330 0000",
	},
	"pan_diners": {
		text:   "diners card 3600 900000 0006 refused by issuer",
		secret: "3600 900000 0006",
	},
}

func TestIdentifiersMaskedByBothEngines(t *testing.T) {
	for name, s := range identifierCorpus {
		t.Run(name, func(t *testing.T) {
			assertMaskedByBoth(t, s)
		})
	}
}

// egressHardeningCorpus is the AI-03 widening: credential and token shapes that
// the original narrow patterns let through — Basic auth, snake_case/SCREAMING
// env credentials, JSON-quoted secrets, SNMP community strings, session cookies,
// and bare provider tokens. All are always-mask secret shapes, so BOTH engines
// must strip them (the governance path masks them before persistence just as the
// egress path masks them before a remote model sees them).
var egressHardeningCorpus = map[string]sample{
	"basic_auth_header": {
		text:   "collector sent authorization: Basic dXNlcjpodW50ZXIy to the gateway",
		secret: "dXNlcjpodW50ZXIy",
	},
	"aws_env_lowercase": {
		text:   "startup read aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY from env",
		secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	},
	"aws_env_screaming": {
		text:   "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY exported to the pod",
		secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	},
	"db_password_env": {
		text:   "dsn builder used db_password=hunter2hunter2 for the pool",
		secret: "hunter2hunter2",
	},
	"pg_password_env": {
		text:   "libpq picked up PGPASSWORD=hunter2hunter2 from the environment",
		secret: "hunter2hunter2",
	},
	"json_quoted_password": {
		text:   `config {"password":"Tr0ub4dor&3"} was rejected by the validator`,
		secret: "Tr0ub4dor&3",
	},
	"json_quoted_token": {
		text:   `webhook body {"token": "ghs_16C7e42F292c6912E7710c838347Ae178B4a"} logged`,
		secret: "ghs_16C7e42F292c6912E7710c838347Ae178B4a",
	},
	"snmp_community": {
		text:   "poller snmp community=Pr1vateC0mm timed out on the device",
		secret: "Pr1vateC0mm",
	},
	"cookie_session": {
		text:   "request carried Cookie: session=7f9c2ba4e88f827d616045507605853e inbound",
		secret: "7f9c2ba4e88f827d616045507605853e",
	},
	// AI-03 reopen: a DSN/connection-string password where the host is an IP or a
	// single label the host pass never touches.
	"dsn_password_ip": {
		text:   "pool dsn postgres://svc_user:Pa55w0rdSecret@10.0.0.5:5432/telemetry failed",
		secret: "Pa55w0rdSecret",
	},
	"dsn_password_single_label": {
		text:   "cache redis://default:R3disPass2@cache01:6379/0 unreachable",
		secret: "R3disPass2",
	},
	// AI-03 reopen: a non-Bearer/Basic Authorization scheme (SPNEGO/Kerberos).
	// The widened Bearer pattern must consume the scheme word and mask the
	// ticket, not mask the scheme word and leak the ticket.
	"negotiate_header": {
		text:   "upstream sent Authorization: Negotiate YIIZkQYGKwYBBQUCoIIZhTCCGYGgDQ== on connect",
		secret: "YIIZkQYGKwYBBQUCoIIZhTCCGYGgDQ==",
	},
}

func TestEgressHardeningCorpusMaskedByBoth(t *testing.T) {
	for name, s := range egressHardeningCorpus {
		t.Run(name, func(t *testing.T) {
			assertMaskedByBoth(t, s)
		})
	}
}

// TestAIEgressMasksUpperAndMixedCaseFQDNs covers the host-shape half of AI-03:
// the dotted-name pattern is now case-insensitive, so upper- and mixed-case
// FQDNs no longer leak to a remote model. This is the egress boundary's
// responsibility (an internal dotted name is a service-inventory disclosure);
// the governance path leaves bare hostnames to its column-level strategy, as
// TestParityDivergesOnlyWhereTheBoundaryDiffers records, so it is asserted on
// the AI path only.
//
// Single-label (dot-less) names are DELIBERATELY not masked: a hyphenated bare
// label (payroll-sql01) is indistinguishable from the operational identifiers
// probectl keeps for correlation — incident ids, AP names — and
// TestRedactFreeTextPIIRealisticTelemetry (internal/ai) enforces that those
// survive. Masking the FQDN is the boundary; a bare label stays so RCA is useful.
func TestAIEgressMasksUpperAndMixedCaseFQDNs(t *testing.T) {
	for _, c := range []struct{ text, host string }{
		{"node DB01.CORP.ACME.COM unreachable", "DB01.CORP.ACME.COM"},
		{"link Core-Rtr-01.NYC.Acme.net flapping", "Core-Rtr-01.NYC.Acme.net"},
	} {
		if got := redactAI(c.text); strings.Contains(got, c.host) {
			t.Errorf("AI egress path leaked FQDN %q\n  in:  %q\n  out: %q", c.host, c.text, got)
		}
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
