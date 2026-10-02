// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
)

// TestAuditToSIEMIdentityModes is the AUD-06 regression. The SIEM copy of the
// audit log is the operator's OWN SOC feed, but it pseudonymized actor and
// target with a hard-coded PII policy, so the SOC could not attribute actions
// and no full-fidelity copy survived local retention. The identity rendering is
// now configurable (PROBECTL_SIEM_AUDIT_IDENTITY): "clear" (default) forwards
// the real actor/target identity so the SOC can attribute, while STILL scrubbing
// secrets; "pseudonymize" keeps the partial-masking policy.
func TestAuditToSIEMIdentityModes(t *testing.T) {
	ev := audit.Event{
		Seq: 9, Actor: "alice.admin@corp.example", Action: "directory.role_bind", Target: "user-7",
		Hash: "abc123", CreatedAt: time.Now(),
		Data: map[string]any{
			"granted_to": "bob.user@corp.example", // an identity data field
			"outcome":    "success",
			"token":      "hunter2-secret-value",                         // a secret, by KEY
			"note":       "issued with api_key=sk1234567890abcdefSECRET", // a secret embedded in free text
		},
	}
	redact := redactionSet(nil)

	// CLEAR (default): the real actor + the identity data field are forwarded so
	// the SOC can attribute; secrets are still gone (by key AND embedded).
	cleared := auditToSIEM("tenant-A", ev, redact, true)
	if cleared.Actor != "alice.admin@corp.example" {
		t.Errorf("AUD-06 clear: must forward the real actor, got %q", cleared.Actor)
	}
	if cleared.Target != "user-7" {
		t.Errorf("AUD-06 clear: must forward the real target, got %q", cleared.Target)
	}
	if cleared.Attributes["granted_to"] != "bob.user@corp.example" {
		t.Errorf("AUD-06 clear: must keep the identity data field attributable, got %q", cleared.Attributes["granted_to"])
	}
	if cleared.Attributes["token"] != "[redacted]" {
		t.Errorf("AUD-06 clear: a secret-keyed value must still be redacted, got %q", cleared.Attributes["token"])
	}
	if strings.Contains(cleared.Attributes["note"], "sk1234567890abcdefSECRET") {
		t.Errorf("AUD-06 clear: an embedded secret must be scrubbed even in clear mode: %q", cleared.Attributes["note"])
	}

	// PSEUDONYMIZE: actor and identity data field are masked.
	pseud := auditToSIEM("tenant-A", ev, redact, false)
	if pseud.Actor == "alice.admin@corp.example" || !strings.Contains(pseud.Actor, "*") {
		t.Errorf("AUD-06 pseudonymize: must mask the actor, got %q", pseud.Actor)
	}
	if pseud.Attributes["granted_to"] == "bob.user@corp.example" {
		t.Errorf("AUD-06 pseudonymize: must mask the identity data field, got %q", pseud.Attributes["granted_to"])
	}
	if pseud.Attributes["token"] != "[redacted]" {
		t.Errorf("AUD-06 pseudonymize: secret must still be redacted, got %q", pseud.Attributes["token"])
	}
}
