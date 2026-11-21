// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestConfigPolicyUsesOnlyAnExactRedactedArchive(t *testing.T) {
	const owner = "2d7e8e4e-f48d-4a3c-afe7-0749bf060ae5"
	const raw = "hostname fixture\nntp server 192.0.2.12\nsnmp-server community cfg-synthetic-sentinel RO\n"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owner))
	redacted := RedactConfig(raw)
	archive := ConfigVersion{TenantID: owner, ID: "archive-a", Version: 7, Content: redacted, ContentHash: hashConfig(redacted), ObservedAt: time.Now().UTC()}
	rules := []ConfigPolicyRule{
		{ID: "clock-source", Revision: "3", Mode: ConfigRuleMustContain, Text: "ntp server "},
		{ID: "legacy-snmp", Revision: "6", Mode: ConfigRuleMustNotContain, Text: "snmp-server community"},
		{ID: "log-sink", Revision: "1", Mode: ConfigRuleMustContain, Text: "logging host 192.0.2.15"},
	}
	results, err := EvaluateConfigPolicy(ctx, archive, rules)
	if err != nil || len(results) != 3 {
		t.Fatal("the scoped redacted archive did not evaluate", err)
	}
	if results[0].State != "pass" || results[0].Matches != 1 || results[1].State != "violation" || results[1].Matches != 1 ||
		results[1].ArchiveSHA256 != archive.ContentHash || results[1].RuleRevision != "6" ||
		len(results[1].OffendingLines) != 1 || results[1].OffendingLines[0] != (ConfigPolicyLine{Number: 3, Text: "snmp-server community [redacted] RO"}) ||
		results[2].State != "violation" || results[2].Matches != 0 || len(results[2].OffendingLines) != 0 {
		t.Fatal("the findings lost their original checks and positions")
	}
	foreign := tenancy.WithTenant(t.Context(), tenancy.ID("bdda1f2d-624b-4615-9b1e-b743197ac71b"))
	if got, err := EvaluateConfigPolicy(foreign, archive, rules); got != nil || !errors.Is(err, entity.ErrScopeMismatch) {
		t.Fatal("the sibling could evaluate another tenant's configuration", err)
	}
	archive.Content, archive.ContentHash = raw, hashConfig(raw)
	unavailable, err := EvaluateConfigPolicy(ctx, archive, rules)
	if err != nil || len(unavailable) != len(rules) {
		t.Fatal("the unredacted archive did not produce an unavailable result", err)
	}
	for _, result := range unavailable {
		if result.State != "evidence_unavailable" || result.Matches != 0 || len(result.OffendingLines) != 0 {
			t.Fatal("an unredacted line reached policy results")
		}
	}
}

func TestConfigPolicyTemplatesUseOnlyCapturedActiveCommands(t *testing.T) {
	const owner = "2d7e8e4e-f48d-4a3c-afe7-0749bf060ae5"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owner))
	for _, sample := range []struct {
		name     string
		template ConfigPolicyTemplate
		content  string
		state    string
		witness  string
	}{
		{"IOS NTP configured", ConfigPolicyIOSNTP,
			"version 17.9\nntp server vrf management 192.0.2.11\nend\n", "pass", ""},
		{"IOS banner and negated NTP", ConfigPolicyIOSNTP,
			"version 17.9\nbanner motd ^C\nntp server 192.0.2.11\n^C\nno ntp server 192.0.2.12\nend\n", "violation", ""},
		{"IOS complete VTY population", ConfigPolicyIOSVTYSSH,
			"version 17.9\nline vty 0 4\n transport input ssh\n!\nline vty 5 15\n transport input none\nend\n", "pass", ""},
		{"IOS mixed VTY transports", ConfigPolicyIOSVTYSSH,
			"version 17.9\nline vty 0 4\n transport input ssh telnet\nend\n", "violation", " transport input ssh telnet"},
		{"IOS implicit VTY transport", ConfigPolicyIOSVTYSSH,
			"version 17.9\nline vty 0 4\n transport output ssh\nend\n", "evidence_unavailable", ""},
		{"IOS incomplete capture", ConfigPolicyIOSVTYSSH,
			"version 17.9\nline vty 0 4\n transport input ssh\n", "evidence_unavailable", ""},
		{"IOS SNMPv3", ConfigPolicyIOSSNMPv3,
			"version 17.9\nsnmp-server group monitoring v3 priv\nend\n", "pass", ""},
		{"IOS legacy SNMP still enabled", ConfigPolicyIOSSNMPv3,
			"version 17.9\nsnmp-server group monitoring v3 priv\nsnmp-server community cfg-synthetic-sentinel RO\nend\n",
			"violation", "snmp-server community [redacted] RO"},
		{"IOS AAA login", ConfigPolicyIOSAAA,
			"version 17.9\naaa new-model\naaa authentication login default local\nend\n", "pass", ""},
		{"IOS permissive AAA fallback", ConfigPolicyIOSAAA,
			"version 17.9\naaa new-model\naaa authentication login default local none\nend\n",
			"violation", "aaa authentication login default local none"},
		{"IOS configured remote logging", ConfigPolicyIOSLogging,
			"version 17.9\nlogging host 192.0.2.33\nend\n", "pass", ""},
		{"IOS missing remote logging", ConfigPolicyIOSLogging,
			"version 17.9\nlogging buffered 10240\nend\n", "violation", ""},
		{"FRR logging", ConfigPolicyFRRLogging,
			"frr version 10.3\nfrr defaults traditional\nlog syslog informational\n!\n", "pass", ""},
		{"FRR disabled logging", ConfigPolicyFRRLogging,
			"frr version 10.3\nno log syslog\n! log file /var/log/frr/nothing\n", "violation", ""},
		{"chrony directly configured source", ConfigPolicyChronyNTP,
			"driftfile /var/lib/chrony/drift\n  PoOl time.lab.example iburst\n", "pass", ""},
		{"chrony commented source", ConfigPolicyChronyNTP,
			"driftfile /var/lib/chrony/drift\n  ! server time.lab.example\n", "violation", ""},
		{"chrony incomplete source set", ConfigPolicyChronyNTP,
			"driftfile /var/lib/chrony/drift\nsourcedir /etc/chrony/sources.d\n", "evidence_unavailable", ""},
	} {
		t.Run(sample.name, func(t *testing.T) {
			redacted := RedactConfig(sample.content)
			archive := ConfigVersion{TenantID: owner, ID: "capture", Version: 1, Content: redacted,
				ContentHash: hashConfig(redacted), ObservedAt: time.Now().UTC()}
			results, err := EvaluateConfigPolicy(ctx, archive, []ConfigPolicyRule{
				{ID: "template-policy", Revision: "1", Mode: ConfigRuleTemplate, Template: sample.template},
			})
			if err != nil || len(results) != 1 || results[0].State != sample.state {
				t.Fatalf("template state want %q, got %+v, %v", sample.state, results, err)
			}
			if sample.witness != "" && (len(results[0].OffendingLines) != 1 || results[0].OffendingLines[0].Text != sample.witness ||
				results[0].OffendingLines[0].Number != 3) {
				t.Fatal("the verdict lost the redacted source line or original position", results[0].OffendingLines)
			}
		})
	}
}
