// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"bufio"
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type ConfigRuleMode string

const (
	ConfigRuleMustContain    ConfigRuleMode = "must_contain"
	ConfigRuleMustNotContain ConfigRuleMode = "must_not_contain"
	ConfigRuleTemplate       ConfigRuleMode = "template"
)

type ConfigPolicyRule struct {
	ID       string               `json:"id"`
	Revision string               `json:"revision"`
	Mode     ConfigRuleMode       `json:"mode"`
	Text     string               `json:"text,omitempty"`
	Template ConfigPolicyTemplate `json:"template,omitempty"`
}

type ConfigPolicyLine struct {
	Number int    `json:"line_number"`
	Text   string `json:"redacted_line,omitempty"`
}

type ConfigPolicyVerdict struct {
	RuleID         string             `json:"rule_id"`
	RuleRevision   string             `json:"rule_revision"`
	ArchiveID      string             `json:"archive_id"`
	ArchiveSHA256  string             `json:"archive_sha256"`
	State          string             `json:"state"`
	Matches        int                `json:"total_matches"`
	OffendingLines []ConfigPolicyLine `json:"offending_lines,omitempty"`
}

var ErrConfigPolicyRules = errors.New("invalid or unbounded device configuration policy")

// EvaluateConfigPolicy checks literal content from the tenant-scoped archive.
// The caller owns archive acquisition, current device authority and policy
// revision. This evaluator requires a complete redacted body at its original
// digest before issuing a pass or identifying an offending line.
func EvaluateConfigPolicy(ctx context.Context, archive ConfigVersion, rules []ConfigPolicyRule) ([]ConfigPolicyVerdict, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || archive.TenantID != tenant.String() {
		return nil, entity.ErrScopeMismatch
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(rules) == 0 || len(rules) > 128 {
		return nil, ErrConfigPolicyRules
	}
	seen := make(map[string]bool, len(rules))
	verdicts := make([]ConfigPolicyVerdict, len(rules))
	for i, rule := range rules {
		if rule.ID == "" || rule.Revision == "" || seen[rule.ID] || !validConfigPolicyRule(rule) {
			return nil, ErrConfigPolicyRules
		}
		seen[rule.ID] = true
		verdicts[i] = ConfigPolicyVerdict{RuleID: rule.ID, RuleRevision: rule.Revision,
			ArchiveID: archive.ID, ArchiveSHA256: archive.ContentHash, State: "evidence_unavailable"}
	}
	const maxArchiveBytes = 2 << 20
	if archive.ID == "" || archive.Version <= 0 || archive.ObservedAt.IsZero() || len(archive.Content) == 0 ||
		len(archive.Content) > maxArchiveBytes || !utf8.ValidString(archive.Content) || strings.ContainsRune(archive.Content, 0) ||
		hashConfig(archive.Content) != archive.ContentHash || RedactConfig(archive.Content) != archive.Content {
		return verdicts, nil
	}
	if len(archive.Content)*len(rules) > 32<<20 {
		return verdicts, nil
	}
	return evaluateRedactedConfigPolicy(ctx, archive.Content, rules, verdicts)
}

func validConfigPolicyRule(rule ConfigPolicyRule) bool {
	switch rule.Mode {
	case ConfigRuleMustContain, ConfigRuleMustNotContain:
		return rule.Template == "" && len(rule.Text) <= 256 && strings.TrimSpace(rule.Text) != "" &&
			!strings.ContainsAny(rule.Text, "\r\n\x00") && utf8.ValidString(rule.Text) && RedactConfig(rule.Text) == rule.Text
	case ConfigRuleTemplate:
		return rule.Text == "" && rule.Template.dialect() != ""
	default:
		return false
	}
}

func evaluateRedactedConfigPolicy(ctx context.Context, content string, rules []ConfigPolicyRule, verdicts []ConfigPolicyVerdict) ([]ConfigPolicyVerdict, error) {
	var templateCount int
	templates := make([]configTemplateEvidence, len(rules))
	for i, rule := range rules {
		if rule.Mode == ConfigRuleTemplate {
			templates[i].template = rule.Template
			templateCount++
		}
	}
	scanner := bufio.NewScanner(strings.NewReader(content))
	// A line longer than this makes the evaluation unavailable. Returning the
	// partial result would promote an uninspected suffix to a passing policy.
	scanner.Buffer(make([]byte, 4096), 16<<10)
	var lineNumber int
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lineNumber++
		line := scanner.Text()
		var words []string
		if templateCount > 0 {
			words = strings.Fields(line)
		}
		for i, rule := range rules {
			verdict := &verdicts[i]
			if rule.Mode == ConfigRuleTemplate {
				templates[i].observe(verdict, lineNumber, line, words)
				continue
			}
			if !strings.Contains(line, rule.Text) {
				continue
			}
			verdict.Matches++
			if rule.Mode == ConfigRuleMustNotContain {
				verdict.addOffendingLine(lineNumber, line)
			}
		}
	}
	if scanner.Err() != nil {
		for i := range verdicts {
			verdicts[i].Matches, verdicts[i].OffendingLines = 0, nil
		}
		return verdicts, nil
	}
	for i, rule := range rules {
		verdict := &verdicts[i]
		if rule.Mode == ConfigRuleTemplate {
			templates[i].finish(verdict)
			continue
		}
		verdict.State = "pass"
		if (rule.Mode == ConfigRuleMustContain) != (verdict.Matches > 0) {
			verdict.State = "violation"
		}
	}
	return verdicts, ctx.Err()
}

func (v *ConfigPolicyVerdict) addOffendingLine(number int, line string) {
	if len(v.OffendingLines) < 8 {
		v.OffendingLines = append(v.OffendingLines, ConfigPolicyLine{Number: number, Text: line})
	}
}
