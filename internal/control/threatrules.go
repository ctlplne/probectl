// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http"
	"sort"

	"github.com/ctlplne/probectl/internal/threat"
)

// ThreatRuleView is one live NDR detection rule as the API reports it: the
// merged result of the embedded defaults and the operator's detection-as-code
// overlay (DPR-075). Before this surface the only evidence that a tuned rule
// was in force was a startup log line.
type ThreatRuleView struct {
	ID             string              `json:"id"`
	Version        int                 `json:"version"`
	Kind           string              `json:"kind"`
	Name           string              `json:"name"`
	Description    string              `json:"description,omitempty"`
	Severity       string              `json:"severity"`
	BaseConfidence int                 `json:"base_confidence"`
	Suppress       string              `json:"suppress"`
	Enabled        bool                `json:"enabled"`
	Thresholds     map[string]float64  `json:"thresholds,omitempty"`
	Lists          map[string][]string `json:"lists,omitempty"`
}

// WithThreatRules exposes the live NDR rule set (and the overlay directory it
// was merged from) on GET /v1/threat/rules. rules is nil when NDR is off.
func (s *Server) WithThreatRules(rules func() []threat.DetectionRule, overlayDir string) *Server {
	s.threatRules = rules
	s.threatRulesDir = overlayDir
	return s
}

func threatRuleView(r threat.DetectionRule) ThreatRuleView {
	return ThreatRuleView{
		ID: r.ID, Version: r.Version, Kind: string(r.Kind), Name: r.Name, Description: r.Description,
		Severity: r.Severity, BaseConfidence: r.BaseConfidence, Suppress: r.Suppress.String(),
		Enabled: r.On(), Thresholds: r.Thresholds, Lists: r.Lists,
	}
}

// handleThreatRules answers "which detections are live, at which thresholds"
// — the question an auditor asks after reading that detection is tunable.
// Rules are deployment-level configuration, never tenant data, so the answer
// is the same for every tenant; the tenant check still gates the call.
func (s *Server) handleThreatRules(w http.ResponseWriter, r *http.Request) error {
	if _, err := s.principalTenant(r); err != nil {
		return err
	}
	if s.threatRules == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"rules_running": false, "overlay_dir": "", "rules": []ThreatRuleView{},
		})
		return nil
	}
	rules := s.threatRules()
	out := make([]ThreatRuleView, 0, len(rules))
	for _, rule := range rules {
		out = append(out, threatRuleView(rule))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, http.StatusOK, map[string]any{
		"rules_running": true, "overlay_dir": s.threatRulesDir, "rules": out,
	})
	return nil
}
