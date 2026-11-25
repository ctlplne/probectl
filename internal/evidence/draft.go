// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/incident"
)

type DraftKind string

const (
	DraftCarrier   DraftKind = "carrier_ticket"
	DraftReview    DraftKind = "postmortem"
	DraftExecutive DraftKind = "executive_summary"
)

var ErrDraftClaim = errors.New("evidence: draft selection contains an unsupported claim")

type DraftSentence struct {
	Text      string          `json:"text"`
	State     State           `json:"state"`
	Citations []DraftCitation `json:"citations"`
}

type DraftSection struct {
	Name      string          `json:"name"`
	Sentences []DraftSentence `json:"sentences"`
}

type IncidentDraft struct {
	Kind      DraftKind      `json:"kind"`
	PackageID string         `json:"package_id"`
	Sections  []DraftSection `json:"sections"`
}

// DraftChoice is the selectable content given to a local model. Rendering
// accepts a selection of IDs exclusively, so the model cannot supply a claim.
type DraftChoice struct {
	ID      int    `json:"id"`
	Section string `json:"section"`
	Text    string `json:"text"`
	State   State  `json:"state"`
}

type draftFact struct {
	section string
	value   DraftSentence
}

type DraftPlan struct {
	kind      DraftKind
	packageID string
	sections  []string
	facts     []draftFact
}

func (s *DraftSource) Plan(kind DraftKind) (*DraftPlan, error) {
	if s == nil {
		return nil, ErrDraftSource
	}
	plan := &DraftPlan{kind: kind, packageID: s.manifest.PackageID}
	switch kind {
	case DraftCarrier:
		if s.manifest.Profile != "carrier" {
			return nil, ErrDraftSource
		}
		plan.sections = []string{"overview", "measurements", "routing", "handoffs", "coverage", "follow_up"}
	case DraftReview:
		plan.sections = []string{"overview", "impact", "timeline", "technical_findings", "follow_up"}
	case DraftExecutive:
		plan.sections = []string{"overview", "impact", "technical_findings", "follow_up"}
	default:
		return nil, ErrDraftClaim
	}
	if kind != DraftCarrier && s.manifest.Profile != "" {
		return nil, ErrDraftSource
	}
	window := s.manifest.Window
	if window.From.IsZero() || window.To.Before(window.From) {
		return nil, ErrDraftSource
	}
	plan.add("overview", StateObserved, fmt.Sprintf("The selected observation window runs from %s to %s.", draftTime(window.From), draftTime(window.To)), "", "/window")
	if kind == DraftCarrier {
		if err := s.planCarrierDraft(plan); err != nil {
			return nil, err
		}
		return plan, nil
	}
	plan.add("overview", StateObserved, fmt.Sprintf("The incident was recorded as %q with %q severity.", s.manifest.Incident.Status, s.manifest.Incident.Severity), "", "/incident/status", "/incident/severity")
	for _, record := range s.manifest.Evidence {
		if err := s.planIncidentDraftRecord(plan, record); err != nil {
			return nil, err
		}
	}
	if s.manifest.Incident.SignalsTruncated {
		plan.add("follow_up", StateUnknown, "Can the incident owner review the signals omitted from this signed extract?", "", "/incident/signals_truncated")
	}
	return plan, nil
}

func (s *DraftSource) planIncidentDraftRecord(plan *DraftPlan, record Record) error {
	content := s.attachments[record.ID]
	switch record.Kind {
	case "incident.impact":
		var impact incident.ImpactResponse
		if err := json.Unmarshal(content, &impact); err != nil || impact.IncidentID != s.manifest.Incident.ID {
			return ErrDraftSource
		}
		if impact.Current.ObservedTotals != nil {
			plan.add("impact", StateObserved, fmt.Sprintf("The impact export has %d attested traffic records for its current window.", impact.Current.AttestedRecords), record.ID, "/current/attested_records", "/current/from", "/current/to")
		}
		plan.add("impact", record.State, fmt.Sprintf("The impact export labels customer coverage %q.", impact.CustomerCoverage), record.ID, "/customer_coverage")
		if impact.Interpretation != "" {
			plan.add("impact", StateUnknown, fmt.Sprintf("The signed impact export qualifies these measurements as %q.", impact.Interpretation), record.ID, "/interpretation")
		}
	case "incident.fault_domain":
		var verdict incident.FaultVerdict
		if err := json.Unmarshal(content, &verdict); err != nil || verdict.IncidentID != s.manifest.Incident.ID {
			return ErrDraftSource
		}
		state := StateInferred
		if verdict.Domain == incident.FaultUnknown {
			state = StateUnknown
		}
		plan.add("technical_findings", state, fmt.Sprintf("The fault-domain evaluation lists %q with %q confidence.", verdict.Domain, verdict.Confidence), record.ID, "/domain", "/confidence")
	default:
		var signal incident.Signal
		if err := json.Unmarshal(content, &signal); err != nil || signal.TenantID != "" || signal.OccurredAt.IsZero() || record.Kind != signal.Plane+"."+signal.Kind {
			return ErrDraftSource
		}
		section := "timeline"
		if plan.kind == DraftExecutive {
			section = "technical_findings"
		}
		plan.add(section, record.State, fmt.Sprintf("At %s the %q plane recorded %q.", draftTime(signal.OccurredAt), signal.Plane, signal.Title), record.ID, "/occurred_at", "/plane", "/title")
	}
	return nil
}

func (s *DraftSource) planCarrierDraft(plan *DraftPlan) error {
	if len(s.manifest.Evidence) != 1 || s.manifest.Evidence[0].Kind != "incident.carrier" {
		return ErrDraftSource
	}
	id := s.manifest.Evidence[0].ID
	var pack incident.CarrierPack
	if err := json.Unmarshal(s.attachments[id], &pack); err != nil || pack.ContractVersion != incident.CarrierContractVersion || pack.IncidentID != s.manifest.Incident.ID {
		return ErrDraftSource
	}
	if pack.Interpretation != "" {
		plan.add("coverage", StateUnknown, fmt.Sprintf("The signed carrier package qualifies these observations as %q.", pack.Interpretation), id, "/interpretation")
	}
	for i, vantage := range pack.Vantages {
		base := "/vantages/" + strconv.Itoa(i)
		for j, sample := range vantage.Measurements.Observations {
			if sample.Available && sample.Packets != nil {
				ptr := base + "/measurements/observations/" + strconv.Itoa(j)
				plan.add("measurements", StateObserved, fmt.Sprintf("At %s test %q recorded %s packets sent and received %s in reply.", draftTime(sample.ObservedAt), vantage.TestID, sample.Packets.Transmitted, sample.Packets.Replies), id, base+"/test_id", ptr+"/observed_at", ptr+"/packets")
			}
		}
		for j, trace := range vantage.Traces {
			ptr := base + "/traces/" + strconv.Itoa(j)
			plan.add("coverage", StateObserved, fmt.Sprintf("The trace at %s names %q as its origin and %q as its window coverage.", draftTime(trace.ObservedAt), trace.Vantage, trace.WindowCoverage), id, ptr+"/observed_at", ptr+"/vantage", ptr+"/window_coverage")
		}
	}
	for i, event := range pack.Routing {
		ptr := "/routing/" + strconv.Itoa(i)
		plan.add("routing", StateObserved, fmt.Sprintf("At %s the routing source recorded %q.", draftTime(event.OccurredAt), event.Title), id, ptr+"/occurred_at", ptr+"/title")
	}
	for i, handoff := range pack.Handoffs {
		base := "/handoffs/" + strconv.Itoa(i)
		for j, sample := range handoff.Counters {
			ptr := base + "/counters/" + strconv.Itoa(j)
			plan.add("handoffs", StateObserved, fmt.Sprintf("The poll ending at %s recorded a %d-bit counter value of %s for %q on interface %q.", draftTime(sample.PollCompletedAt), sample.Width, sample.Value, sample.Metric, handoff.InterfaceID), id, base+"/interface_id", ptr)
		}
	}
	for i, missing := range pack.Coverage.Missing {
		ptr := "/coverage/missing/" + strconv.Itoa(i)
		plan.add("coverage", StateUnknown, fmt.Sprintf("The signed package lists %q as missing evidence.", missing), id, ptr)
		plan.add("follow_up", StateUnknown, fmt.Sprintf("Can the carrier provide independent observations for coverage gap %q?", missing), id, ptr)
	}
	return nil
}

func (p *DraftPlan) add(section string, state State, sentence, evidenceID string, pointers ...string) {
	citations := make([]DraftCitation, len(pointers))
	for i, pointer := range pointers {
		citations[i] = DraftCitation{EvidenceID: evidenceID, Pointer: pointer}
	}
	p.facts = append(p.facts, draftFact{section, DraftSentence{Text: sentence, State: state, Citations: citations}})
}

func draftTime(at time.Time) string { return at.UTC().Format(time.RFC3339Nano) }

func (p *DraftPlan) Choices() []DraftChoice {
	choices := make([]DraftChoice, len(p.facts))
	for i, fact := range p.facts {
		choices[i] = DraftChoice{ID: i + 1, Section: fact.section, Text: fact.value.Text, State: fact.value.State}
	}
	return choices
}

// Render accepts only IDs from this exact plan. The model cannot provide text,
// citations, a replacement section or an ordering that alters the timeline.
// Signed coverage limits survive every selection. A nil selection uses the
// deterministic builtin choices.
func (p *DraftPlan) Render(selection []int) (IncidentDraft, error) {
	selected := make([]bool, len(p.facts))
	if selection != nil {
		if len(selection) == 0 {
			return IncidentDraft{}, ErrDraftClaim
		}
		for _, choice := range selection {
			if choice <= 0 || choice > len(selected) || selected[choice-1] {
				return IncidentDraft{}, ErrDraftClaim
			}
			selected[choice-1] = true
		}
	}
	draft := IncidentDraft{Kind: p.kind, PackageID: p.packageID, Sections: make([]DraftSection, len(p.sections))}
	index := make(map[string]int, len(p.sections))
	for i, section := range p.sections {
		draft.Sections[i] = DraftSection{Name: section, Sentences: []DraftSentence{}}
		index[section] = i
	}
	for i, fact := range p.facts {
		section := &draft.Sections[index[fact.section]]
		state := fact.value.State
		required := fact.section == "overview" || state == StateUnknown || state == StateStale || state == StateUnsupported
		builtinChoice := selection == nil && (p.kind != DraftExecutive || len(section.Sentences) < 3)
		if selected[i] || required || builtinChoice {
			value := fact.value
			value.Citations = slices.Clone(value.Citations)
			section.Sentences = append(section.Sentences, value)
		}
	}
	return draft, nil
}
