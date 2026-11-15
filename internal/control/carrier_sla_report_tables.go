// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Financial values and canonical UUIDs stay exact. Only operator-entered
// description fields pass through text redaction; grouping happened before
// redaction, so two carriers cannot merge because their labels became equal.
func (s *Server) publicCarrierSLAClaim(ctx context.Context, tenant string, input flow.CarrierSLAClaimDraft, memory int64) (flow.CarrierSLAClaimDraft, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return flow.CarrierSLAClaimDraft{}, err
	}
	if int64(len(raw)) > memory/16 {
		return flow.CarrierSLAClaimDraft{}, store.ErrClientReportBudget
	}
	var out flow.CarrierSLAClaimDraft
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, err
	}
	policy := incidentEvidenceTenantPolicy(redactionPolicy(s.cfg), tenant)
	clean := func(text string) string { return ai.RedactTextForTenant(text, policy, tenant) }
	for i := range out.Groups {
		group := &out.Groups[i]
		group.Carrier = clean(group.Carrier)
		for j := range group.Circuits {
			statement := &group.Circuits[j]
			definition := &statement.Agreement.Definition
			definition.Name, definition.Reference, definition.Target.TagValue = clean(definition.Name), clean(definition.Reference), clean(definition.Target.TagValue)
			if definition.SLA != nil {
				terms := definition.SLA
				terms.Carrier, terms.CircuitID, terms.Site = clean(terms.Carrier), clean(terms.CircuitID), clean(terms.Site)
				for k := range terms.Sources {
					terms.Sources[k].AgentID = clean(terms.Sources[k].AgentID)
				}
			}
			for k := range statement.Credit.Assessments {
				assessment := &statement.Credit.Assessments[k]
				assessment.RuleID = clean(assessment.RuleID)
				assessment.MeasurementID = clean(assessment.MeasurementID)
				for index := range assessment.Citations {
					assessment.Citations[index] = clean(assessment.Citations[index])
				}
			}
			if definition.SLA != nil {
				for k := range definition.SLA.Rules {
					definition.SLA.Rules[k].ID = clean(definition.SLA.Rules[k].ID)
				}
			}
			for k := range statement.Sources {
				statement.Sources[k].AgentID = clean(statement.Sources[k].AgentID)
				statement.Sources[k].ID = clean(statement.Sources[k].ID)
			}
		}
	}
	return out, ctx.Err()
}

func (s *Server) writeCarrierSLAReportOriginal(ctx context.Context, target io.Writer, tenant string, item store.IncidentTestMeasurement, memory int64) error {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenant || item.TenantID != tenant {
		return entity.ErrScopeMismatch
	}
	policy := incidentEvidenceTenantPolicy(redactionPolicy(s.cfg), tenant)
	clean := func(text string) string { return ai.RedactTextForTenant(text, policy, tenant) }
	var icmp any
	if m := item.ICMP; m != nil {
		if int64(len(m.Responders))+int64(len(m.NetworkErrors)) > memory/4096 || m.RoundTrips != nil && int64(len(m.RoundTrips.Nanos)) > memory/256 {
			return store.ErrClientReportBudget
		}
		copy := *m
		copy.Responders = append([]string{}, m.Responders...)
		for i := range copy.Responders {
			copy.Responders[i] = clean(copy.Responders[i])
		}
		copy.NetworkErrors = append([]entity.ICMPNetworkError{}, m.NetworkErrors...)
		for i := range copy.NetworkErrors {
			copy.NetworkErrors[i].Responder = clean(copy.NetworkErrors[i].Responder)
		}
		var rtts *change.EffectOriginalRoundTrips
		if m.RoundTrips != nil {
			rtts = &change.EffectOriginalRoundTrips{Nanos: make([]string, len(m.RoundTrips.Nanos)), ExecutionNanos: strconv.FormatUint(m.RoundTrips.ExecutionNanos, 10)}
			for i, nanos := range m.RoundTrips.Nanos {
				rtts.Nanos[i] = strconv.FormatUint(nanos, 10)
			}
		}
		icmp = struct {
			entity.ICMPMeasurement
			RoundTrips *change.EffectOriginalRoundTrips `json:"round_trips,omitempty"`
		}{copy, rtts}
	}
	value := struct {
		ContextID     string               `json:"context_id"`
		EntityID      string               `json:"entity_id"`
		AgentID       string               `json:"agent_id"`
		TestID        string               `json:"test_id"`
		EvidenceID    string               `json:"evidence_id"`
		ObservationID string               `json:"observation_id"`
		CaptureDigest string               `json:"capture_digest"`
		ObservedAt    time.Time            `json:"observed_at"`
		Available     bool                 `json:"available"`
		Reason        string               `json:"reason"`
		Status        string               `json:"status"`
		ICMP          any                  `json:"icmp,omitempty"`
		Outcome       *entity.ProbeOutcome `json:"outcome,omitempty"`
	}{item.ContextID, item.EntityID, clean(item.AgentID), item.TestID, item.EvidenceID, item.ObservationID, hex.EncodeToString(item.CaptureDigest[:]), item.ObservedAt, item.Available, clean(item.Reason), incidentTestObservation(item).Status, icmp, item.Outcome}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if int64(len(raw)) > memory/8 {
		return store.ErrClientReportBudget
	}
	_, err = target.Write(raw)
	return err
}

func carrierSLAReportBounds(draft flow.CarrierSLAClaimDraft) (time.Time, time.Time, error) {
	var from, to time.Time
	for _, group := range draft.Groups {
		if group.Period.From.IsZero() || !group.Period.To.After(group.Period.From) {
			return from, to, errReportSourceRequirements
		}
		if from.IsZero() || group.Period.From.Before(from) {
			from = group.Period.From
		}
		if group.Period.To.After(to) {
			to = group.Period.To
		}
	}
	if from.IsZero() {
		return from, to, errReportSourceRequirements
	}
	return from, to, nil
}

func carrierSLAReportTables(ctx context.Context, capture *reportFlowCapture, memory int64) ([]reporting.CSVTable, error) {
	if capture == nil || capture.claimCapture == nil || capture.claimCapture.signed == nil {
		return nil, errReportSourceRequirements
	}
	claim := capture.claimCapture
	from, to, err := carrierSLAReportBounds(claim.draft)
	if err != nil {
		return nil, err
	}
	p := &reportFlowProjection{ctx: ctx, tenant: capture.TenantID, memory: memory}
	groupRows := [][]string{}
	rows := [][]string{}
	for groupIndex, group := range claim.draft.Groups {
		exact := "unknown"
		if group.ExactCredit != nil {
			exact = *group.ExactCredit
		}
		row := []string{strconv.Itoa(groupIndex), group.Carrier, group.Currency, group.Period.From.Format(time.RFC3339Nano), group.Period.To.Format(time.RFC3339Nano), group.Period.Timezone, strconv.Itoa(group.Period.BillingDay), strconv.FormatBool(group.Complete), exact, group.KnownCreditLowerBound, claim.packageID}
		if err := chargeClientReportCells(p, row); err != nil {
			return nil, err
		}
		groupRows = append(groupRows, row)

		for _, statement := range group.Circuits {
			for _, breach := range statement.Credit.Assessments {
				raw, err := json.Marshal(breach)
				if err != nil {
					return nil, err
				}
				row := []string{strconv.Itoa(groupIndex), group.Carrier, group.Currency, group.Period.From.Format(time.RFC3339Nano), group.Period.To.Format(time.RFC3339Nano), statement.Agreement.ID, statement.Agreement.Version, statement.Agreement.Definition.SLA.CircuitID, string(raw), claim.packageID}
				if err := chargeClientReportCells(p, row); err != nil {
					return nil, err
				}
				rows = append(rows, row)
			}
		}
	}
	groups := sealedClientReportTable(capture.TenantID, "carrier-sla-groups", "Conditional monthly claim totals by carrier, currency and calendar", from, to, plainClientReportColumns([]string{"group", "carrier", "currency", "period_from", "period_to", "timezone", "billing_day", "complete", "conditional_exact_credit", "known_credit_lower_bound", "signed_package_id"}), groupRows)
	groups.Source = "complete recorded circuit revisions, grouped before display redaction; human review and carrier adjudication required"
	breaches := sealedClientReportTable(capture.TenantID, "carrier-sla-assessments", "Every recorded SLA rule and measured breach", from, to, plainClientReportColumns([]string{"group", "carrier", "currency", "period_from", "period_to", "agreement_id", "version", "circuit_id", "assessment", "signed_package_id"}), rows)
	breaches.Source = "complete selected original receipt populations and recorded financial terms; unknowns retain no asserted credit"
	receipt, err := claim.signed.Receipt(ctx)
	if err != nil {
		return nil, err
	}
	// Bounded transfer chunks are not a population limit. Every byte of the
	// complete existing evidence envelope is included, in ordinal order. This
	// also avoids one enormous CSV/PDF cell for a month's original receipts.
	const chunkBytes = 12 << 10
	chunks := (receipt.Bytes + chunkBytes - 1) / chunkBytes
	encoded := reporting.CSVTable{ID: "carrier-sla-evidence", Title: "Complete offline signed claim evidence", TenantID: capture.TenantID, Source: "Concatenate decoded signed_package_base64_chunk cells in ordinal order, then use incident verify --trusted-key-fingerprint with the deployment fingerprint obtained out of band", AbsoluteFrom: from, AbsoluteTo: to, Columns: plainClientReportColumns([]string{"package_id", "package_sha256", "package_bytes", "ordinal", "chunks", "signed_package_base64_chunk"}), ExpectedRows: chunks}
	encoded.WalkRows = func(ctx context.Context, visit func([]string) error) error {
		if visit == nil {
			return entity.ErrInvalidClaim
		}
		reader, err := claim.signed.Open(ctx)
		if err != nil {
			return err
		}
		defer reader.Close()
		buffer := make([]byte, chunkBytes)
		for ordinal := int64(0); ordinal < chunks; ordinal++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			n, err := io.ReadFull(reader, buffer)
			if err != nil && !(err == io.ErrUnexpectedEOF && ordinal == chunks-1) {
				return err
			}
			if n <= 0 {
				return io.ErrUnexpectedEOF
			}
			if err := visit([]string{claim.packageID, receipt.SHA256, strconv.FormatInt(receipt.Bytes, 10), strconv.FormatInt(ordinal, 10), strconv.FormatInt(chunks, 10), base64.StdEncoding.EncodeToString(buffer[:n])}); err != nil {
				return err
			}
		}
		var sentinel [1]byte
		if n, err := reader.Read(sentinel[:]); n != 0 || err != io.EOF {
			return store.ErrReportArtifactIntegrity
		}
		return ctx.Err()
	}
	return []reporting.CSVTable{groups, breaches, encoded}, nil
}

func carrierSLAReportDocument(view *store.DashboardView, definition dashboardDefinition, tenantName, generator string, at time.Time, capture *reportFlowCapture) (reporting.Document, error) {
	if capture.claimCapture == nil {
		return reporting.Document{}, errReportSourceRequirements
	}
	from, to, err := carrierSLAReportBounds(capture.claimCapture.draft)
	if err != nil {
		return reporting.Document{}, err
	}
	provenance := append(append([]string{}, definition.Provenance...), "Offline signed carrier claim: "+capture.claimCapture.packageID)
	limitations := append(append([]string{}, definition.CoverageLimitations...), "Observed original probe populations, not complete schedule or continuous availability. Repair basis is the observed failed-completion to next-success interval. Missing sources remain unknown; no causal attribution, automatic submission or carrier adjudication.")
	return reporting.Document{Title: view.Name, Preset: view.Preset, TenantName: tenantName, TenantScope: view.TenantID, AbsoluteFrom: from, AbsoluteTo: to, GeneratedAt: at, GeneratedBy: generator, Provenance: provenance, RedactionState: definition.RedactionState, CoverageLimitations: limitations, Tables: capture.Tables}, nil
}
