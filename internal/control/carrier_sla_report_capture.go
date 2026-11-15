// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type carrierSLAReportCapture struct {
	draft       flow.CarrierSLAClaimDraft
	publication func(context.Context) error
	signed      *reporting.BodyStage
	packageID   string
}

// A report has one fairness admission, retained until the rendered body is
// either published or discarded. It never enters a second public operation.
func (s *Server) captureCarrierSLAReport(ctx context.Context, actor *auth.Principal, definition reporting.CarrierSLAReportDefinition, at time.Time) (_ *reportFlowCapture, resultErr error) {
	phase := "admission"
	defer func() {
		if resultErr != nil {
			resultErr = fmt.Errorf("carrier SLA report %s: %w", phase, resultErr)
		}
	}()
	bound, ok := tenancy.FromContext(ctx)
	if !ok || actor == nil || actor.UserID == "" || actor.TenantID != bound.String() {
		return nil, entity.ErrScopeMismatch
	}
	if s.pool == nil || s.cfg == nil || s.cfg.FlowQueryLibraryBytes <= 0 || s.fairnessGate == nil || len(s.evidenceSigningKey) == 0 {
		return nil, apierror.Unavailable("signed financial report storage, admission or signing is unavailable")
	}
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := budget.Validate(); err != nil {
		return nil, err
	}
	if s.requireMFA && !actor.MFASatisfied {
		return nil, apierror.Forbidden("multi-factor authentication required")
	}
	ctx, err := bindFlowRoleContext(auth.WithPrincipal(ctx, actor), actor)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	if err := s.currentCapacityAgreementActor(ctx, actor, false); err != nil {
		cancel()
		return nil, err
	}
	release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
	if err != nil {
		cancel()
		return nil, tagQueryAdmissionError(err)
	}
	var signed *reporting.BodyStage
	close := func() {
		if signed != nil {
			_ = signed.Close()
		}
		release()
		cancel()
	}
	defer func() {
		if resultErr != nil {
			close()
		}
	}()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "/v1/dashboard-reports", nil)
	if err != nil {
		return nil, err
	}
	op := withCarrierSLAClaimBudget(capacityAgreementOperation{request: request, actor: actor, budget: budget, store: s.capacityAgreementRepository(actor, budget)})
	phase = "financial selection"
	input, err := s.resolveCarrierSLAReportSelections(ctx, op, definition, at)
	if err != nil {
		return nil, err
	}
	retained := make([]carrierSLAClaimRequirement, 0, len(input.Selections))
	op.captureSLA = func(agreement flow.CapacityAgreement, sources []store.IncidentConfiguredTest) {
		retained = append(retained, carrierSLAClaimRequirement{agreement, sources})
	}
	phase = "original calculation"
	draft, publication, err := s.prepareCarrierSLAClaim(op, input)
	if err != nil {
		return nil, err
	}
	phase = "source requirements"
	requirements := make([]carrierSLAReportRequirement, 0, len(retained))
	for index, value := range retained {
		digest, err := carrierSLAReportDefinitionDigest(value.agreement.Definition)
		if err != nil {
			return nil, err
		}
		tests, err := store.ClientReportTestRequirements(value.sources)
		if err != nil {
			return nil, err
		}
		selectedAt, err := time.Parse(time.RFC3339Nano, input.Selections[index].At)
		if err != nil {
			return nil, err
		}
		period, err := flow.CapacityBillingPeriodAt(ctx, value.agreement.Definition, selectedAt, budget.MemoryBytes/16, budget.ReadBytes/16)
		if err != nil {
			return nil, err
		}
		requirements = append(requirements, carrierSLAReportRequirement{value.agreement.ID, value.agreement.Version, value.agreement.CurrentVersion, digest, period, tests})
	}
	if err := validateCarrierSLAReportRequirements(ctx, actor.TenantID, requirements, budget.MemoryBytes/4); err != nil {
		return nil, err
	}
	phase = "complete original stage"
	originals, err := s.stageCarrierSLAReportOriginals(ctx, op, draft, retained, requirements)
	if err != nil {
		return nil, err
	}
	defer originals.Close()
	phase = "public financial projection"
	public, err := s.publicCarrierSLAClaim(ctx, actor.TenantID, draft, budget.MemoryBytes/16)
	if err != nil {
		return nil, err
	}
	phase = "signature"
	signed, packageID, err := s.signCarrierSLAReport(ctx, actor.TenantID, public, originals, budget)
	if err != nil {
		return nil, err
	}
	capture := &reportFlowCapture{TenantID: actor.TenantID, Claims: requirements, release: close,
		claimCapture: &carrierSLAReportCapture{draft: public, publication: publication, signed: signed, packageID: packageID}}
	phase = "report tables"
	capture.Tables, err = carrierSLAReportTables(ctx, capture, budget.MemoryBytes/16)
	if err != nil {
		return nil, err
	}
	return capture, nil
}

func (s *Server) resolveCarrierSLAReportSelections(ctx context.Context, op capacityAgreementOperation, definition reporting.CarrierSLAReportDefinition, at time.Time) (flow.CarrierSLAClaimRequest, error) {
	input := flow.CarrierSLAClaimRequest{Selections: make([]flow.CarrierSLASelection, 0, len(definition.Selections))}
	if len(definition.Selections) == 0 || int64(len(definition.Selections)) > op.budget.MemoryBytes/4096 {
		return input, flow.ErrCarrierSLAInput
	}
	err := tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		for _, selection := range definition.Selections {
			item, err := op.store.CapacityAgreementInScope(ctx, sc, op.actor.UserID, selection.AgreementID, selection.Version, nil)
			if err != nil {
				return err
			}
			instant := selection.At
			if instant == "" {
				period, err := flow.CapacityBillingPeriodAt(ctx, item.Definition, at, op.budget.MemoryBytes/16, op.budget.ReadBytes/16)
				if err != nil {
					return err
				}
				instant = period.From.Add(-time.Nanosecond).UTC().Format(time.RFC3339Nano)
			}
			input.Selections = append(input.Selections, flow.CarrierSLASelection{AgreementID: selection.AgreementID, Version: selection.Version, At: instant})
		}
		return ctx.Err()
	})
	return input, err
}

// Encode every original from the approved historical reader, and independently
// accumulate that same streamed population before accepting its signed stage.
// No display page, breach-only filter or unsuccessful-only subset is used.
func (s *Server) stageCarrierSLAReportOriginals(ctx context.Context, op capacityAgreementOperation, draft flow.CarrierSLAClaimDraft, retained []carrierSLAClaimRequirement, requirements []carrierSLAReportRequirement) (*reporting.BodyStage, error) {
	limits := reporting.BodyStageLimits{Bytes: op.budget.MemoryBytes/8 - (1 << 20), MemoryBytes: op.budget.MemoryBytes / 8}
	stage, _, err := reporting.StageBody(ctx, op.actor.TenantID, limits, func(target io.Writer) error {
		if _, err := io.WriteString(target, `{"contract_version":"probectl-carrier-sla-originals/v1","selections":[`); err != nil {
			return err
		}
		for index, value := range retained {
			statement, ok := carrierSLAReportStatement(draft, value.agreement.ID, value.agreement.Version, requirements[index].Period.From)
			if !ok {
				return errReportSourceRequirements
			}
			if index > 0 {
				if _, err := io.WriteString(target, ","); err != nil {
					return err
				}
			}
			header, err := json.Marshal(struct {
				AgreementID string                     `json:"agreement_id"`
				Version     string                     `json:"version"`
				Period      flow.CapacityBillingPeriod `json:"period"`
			}{value.agreement.ID, value.agreement.Version, statement.Period})
			if err != nil {
				return err
			}
			if _, err := target.Write(header[:len(header)-1]); err != nil {
				return err
			}
			if _, err := io.WriteString(target, `,"measurements":[`); err != nil {
				return err
			}
			accumulator, err := newCarrierSLAAccumulator(ctx, value.sources, statement.Period.From, statement.Period.To, op.budget.MemoryBytes/8, op.budget.ReadBytes)
			if err != nil {
				return err
			}
			count := int64(0)
			err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
				if err := s.revalidateCarrierSLAClaimInScope(ctx, sc, op, value); err != nil {
					return err
				}
				limits := store.ConfiguredMeasurementScanBudget{MemoryBytes: op.budget.MemoryBytes / 16, ReadBytes: op.budget.ReadBytes, ReadRows: int64(op.budget.ReadRows), ChargeRead: op.chargeRead}
				return store.NewEntityRegistry(s.pool).WalkConfiguredTestMeasurementsInScope(ctx, sc, value.sources, statement.Period.From, statement.Period.To, limits, func(item store.IncidentTestMeasurement) error {
					if err := accumulator.observe(ctx, item); err != nil {
						return err
					}
					if count > 0 {
						if _, err := io.WriteString(target, ","); err != nil {
							return err
						}
					}
					count++
					return s.writeCarrierSLAReportOriginal(ctx, target, op.actor.TenantID, item, op.budget.MemoryBytes/64)
				})
			})
			if err != nil {
				return err
			}
			accumulator.partial = statement.AsOf.Before(statement.Period.To)
			credit, populations, err := accumulator.finish(ctx, *value.agreement.Definition.SLA, op.budget.MemoryBytes/16, op.budget.ReadBytes/4)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(credit, statement.Credit) || !reflect.DeepEqual(populations, statement.Sources) {
				return apierror.Conflict("complete SLA originals changed while signing; retry")
			}
			if _, err := io.WriteString(target, "]}"); err != nil {
				return err
			}
		}
		_, err := io.WriteString(target, "]}")
		return err
	})
	return stage, err
}

func carrierSLAReportStatement(draft flow.CarrierSLAClaimDraft, id, version string, from time.Time) (flow.CarrierSLAStatement, bool) {
	var result flow.CarrierSLAStatement
	found := false
	for _, group := range draft.Groups {
		for _, statement := range group.Circuits {
			if statement.Agreement.ID == id && statement.Agreement.Version == version && statement.Period.From.Equal(from) {
				if found {
					return result, false
				}
				result = statement
				found = true
			}
		}
	}
	return result, found
}

func (s *Server) signCarrierSLAReport(ctx context.Context, tenant string, draft flow.CarrierSLAClaimDraft, originals *reporting.BodyStage, budget flowstore.ExplorerBudget) (*reporting.BodyStage, string, error) {
	claim, err := json.Marshal(draft)
	if err != nil {
		return nil, "", err
	}
	claimStage, _, err := reporting.StageBody(ctx, tenant, reporting.BodyStageLimits{Bytes: budget.MemoryBytes / 16, MemoryBytes: budget.MemoryBytes/16 + (1 << 20)}, func(target io.Writer) error { _, err := target.Write(claim); return err })
	if err != nil {
		return nil, "", err
	}
	defer claimStage.Close()
	packageID, err := crypto.UUIDv4()
	if err != nil {
		return nil, "", err
	}
	from, to, err := carrierSLAReportBounds(draft)
	if err != nil {
		return nil, "", err
	}
	manifest := evidence.Manifest{Contract: evidence.ContractVersion, Profile: "carrier-sla", PackageID: "pkg_" + packageID, TenantScopeDigest: hex.EncodeToString(crypto.Hash([]byte("probectl.carrier-sla.tenant.v1:" + tenant))), CreatedAt: draft.GeneratedAt, Window: evidence.Window{From: from, To: to}, Redaction: "tenant policy; canonical source identities and exact financial measurements retained", Evidence: []evidence.Record{}, Statements: []evidence.Statement{}}
	sources := make([]evidence.AttachmentSource, 0, 2)
	for index, stage := range []*reporting.BodyStage{claimStage, originals} {
		receipt, err := stage.Receipt(ctx)
		if err != nil {
			return nil, "", err
		}
		digest := evidence.DigestAlgorithm + ":" + receipt.SHA256
		id, summary := "claim", "Complete grouped financial draft and recorded terms"
		if index == 1 {
			id, summary = "originals", "Complete selected historical receipt population, including unknowns"
		}
		manifest.Evidence = append(manifest.Evidence, evidence.Record{ID: id, Kind: "carrier_sla." + id, Summary: summary, State: evidence.StateObserved, AttachmentDigest: digest, Provenance: evidence.Provenance{Source: "tenant_authorized_recorded_terms_and_original_receipts", VantageID: "selected_configured_sources", VantageOwner: "operator", TrustTier: "authenticated_evidence", Independence: "same_operator", CapturedAt: draft.GeneratedAt, Freshness: "historical_under_current_authority", ClockQuality: "original_receipt_clocks", MissingIntervals: []evidence.MissingInterval{}}})
		sources = append(sources, evidence.AttachmentSource{Digest: digest, MediaType: "application/json", Bytes: receipt.Bytes, Open: stage.Open})
	}
	manifest.Statements = append(manifest.Statements, evidence.Statement{ID: "review", Class: "inference", Text: "Draft credits follow the recorded terms and observed original populations; human review and carrier adjudication are required. This is not continuous coverage, causal attribution, or a submitted claim.", EvidenceIDs: []string{"claim", "originals"}})
	signed, _, err := reporting.StageBody(ctx, tenant, reporting.BodyStageLimits{Bytes: budget.MemoryBytes/4 - (1 << 20), MemoryBytes: budget.MemoryBytes / 4}, func(target io.Writer) error {
		return evidence.WriteSigned(ctx, target, manifest, sources, s.evidenceSigningKey)
	})
	return signed, manifest.PackageID, err
}
