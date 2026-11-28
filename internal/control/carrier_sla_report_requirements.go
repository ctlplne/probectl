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
	"slices"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Only canonical selectors and one-way digests are retained. This is a future
// reader's checklist, never a financial permission or an original-sender grant.
type carrierSLAReportRequirement struct {
	AgreementID      string                        `json:"agreement_id"`
	Version          string                        `json:"version"`
	CurrentVersion   string                        `json:"current_version"`
	DefinitionDigest string                        `json:"definition_digest"`
	Period           flow.CapacityBillingPeriod    `json:"period"`
	Tests            []store.ReportTestRequirement `json:"tests"`
	EvidenceBefore   *time.Time                    `json:"evidence_before,omitempty"`
	Paths            []carrierSLAPathRequirement   `json:"paths,omitempty"`
	Flows            []carrierSLAFlowRequirement   `json:"flows,omitempty"`
}

func (r carrierSLAReportRequirement) evidencePeriod() flow.CapacityBillingPeriod {
	period := r.Period
	if r.EvidenceBefore != nil {
		period.To = *r.EvidenceBefore
	}
	return period
}

func carrierSLAReportDefinitionDigest(definition flow.CapacityAgreementDefinition) (string, error) {
	raw, err := json.Marshal(definition)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(crypto.Hash(raw)), nil
}

func validateCarrierSLAReportRequirements(ctx context.Context, tenant string, values []carrierSLAReportRequirement, memory int64) error {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenant || !reportRequirementUUID(tenant) || len(values) == 0 || memory <= 0 || int64(len(values)) > memory/4096 {
		return errReportSourceRequirements
	}
	seen := map[string]bool{}
	for _, value := range values {
		if err := ctx.Err(); err != nil {
			return err
		}
		version, err := strconv.ParseInt(value.Version, 10, 64)
		current, currentErr := strconv.ParseInt(value.CurrentVersion, 10, 64)
		key := value.AgreementID + ":" + value.Version + ":" + value.Period.From.UTC().Format(time.RFC3339Nano)
		if !reportRequirementUUID(value.AgreementID) || err != nil || version <= 0 || strconv.FormatInt(version, 10) != value.Version || currentErr != nil || current < version || strconv.FormatInt(current, 10) != value.CurrentVersion || !canonicalFlowRoutingDigest(value.DefinitionDigest) || value.Period.From.IsZero() || !value.Period.To.After(value.Period.From) || value.Period.Timezone == "" || value.Period.BillingDay < 1 || value.Period.BillingDay > 31 || len(value.Tests) == 0 || seen[key] {
			return errReportSourceRequirements
		}
		seen[key] = true
		if memory < 4096 || int64(len(value.Tests)) > (memory-4096)/2048 {
			return errReportSourceRequirements
		}
		memory -= int64(len(value.Tests))*2048 + 4096
		tests := map[string]bool{}
		for _, test := range value.Tests {
			key := test.ContextID + ":" + test.EntityID + ":" + test.AgentID + ":" + test.TestID
			if test.TenantID != tenant || !reportRequirementUUID(test.ContextID) || !reportRequirementUUID(test.EntityID) || !reportRequirementUUID(test.TestID) || test.AgentID == "" || test.SourceGeneration <= 0 || !canonicalFlowRoutingDigest(test.ConfigurationDigest) || tests[key] {
				return errReportSourceRequirements
			}
			tests[key] = true
		}
		memory, err = validateCarrierSLAEvidenceRequirements(value, memory)
		if err != nil {
			return err
		}
	}
	return ctx.Err()
}

func validateCarrierSLAEvidenceRequirements(value carrierSLAReportRequirement, memory int64) (int64, error) {
	if value.EvidenceBefore == nil {
		if len(value.Paths) > 0 || len(value.Flows) > 0 {
			return 0, errReportSourceRequirements
		}
		return memory, nil
	}
	if !value.EvidenceBefore.After(value.Period.From) || value.EvidenceBefore.After(value.Period.To) || int64(len(value.Flows)) > memory/1024 {
		return 0, errReportSourceRequirements
	}
	memory -= int64(len(value.Flows)) * 1024
	last := ""
	for _, record := range value.Flows {
		if !canonicalFlowRoutingDigest(record.Key) || !canonicalFlowRoutingDigest(record.Digest) || record.Key <= last {
			return 0, errReportSourceRequirements
		}
		last = record.Key
	}
	if len(value.Paths) == 0 {
		return memory, nil
	}
	if int64(len(value.Paths)) > memory/1024 {
		return 0, errReportSourceRequirements
	}
	memory -= int64(len(value.Paths)) * 1024
	pathTests := make(map[[2]string]bool, len(value.Tests))
	for _, test := range value.Tests {
		pathTests[[2]string{test.TestID, test.AgentID}] = true
	}
	pathIDs := make(map[[3]string]bool, len(value.Paths))
	for _, round := range value.Paths {
		key := [3]string{round.TestID, round.AgentID, round.RoundID}
		if len(round.RoundID) != 32 || !pathTests[[2]string{round.TestID, round.AgentID}] || pathIDs[key] {
			return 0, errReportSourceRequirements
		}
		roundID, err := hex.DecodeString(round.RoundID)
		if err != nil || hex.EncodeToString(roundID) != round.RoundID || !canonicalFlowRoutingDigest(round.Digest) {
			return 0, errReportSourceRequirements
		}
		pathIDs[key] = true
	}
	return memory, nil
}

func (s *Server) revalidateCarrierSLAReportScope(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, tenant string, values []carrierSLAReportRequirement, publishing bool) error {
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if actor == nil || actor.UserID == "" || actor.TenantID != tenant || sc.Tenant.String() != tenant || s.cfg == nil || s.cfg.FlowQueryLibraryBytes <= 0 {
		return errReportSourceRequirements
	}
	if err := validateCarrierSLAReportRequirements(ctx, tenant, values, budget.MemoryBytes/4); err != nil {
		return err
	}
	if err := s.authorizeCapacityAgreement(ctx, sc, actor, false); err != nil {
		return err
	}
	current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
	if err != nil {
		return err
	}
	ctx, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return err
	}
	repository := s.capacityAgreementRepository(actor, budget)
	registry := store.NewEntityRegistry(s.pool)
	// A published historical artifact remains pinned to its immutable terms.
	// Later terms do not grant access or invalidate an unchanged old period.
	// Publication additionally checks the head captured by its calculation.
	for _, value := range values {
		agreement, err := repository.CapacityAgreementInScope(ctx, sc, actor.UserID, value.AgreementID, value.Version, nil)
		if err != nil {
			return err
		}
		digest, err := carrierSLAReportDefinitionDigest(agreement.Definition)
		if err != nil {
			return err
		}
		if agreement.TenantID != tenant || publishing && agreement.CurrentVersion != value.CurrentVersion || digest != value.DefinitionDigest || !agreement.TargetPresent || !agreement.SLASourceMetadataTrusted || agreement.Definition.SLA == nil || len(agreement.Definition.SLA.Sources) != len(value.Tests) {
			return errReportSourceRequirements
		}
		for _, instant := range []time.Time{value.Period.From, value.Period.To.Add(-time.Nanosecond)} {
			terms, err := repository.CapacityAgreementInScope(ctx, sc, actor.UserID, value.AgreementID, "", &instant)
			if err != nil {
				return err
			}
			if terms.Version != value.Version {
				return errReportSourceRequirements
			}
		}
		period, err := flow.CapacityBillingPeriodAt(ctx, agreement.Definition, value.Period.From, budget.MemoryBytes/16, budget.ReadBytes/16)
		if err != nil {
			return err
		}
		if !period.From.Equal(value.Period.From) || !period.To.Equal(value.Period.To) || period.Timezone != value.Period.Timezone || period.BillingDay != value.Period.BillingDay || period.BoundaryPolicy != value.Period.BoundaryPolicy {
			return errReportSourceRequirements
		}
		if _, _, err := s.capacityBillMembersInScope(ctx, sc, principal, agreement.Definition.Target, budget.MemoryBytes/8, func(ctx context.Context, record entity.ContextRecord) error {
			if record.TenantID != tenant {
				return entity.ErrScopeMismatch
			}
			return s.authorizeClientReportTests(ctx, principal, entityContextResource(record))
		}); err != nil {
			return err
		}
		authorize := func(ctx context.Context, record entity.ContextRecord, member store.IncidentImpactEntity, testID string) error {
			if record.TenantID != tenant || record.ContextID != member.ContextID {
				return entity.ErrScopeMismatch
			}
			resource := entityContextResource(record)
			resource["entity_id"], resource["test_id"] = member.EntityID, testID
			return s.authorizeClientReportTests(ctx, principal, resource)
		}
		selected := make([]store.IncidentConfiguredTest, 0, len(value.Tests))
		for _, test := range value.Tests {
			selected = append(selected, store.IncidentConfiguredTest{TenantID: tenant, ContextID: test.ContextID, EntityID: test.EntityID, TestID: test.TestID, AgentID: test.AgentID, SourceGeneration: test.SourceGeneration})
		}
		sources, err := registry.CarrierSLAConfiguredTestsInScope(ctx, sc, value.AgreementID, value.Version, selected, budget.MemoryBytes/8, authorize)
		if err != nil {
			return err
		}
		if err := registry.RecheckClientReportTestRequirementsInScope(ctx, sc, value.Tests, budget.MemoryBytes/8, authorize); err != nil {
			return err
		}
		if err := s.revalidateCarrierSLAPaths(ctx, sc, principal, agreement, sources, value, budget.MemoryBytes/16); err != nil {
			return err
		}
		if len(value.Flows) > 0 {
			if err := s.revalidateCarrierSLAFlows(ctx, sc, principal, agreement.Definition.Target, value, budget, publishing); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func (s *Server) revalidateCarrierSLAFlows(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, target flow.CapacityTarget, value carrierSLAReportRequirement, budget flowstore.ExplorerBudget, publishing bool) error {
	if publishing {
		ctx = store.WithReportSourceAuditLock(ctx, sc)
	}
	keys := make([]string, 0, len(value.Flows))
	for _, record := range value.Flows {
		keys = append(keys, record.Key)
	}
	records, err := s.carrierSLAFlowOriginals(ctx, sc, actor, target, value.evidencePeriod(), keys, budget, nil)
	if err != nil {
		return err
	}
	current, err := carrierSLAFlowRequirements(records)
	if err != nil {
		return err
	}
	if !slices.Equal(current, value.Flows) {
		return errReportSourceRequirements
	}
	return ctx.Err()
}
