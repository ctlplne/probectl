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
	"strconv"

	"github.com/ctlplne/probectl/internal/browsercanary"
	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/slo"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testspec"
)

func summarizeIncidentSLOs(ctx context.Context, tenant string, definitions []slo.SLO, sources []store.IncidentConfiguredTest, tests []incident.ImpactTest, maxBytes int64) ([]incident.ImpactSLO, error) {
	if maxBytes < 4096 || int64(len(sources))+int64(len(tests)) > maxBytes/1024 {
		return nil, flowstore.ErrExplorerBudget
	}
	bySource := make(map[incidentTestSummaryKey]store.IncidentConfiguredTest, len(sources))
	for _, source := range sources {
		if source.TenantID != tenant {
			return nil, entity.ErrScopeMismatch
		}
		key := incidentTestSummaryKey{source.ContextID, source.EntityID, source.TestID, source.AgentID}
		if _, duplicate := bySource[key]; duplicate {
			return nil, entity.ErrConflictingEvidence
		}
		bySource[key] = source
	}
	out := []incident.ImpactSLO{}
	remaining := maxBytes
	for _, definition := range definitions {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !definition.ForTenant(tenant) {
			return nil, entity.ErrScopeMismatch
		}
		body, err := json.Marshal(definition)
		if err != nil {
			return nil, err
		}
		remaining -= 2048 + 4*int64(len(body))
		if remaining < 0 {
			return nil, flowstore.ErrExplorerBudget
		}
		item := incident.ImpactSLO{Name: definition.Name, DisplayName: definition.DisplayName, Service: definition.Service,
			DefinitionDigest: hex.EncodeToString(crypto.Hash(append([]byte("probectl.incident-slo-selector.v1\n"), body...))),
			ObjectiveRatio:   strconv.FormatFloat(definition.Objective, 'g', -1, 64), Window: definition.Window.String(), Basis: "observed_failed_sli_inputs_only_not_a_rolling_budget_verdict",
			Current: incident.ImpactSLOPeriod{Sources: []incident.ImpactSLOSource{}}, Previous: incident.ImpactSLOPeriod{Sources: []incident.ImpactSLOSource{}}}
		for _, test := range tests {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			source, found := bySource[incidentTestSummaryKey{test.ContextID, test.EntityID, test.TestID, test.AgentID}]
			if !found {
				return nil, entity.ErrScopeMismatch
			}
			matched, err := incidentSLOMatchesTest(definition, source, test)
			if err != nil {
				return nil, err
			}
			if !matched {
				continue
			}
			for _, pair := range []struct {
				from incident.ImpactTestPeriod
				to   *incident.ImpactSLOPeriod
			}{{test.Current, &item.Current}, {test.Previous, &item.Previous}} {
				input := incident.ImpactSLOSource{ContextID: test.ContextID, EntityID: test.EntityID, TestID: test.TestID, AgentID: test.AgentID, EvidenceIDs: []string{}}
				seen := map[string]bool{}
				for _, observation := range pair.from.Observations {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					if observation.Status != "failed" || seen[observation.EvidenceID] {
						continue
					}
					remaining -= int64(1024 + 4*(len(test.AgentID)+len(observation.EvidenceID)))
					if remaining < 0 {
						return nil, flowstore.ErrExplorerBudget
					}
					seen[observation.EvidenceID] = true
					input.EvidenceIDs = append(input.EvidenceIDs, observation.EvidenceID)
				}
				if len(input.EvidenceIDs) > 0 {
					pair.to.FailedInputs += len(input.EvidenceIDs)
					pair.to.Sources = append(pair.to.Sources, input)
				}
			}
		}
		if item.Current.FailedInputs+item.Previous.FailedInputs > 0 {
			out = append(out, item)
		}
	}
	return out, ctx.Err()
}

func incidentSLOMatchesTest(definition slo.SLO, source store.IncidentConfiguredTest, test incident.ImpactTest) (bool, error) {
	digest, err := testspec.DefinitionHash(source.Definition)
	if err != nil {
		return false, err
	}
	if digest != test.DefinitionDigest || source.Type != test.Type {
		return false, entity.ErrConflictingEvidence
	}
	if definition.TestID != "" && definition.TestID != source.TestID || definition.CanaryType != "" && definition.CanaryType != source.Type {
		return false, nil
	}
	if definition.Target == "" {
		return definition.Matches(source.Type, "", source.TestID), nil
	}
	config := canary.Config{Type: source.Type, Target: source.Target, Params: source.Definition.Params}
	var target string
	if source.Type == browsercanary.Type {
		target, err = browsercanary.ConfiguredResultTarget(config)
	} else {
		target, err = canary.ConfiguredResultTarget(config)
	}
	if err != nil {
		return false, err
	}
	return definition.Matches(source.Type, target, source.TestID), nil
}
