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
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type seasonalFlowPopulation struct {
	current map[string]anomaly.ExactSeasonalFeature
	before  map[string][]anomaly.ExactSeasonalFeature
	memory  int64
}

func projectSeasonalFlow(ctx context.Context, captured *reportFlowCapture, source reportFlowSourceRef, measure string, ends []time.Time, memory int64) (seasonalFlowPopulation, error) {
	var empty seasonalFlowPopulation
	bound, ok := tenancy.FromContext(ctx)
	if !ok || captured == nil || captured.TenantID != bound.String() {
		return empty, tenancy.ErrNoTenant
	}
	if len(ends) == 0 || len(captured.Results) != len(ends) || memory <= 0 {
		return empty, alert.ErrSeasonalSource
	}
	ordered := slices.Clone(ends)
	slices.SortFunc(ordered, time.Time.Compare)
	population := seasonalFlowPopulation{
		current: make(map[string]anomaly.ExactSeasonalFeature),
		before:  make(map[string][]anomaly.ExactSeasonalFeature),
		memory:  memory,
	}
	// Start at the latest complete query to learn the set of exact current
	// subjects. Historical periods never add a subject on their own.
	for i := len(captured.Results) - 1; i >= 0; i-- {
		record := captured.Results[i]
		if record.TenantID != bound.String() || record.ID != source.ID || record.Version != source.Version ||
			record.Period != "current" || !record.Result.Query.To.Equal(ordered[i]) ||
			record.Result.Coverage == nil || !record.Result.Coverage.CompleteInputs {
			return empty, apierror.Unavailable("complete owned flow windows are required for the baseline")
		}
		if err := population.addFlowWindow(ctx, record, measure, i == len(captured.Results)-1); err != nil {
			return empty, err
		}
	}
	return population, ctx.Err()
}

func (p *seasonalFlowPopulation) addFlowWindow(ctx context.Context, record capturedReportFlow, measure string, current bool) error {
	if record.Result.OldestInput.IsZero() {
		return ctx.Err() // the source provided no observed input for this period
	}
	condition := alert.QueryCondition{Mode: "threshold", Metric: measure, Comparison: alert.GTE, Threshold: "0"}
	if err := condition.Validate(record.Result.Query.Metrics); err != nil {
		return apierror.Validation("the measure must exist in the saved flow view").Wrap(err)
	}
	groups, err := alertResultGroups(ctx, condition, record.Result, p.memory/2)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(groups))
	for _, group := range groups {
		if err := ctx.Err(); err != nil {
			return err
		}
		if group.Dimensions["@other"] == "true" || group.Dimensions["@row_other"] == "true" || group.Dimensions["@column_other"] == "true" {
			continue // a changing residual population is not a single series
		}
		row, err := seasonalFlowFeature(record, measure, group)
		if err != nil || seen[row.Subject] {
			return alert.ErrSeasonalSource
		}
		seen[row.Subject] = true
		if !current {
			if _, ok := p.current[row.Subject]; !ok {
				continue
			}
		}
		p.memory -= 512 + int64(len(row.Subject)+len(row.Decimal)+len(row.Citation))
		if p.memory <= 0 {
			return alert.ErrSeasonalSource
		}
		if current {
			p.current[row.Subject] = row
		} else {
			p.before[row.Subject] = append(p.before[row.Subject], row)
		}
	}
	return nil
}

func seasonalFlowFeature(record capturedReportFlow, measure string, group alert.QueryGroup) (anomaly.ExactSeasonalFeature, error) {
	body, err := json.Marshal(struct {
		Context [4]string
		Group   map[string]string
	}{[4]string{record.TenantID, record.ID, record.Version, measure}, group.Dimensions})
	if err != nil {
		return anomaly.ExactSeasonalFeature{}, err
	}
	digest := crypto.Hash(body)
	if len(digest) != 32 {
		return anomaly.ExactSeasonalFeature{}, alert.ErrSeasonalSource
	}
	key := hex.EncodeToString(digest)
	end := record.Result.Query.To.UTC()
	feature := anomaly.Feature{
		TenantID: record.TenantID, Plane: "flow", Source: "saved-explorer", Subject: key,
		Metric: measure, TS: exactSeasonalObservedAt(end),
		Citation: "explorer:" + record.ID + ":" + record.Version + ":" + key + ":" + end.Format(time.RFC3339Nano),
	}
	return anomaly.ExactSeasonalFeature{Feature: feature, Decimal: group.Value}, nil
}
