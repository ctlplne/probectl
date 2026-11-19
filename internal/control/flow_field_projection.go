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
	"math/big"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Project only the top population of a bounded, pinned query result. The
// renderer's Other cell lacks a stable member identity. A distinct field or
// scope mismatch rejects both periods before exposing values.
func projectRankedFlowField(ctx context.Context, captured capturedReportFlow, expected reportFlowSourceRef, scopeDigest, measure string, limit int, memory int64) (anomaly.FlowFieldDistributionWindow, error) {
	var none anomaly.FlowFieldDistributionWindow
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != captured.TenantID {
		return none, tenancy.ErrNoTenant
	}
	result := captured.Result
	if captured.ID != expected.ID || captured.Version != expected.Version ||
		result.Coverage == nil || !result.Coverage.CompleteInputs || result.OldestInput.IsZero() || result.Query.View != "table" ||
		result.Query.RowLimit < limit || limit < 1 || limit > anomaly.MaxFlowFieldRank ||
		result.TotalGroups < 0 || len(result.Rows) < min(limit, result.TotalGroups) || scopeDigest == "" {
		return none, anomaly.ErrFlowFieldCoverage
	}
	if err := checkFlowFieldRankMeasure(result, measure); err != nil {
		return none, err
	}
	if result.TotalGroups > limit && !provedFlowFieldCutoff(result.Rows, measure, limit) {
		return none, anomaly.ErrFlowFieldCoverage
	}
	window := anomaly.RankedFlowFieldWindow{TenantID: captured.TenantID, ViewID: captured.ID, ViewRevision: captured.Version,
		ScopeDigest: scopeDigest, Measure: measure, From: result.Query.From, To: result.Query.To, CompleteTopSet: true}
	items := result.Rows[:min(limit, result.TotalGroups)]
	if memory <= 0 || int64(len(items)) > memory/512 {
		return none, anomaly.ErrFlowFieldCoverage
	}
	window.Rows = make([]anomaly.RankedFlowField, 0, len(items))
	for pos, row := range items {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		amount, found := row.Metrics[measure]
		if row.Other || !found || len(row.Group) != len(result.Query.GroupBy) {
			return none, anomaly.ErrFlowFieldCoverage
		}
		memory -= 512 + int64(len(amount))
		secondary := map[string]string{}
		for _, metric := range result.Query.Metrics {
			if metric.Role != "secondary" {
				continue
			}
			name := metric.Measure + ":" + metric.Calculation
			value, ok := row.Metrics[name]
			if !ok || len(value) > 256 {
				return none, anomaly.ErrFlowFieldCoverage
			}
			memory -= 128 + int64(len(name)+len(value))
			secondary[name] = value
		}
		for _, field := range result.Query.GroupBy {
			value, present := row.Group[field]
			if !present {
				return none, anomaly.ErrFlowFieldCoverage
			}
			memory -= int64(len(field)+len(value)) * 6
		}
		if memory <= 0 {
			return none, anomaly.ErrFlowFieldCoverage
		}
		key, err := rankedFlowMemberKey(window, row.Group)
		if err != nil {
			return none, err
		}
		window.Rows = append(window.Rows, anomaly.RankedFlowField{TenantID: captured.TenantID, Key: key,
			Rank: pos + 1, Value: amount, Group: row.Group, Secondary: secondary,
			Citation: captured.ID + ":" + captured.Version + ":" + window.To.UTC().Format(time.RFC3339Nano) + ":" + key})
	}
	return anomaly.FlowFieldDistributionWindow{Ranking: window, ParentTotal: result.Totals[measure]}, ctx.Err()
}

// The first excluded original distinguishes a complete, strict cutoff
// from an unobserved or tied boundary. Neither unknown can show entry.
func provedFlowFieldCutoff(rows []flowstore.PlanRow, measure string, limit int) bool {
	if len(rows) <= limit || rows[limit-1].Other || rows[limit].Other {
		return false
	}
	cutoff, below := rows[limit-1].Metrics[measure], rows[limit].Metrics[measure]
	if len(cutoff) > 256 || len(below) > 256 {
		return false
	}
	inside, insideOK := new(big.Rat).SetString(cutoff)
	outside, outsideOK := new(big.Rat).SetString(below)
	return insideOK && outsideOK && outside.Sign() >= 0 && inside.Cmp(outside) > 0
}

func rankedFlowMemberKey(window anomaly.RankedFlowFieldWindow, parts map[string]string) (string, error) {
	encoded, err := json.Marshal(struct {
		Tenant, View, Revision, Scope string
		Parts                         map[string]string
	}{window.TenantID, window.ViewID, window.ViewRevision, window.ScopeDigest, parts})
	if err != nil {
		return "", err
	}
	digest := crypto.Hash(encoded)
	if len(digest) != 32 {
		return "", anomaly.ErrFlowFieldCoverage
	}
	return hex.EncodeToString(digest), nil
}

func checkFlowFieldRankMeasure(result flowstore.PlanResult, measure string) error {
	if len(result.Query.GroupBy) == 0 {
		return anomaly.ErrFlowFieldCoverage
	}
	for _, metric := range result.Query.Metrics {
		if metric.Role == "primary" && metric.Measure+":"+metric.Calculation == measure {
			return nil
		}
	}
	return anomaly.ErrFlowFieldCoverage
}
