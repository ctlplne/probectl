// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
)

type pathHealthRCAKey struct{}

type pathHealthRCA struct {
	query      *pathHealthOperation
	snapshot   pathHealthSnapshot
	row        ai.Row
	credential func(context.Context) error
}

// A path selector resolves only through the owned test and its current bound
// sources. The original HTTP credential remains on the cloned request; native
// callers supply their transport's exact originating credential check.
func (s *Server) preparePathHealthRCA(r *http.Request, subject map[string]string, window ai.TimeRange, credential func(context.Context) error) (context.Context, *pathHealthRCA, error) {
	id := subject["path_test_id"]
	parsed, err := gouuid.Parse(id)
	if err != nil || parsed == gouuid.Nil || parsed.String() != id {
		return nil, nil, apierror.Validation("path_test_id requires a canonical owned test UUID")
	}
	values := url.Values{}
	for _, key := range []string{"health_from", "health_to", "health_poll_gap", "health_max_bps"} {
		if value := subject[key]; value != "" {
			values.Set(key, value)
		}
	}
	if !window.Start.IsZero() {
		values.Set("health_from", window.Start.UTC().Format(time.RFC3339Nano))
	}
	if !window.End.IsZero() {
		values.Set("health_to", window.End.UTC().Format(time.RFC3339Nano))
	}
	request := r.Clone(r.Context())
	location := *r.URL
	location.Path, location.RawPath, location.RawQuery = "/v1/tests/"+id+"/path/entities", "", values.Encode()
	request.URL = &location
	request.SetPathValue("id", id)
	query, err := s.beginPathHealth(request)
	if err != nil {
		return nil, nil, pathHealthError(err)
	}
	snapshot, err := s.readPathHealth(query)
	if err != nil {
		query.op.done()
		return nil, nil, pathHealthError(err)
	}
	pack, err := marshalNativePathHealth(snapshot.result)
	if err != nil || int64(len(pack)) > query.op.budget.ResponseBytes || int64(len(pack)) > query.remaining/2 {
		query.op.done()
		return nil, nil, apierror.TooLarge("complete path RCA evidence exceeds resource admission")
	}
	query.remaining -= int64(len(pack)) * 2
	summary, signal, observedAt := pathHealthRCASummary(snapshot.result)
	plane, severity := "topology", "info"
	if signal {
		plane, severity = "path", "warning"
	}
	prepared := &pathHealthRCA{query: query, snapshot: snapshot, credential: credential, row: ai.Row{
		"metric": "probectl.path.interface_health", "plane": plane, "severity": severity,
		"title":   "Current interface and operator archive observations on the owned path; causal attribution remains unproven",
		"summary": summary, "path_test_id": id, "path_health": pack,
		"ref": "/path?test_id=" + id, "occurred_at": observedAt,
	}}
	ctx := context.WithValue(query.op.request.Context(), pathHealthRCAKey{}, prepared)
	ctx = ai.WithCurrentEvidence(ctx, func(ctx context.Context) error { return s.checkPathHealthRCA(ctx, prepared) })
	return ctx, prepared, nil
}

func (s *Server) checkPathHealthRCA(ctx context.Context, prepared *pathHealthRCA) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	query := prepared.query
	if err := s.revalidatePathHealthSnapshot(query, prepared.snapshot); err != nil {
		return err
	}
	actor := query.op.actor
	current, err := loadCurrentUserAuthority(query.op.request.Context(), s.pool, actor.TenantID, actor.UserID)
	if err != nil {
		return err
	}
	authCtx, principal, err := current.requestContext(query.op.request.Context(), actor)
	if err != nil {
		return err
	}
	if err := s.authorize(authCtx, principal, permAIQuery, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: actor.TenantID}); err != nil {
		return err
	}
	if prepared.credential != nil {
		return prepared.credential(ctx)
	}
	return s.revalidatePathHealthCredential(query)
}

func (s metricsEvidenceSource) queryPathHealthRCA(ctx context.Context, tenant string, selector map[string]string) ([]ai.Row, error) {
	prepared, ok := ctx.Value(pathHealthRCAKey{}).(*pathHealthRCA)
	if !ok || s.pathHealth == nil || prepared.query.op.actor.TenantID != tenant || prepared.snapshot.result.TestID != selector["path_test_id"] {
		return nil, ai.ErrForbidden
	}
	if err := s.pathHealth.checkPathHealthRCA(ctx, prepared); err != nil {
		return nil, err
	}
	return []ai.Row{prepared.row}, nil
}

func pathHealthRCASummary(result pathHealthResult) (string, bool, time.Time) {
	var summary strings.Builder
	var observedAt time.Time
	fmt.Fprintf(&summary, "Complete current path: %d responders, status %s. ", len(result.Items), result.Status)
	unavailable, signal := 0, false
	for _, hop := range result.Items {
		if hop.Health != nil {
			for _, ref := range hop.Health.ConfigChanges {
				if ref.ObservedAt.After(observedAt) {
					observedAt = ref.ObservedAt
				}
				switch ref.ChangeStatus {
				case "original_predecessor_verified":
					signal = true
					fmt.Fprintf(&summary, "Hop %d operator archive changed from original version %d to %d; device collection was not attested. ", hop.TTL, ref.PreviousVersion, ref.Version)
				case "unavailable_original_predecessor":
					fmt.Fprintf(&summary, "Hop %d archive version %d has no available original predecessor. ", hop.TTL, ref.Version)
				}
			}
		}
		if hop.Health == nil || hop.Health.Status != "observed_originals" {
			unavailable++
			continue
		}
		for _, counter := range hop.Health.Counters {
			if counter.PollCompletedAt != nil && counter.PollCompletedAt.After(observedAt) {
				observedAt = *counter.PollCompletedAt
			}
			if counter.UtilizationNumerator != "" {
				fmt.Fprintf(&summary, "Hop %d %s utilization %s/%s percent, %s. ", hop.TTL, counter.Metric, counter.UtilizationNumerator, counter.UtilizationDenominator, counter.UtilizationKind)
			}
			if !strings.HasSuffix(counter.Metric, ".errors") && !strings.HasSuffix(counter.Metric, ".discards") {
				continue
			}
			delta, ok := new(big.Int).SetString(counter.MinimumDelta, 10)
			if !ok || delta.Sign() <= 0 || counter.RateKind == "unavailable" {
				continue
			}
			signal = true
			fmt.Fprintf(&summary, "Hop %d %s increased by at least %s under counter continuity. ", hop.TTL, counter.Metric, delta.String())
		}
		for _, trend := range hop.Health.ErrorTrends {
			if trend.State == "rising_minimum_rate" {
				signal = true
				fmt.Fprintf(&summary, "Hop %d %s minimum rate is above its %d-sample local baseline; original rate pairs and approximate model statistics are in the structured evidence. ", hop.TTL, trend.Metric, trend.BaselineSamples)
			}
		}
	}
	fmt.Fprintf(&summary, "%d responders have no current original polled counter set. Original words, intervals, assumptions and capture receipts for every responder are in the complete structured evidence. Correlation is observed; a cause of path loss is not established.", unavailable)
	return summary.String(), signal, observedAt
}
