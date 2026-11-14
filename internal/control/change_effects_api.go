// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/fairness"
)

func (s *Server) handleChangeEffects(w http.ResponseWriter, r *http.Request) error {
	var input changeEffectsInput
	for key, target := range map[string]*time.Time{"from": &input.From, "to": &input.To} {
		value, err := time.Parse(time.RFC3339Nano, r.URL.Query().Get(key))
		if err != nil {
			return apierror.BadRequest("explicit RFC3339 comparison from/to are required")
		}
		*target = value.UTC()
	}
	input.DataSeries = r.URL.Query().Get("dataseries")
	scope := s.configEvidenceForRequest(r, permChangeRead, permFlowRead, permTestRead, "events.read")
	result, publication, err := s.computeChangeEffects(r.Context(), scope, r.PathValue("id"), input)
	if err != nil {
		if errors.Is(err, fairness.ErrQueryConcurrency) || errors.Is(err, fairness.ErrQueryBudget) {
			w.Header().Set("Retry-After", "1")
			return apierror.RateLimited("tenant change comparison allowance exceeded; retry shortly")
		}
		return err
	}
	defer publication.close()
	if err := publication.check(r.Context()); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}
