// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/store/flowstore"
)

// Source-backed reports keep the query's read, memory and tenant-fairness
// policy, but their complete capture/render/replay/publication operation uses
// the report deadline. Interactive query admission is unchanged.
func (s *Server) sourceReportBudget() (flowstore.ExplorerBudget, error) {
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	budget.ExecutionLimit = 5 * time.Minute
	if s.cfg != nil && s.cfg.ReportOperationTimeout != 0 {
		budget.ExecutionLimit = s.cfg.ReportOperationTimeout
	}
	return budget, budget.Validate()
}

// The listener's ordinary fifteen-second write deadline must not reset a
// complete report after its source/render work was admitted for longer.
func (s *Server) extendReportResponse(w http.ResponseWriter, r *http.Request) error {
	profile, err := s.staticReportOperation()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(profile.timeout)
	if earlier, ok := r.Context().Deadline(); ok && earlier.Before(deadline) {
		deadline = earlier
	}
	_ = http.NewResponseController(w).SetWriteDeadline(deadline)
	return nil
}
