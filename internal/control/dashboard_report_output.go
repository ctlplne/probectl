// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

// Load validates environment values; zero-valued embedded/test configurations
// use the same defaults. A negative direct setting is retained and refused.
func (s *Server) reportOutputPolicy() reporting.OutputPolicy {
	p := reporting.DefaultOutputPolicy()
	if s.cfg == nil {
		return p
	}
	if s.cfg.ReportCSVRows != 0 {
		p.CSVRows = int64(s.cfg.ReportCSVRows)
	}
	if s.cfg.ReportPDFRows != 0 {
		p.PDFRows = int64(s.cfg.ReportPDFRows)
	}
	if s.cfg.ReportMaxBytes != 0 {
		p.Bytes = int64(s.cfg.ReportMaxBytes)
	}
	return p
}

func reportBodyStageLimits(policy reporting.OutputPolicy, budget flowstore.ExplorerBudget) (reporting.BodyStageLimits, error) {
	if err := policy.Validate(); err != nil {
		return reporting.BodyStageLimits{}, err
	}
	if err := budget.Validate(); err != nil {
		return reporting.BodyStageLimits{}, err
	}
	memory := budget.MemoryBytes / 2
	// Reserve all possible chunk-slice accounting, hash/reader scratch and
	// final-chunk slack. The stage charges actual buffers independently.
	chunks := (policy.Bytes + reporting.BodyChunkBytes - 1) / reporting.BodyChunkBytes
	bytes := min(policy.Bytes, memory-chunks*64-(256<<10))
	if bytes <= 0 {
		return reporting.BodyStageLimits{}, reporting.ErrBodyStageLimit
	}
	return reporting.BodyStageLimits{Bytes: bytes, MemoryBytes: memory}, nil
}
