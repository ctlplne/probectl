// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"errors"
	"time"
)

// HTTPWorkBudget bounds detached legacy HTTP execution. Native source and
// tenant fairness/read/memory/render limits remain independent and unchanged.
type HTTPWorkBudget struct {
	Timeout        time.Duration
	ActiveRequests int
}

func DefaultHTTPWorkBudget() HTTPWorkBudget {
	return HTTPWorkBudget{Timeout: time.Minute, ActiveRequests: 1024}
}

func (b HTTPWorkBudget) Validate() error {
	if b.Timeout <= 0 || b.ActiveRequests < 1 {
		return errors.New("mcp: HTTP work timeout and active request admission must be positive")
	}
	return nil
}

// WithHTTPWorkBudget copies operator cost policy. A request cannot modify it.
func WithHTTPWorkBudget(b HTTPWorkBudget) Option { return func(s *Server) { s.httpWorkBudget = b } }
