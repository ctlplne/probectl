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

// Work still expires at its original deadline. Leave a bounded interval for
// the handler and TLS record to close without an expired socket write.
const httpResponseCloseGrace = 5 * time.Second

// HTTPWorkBudget bounds detached legacy HTTP execution. Native source and
// tenant fairness/read/memory/render limits remain independent and unchanged.
type HTTPWorkBudget struct {
	Timeout        time.Duration
	ActiveRequests int
}

func DefaultHTTPWorkBudget() HTTPWorkBudget {
	return HTTPWorkBudget{Timeout: 3 * time.Minute, ActiveRequests: 1024}
}

func (b HTTPWorkBudget) Validate() error {
	if b.Timeout <= 0 || b.ActiveRequests < 1 {
		return errors.New("mcp: HTTP work timeout and active request admission must be positive")
	}
	return nil
}

// WithHTTPWorkBudget copies operator cost policy. A request cannot modify it.
func WithHTTPWorkBudget(b HTTPWorkBudget) Option { return func(s *Server) { s.httpWorkBudget = b } }
