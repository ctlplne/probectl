// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"net/http"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/fairness"
)

func tagQueryAdmissionError(err error) error {
	switch {
	case errors.Is(err, fairness.ErrQueryConcurrency):
		return apierror.RateLimited("tenant query concurrency limit reached; retry shortly")
	case errors.Is(err, fairness.ErrQueryBudget):
		return apierror.RateLimited("tenant query budget exhausted; retry shortly")
	default:
		return apierror.Unavailable("tag query admission is unavailable")
	}
}

func tagQueryResponseError(w http.ResponseWriter, err error) error {
	if domain, ok := apierror.As(err); ok && domain.Kind == apierror.KindRateLimited {
		w.Header().Set("Retry-After", "1")
	}
	return err
}
