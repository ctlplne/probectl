// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"errors"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/fairness"
)

// ErrorClass gives logs bounded diagnostics without calling an untrusted
// dependency error's Error method. Error text may contain credentials, SQL or
// another tenant's details (docs/guardrails.md G7-6); it is never a log field.
func ErrorClass(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, fairness.ErrQueryConcurrency):
		return "query_concurrency"
	case errors.Is(err, fairness.ErrQueryBudget):
		return "query_budget"
	}
	var domain *apierror.Error
	if errors.As(err, &domain) {
		switch apierror.Code(domain.Code) {
		case apierror.CodeValidation:
			return "validation"
		case apierror.CodeNotFound:
			return "not_found"
		case apierror.CodeConflict:
			return "conflict"
		case apierror.CodeForbidden:
			return "permission"
		case apierror.CodeUnauthorized:
			return "authentication"
		case apierror.CodeUnavailable:
			return "unavailable"
		}
	}
	return "dependency"
}
