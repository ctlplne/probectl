// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"errors"

	"github.com/ctlplne/probectl/internal/apierror"
)

// Native refusals contain only whitelisted public codes and constant guidance.
// Never copy dependency messages, causes, field values, SQL or private IDs.
func nativeFailureMessage(err error) string {
	var domain *apierror.Error
	if !errors.As(err, &domain) {
		return "tool execution failed"
	}
	switch apierror.Code(domain.Code) {
	case apierror.CodeFlowQueryBudget:
		return "flow_query_budget_exceeded: query resource budget exceeded; use smaller pages or coarser buckets, with frozen pages/CSV for complete table export"
	case apierror.CodeFlowQueryCoverage:
		return "flow_query_coverage_unavailable: requested fields or time span lack complete source coverage; check the registry and available source resolution"
	case apierror.CodeValidation:
		return "validation: arguments must match the advertised native schema and authorized resource"
	case apierror.CodeNotFound:
		return "not_found: private result or configuration is unavailable; refresh your authorized list or run a fresh query"
	case apierror.CodeConflict:
		return "conflict: configuration revision changed; read the latest exact revision before retrying"
	case apierror.CodeForbidden:
		return "forbidden: the requested operation requires an authorized source permission"
	case apierror.CodeUnauthorized:
		return "unauthorized: authenticated tenant and user identity are required"
	case apierror.CodeUnavailable:
		return "unavailable: source or shared result services are temporarily unavailable; retry after backoff"
	case apierror.CodeRateLimited:
		return "rate_limited: current admission or resource budget is exhausted; reduce the request or retry after backoff"
	case apierror.CodeQuotaExceeded:
		return "quota_exceeded: configuration resource budget exceeded; review the operator's configured resource budgets"
	default:
		return "tool execution failed"
	}
}

const nativeResultBudgetMessage = "flow_query_budget_exceeded: result exceeds transport resource budget; use smaller pages or coarser buckets, with frozen pages/CSV for complete table export"
