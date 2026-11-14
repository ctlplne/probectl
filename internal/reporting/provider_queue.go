// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import "context"

// MonthlyReportQueue accepts operational triggers only. It cannot read or
// return reports, source facts, owner identities or artifact download links.
type MonthlyReportQueue interface {
	QueueMonthlyReports(context.Context, string, string, string) (MonthlyReportQueueResult, error)
	MonthlyReportProgress(context.Context, string, string, string) (MonthlyReportQueueResult, error)
}

type MonthlyReportQueueResult struct {
	TenantID  string `json:"tenant_id"`
	Eligible  int64  `json:"eligible"`
	Queued    int64  `json:"queued"`
	Pending   int64  `json:"pending"`
	Delivered int64  `json:"delivered"`
	Inactive  int64  `json:"inactive"`
	Replay    bool   `json:"replay"`
}
