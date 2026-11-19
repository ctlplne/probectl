// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import (
	"context"
	"time"
)

// ProspectProviderQueue exposes the operational status and due-assessment
// request for one opted-in tenant. Assessment contents have no provider path.
type ProspectProviderQueue interface {
	Status(context.Context, string) (ProspectProviderStatus, error)
	RequestAssessment(context.Context, string, string, ProspectProviderRequest) (ProspectProviderStatus, error)
}

// ProspectProviderRequest pins a retry to the exact access observed by the operator.
type ProspectProviderRequest struct {
	ID                 string `json:"request_id"`
	EngagementRevision int64  `json:"engagement_revision"`
	AccessRevision     int64  `json:"access_revision"`
}

type ProspectProviderStatus struct {
	TenantID           string    `json:"tenant_id"`
	Phase              string    `json:"phase"`
	EndsAt             time.Time `json:"ends_at"`
	Pending            bool      `json:"request_pending"`
	EngagementRevision int64     `json:"engagement_revision"`
	AccessRevision     int64     `json:"access_revision"`
	RequestID          string    `json:"request_id,omitempty"`
}
