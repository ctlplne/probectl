// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"errors"
	"time"
)

var ErrConfigReferenceBudget = errors.New("complete configuration references exceed resource admission")

// ConfigArchiveReference contains original archive metadata, never content.
// The operator assertion and its exact assignment remain explicit. A missing
// original predecessor is unavailable rather than replaced by a hash match.
type ConfigArchiveReference struct {
	ID              string               `json:"id"`
	Version         int                  `json:"version"`
	ContentHash     string               `json:"content_hash"`
	PreviousHash    string               `json:"previous_hash,omitempty"`
	PreviousID      string               `json:"previous_id,omitempty"`
	PreviousVersion int                  `json:"previous_version,omitempty"`
	Drifted         bool                 `json:"drifted"`
	ChangeStatus    string               `json:"change_status"`
	Source          string               `json:"source,omitempty"`
	ObservedAt      time.Time            `json:"observed_at"`
	ArchivedAt      time.Time            `json:"archived_at"`
	Binding         ConfigArchiveBinding `json:"binding"`
}

type ConfigArchiveReferenceReader interface {
	ReadConfigArchiveReferences(context.Context, string, ConfigArchiveBinding, time.Time, time.Time, int64) ([]ConfigArchiveReference, int64, error)
}
