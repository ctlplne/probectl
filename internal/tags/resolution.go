// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tags

// SubjectResolution is the curated effective-tag projection. Fact freshness
// has its own as-of time; the tag revision does not version the evidence plane.
// Exporter identities and raw source facts never enter this projection.
type SubjectResolution struct {
	ContextID   string          `json:"context_id"`
	TargetKind  string          `json:"target_kind"`
	TargetID    string          `json:"target_id,omitempty"`
	TagRevision string          `json:"tag_revision"`
	AsOf        string          `json:"as_of"`
	Items       []EffectiveItem `json:"items"`
}

type EffectiveItem struct {
	TagID  string `json:"tag_id"`
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source string `json:"source"`
}
