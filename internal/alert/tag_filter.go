// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tags"
)

const TagFilterVersion = 1

// TagFilterState is the bounded metadata-only public projection. Alert channels
// and secrets are never part of this read or mutation response.
type TagFilterState struct {
	RuleID       string                 `json:"rule_id"`
	HasTagFilter bool                   `json:"has_tag_filter"`
	TagFilter    *TagFilter             `json:"tag_filter,omitempty"`
	Editor       *TagFilterEditorSchema `json:"editor,omitempty"`
}

// The editor vocabulary is a current authorized read projection, never saved
// with a rule or included when clearing a filter without metadata-read grants.
type TagFilterEditorSchema struct {
	TagRevision string           `json:"tag_revision"`
	AsOf        string           `json:"as_of"`
	Fields      []TagFilterField `json:"fields"`
	Limits      TagFilterLimits  `json:"limits"`
}

type TagFilterField struct {
	Name      string               `json:"name"`
	TagID     string               `json:"tag_id"`
	Type      flow.QueryFieldType  `json:"type"`
	Operators []flow.QueryOperator `json:"operators"`
}

type TagFilterLimits struct {
	MaxGroupEntries       int `json:"max_group_entries"`
	MaxExpandedConditions int `json:"max_expanded_conditions"`
	MaxFilterDepth        int `json:"max_filter_depth"`
	MaxRegexBytes         int `json:"max_regex_bytes"`
	MaxValuesPerPredicate int `json:"max_values_per_predicate"`
	MaxValueBytes         int `json:"max_value_bytes"`
	GrammarBytes          int `json:"grammar_bytes"`
}

// TagFilterInput contains no tenant, owner or authority hints. The server binds
// its field references and authenticated user before saving configuration.
type TagFilterInput struct {
	TargetKind string                 `json:"target_kind"`
	Filter     *flow.QueryFilterGroup `json:"filter"`
}

// TagFilter is current metadata selection, separate from metric labels and
// alert fingerprints. The owner ID is a reference to reload under tenant RLS,
// never a credential or a durable assertion of MFA or current read authority.
type TagFilter struct {
	Version     int                    `json:"version"`
	TargetKind  string                 `json:"target_kind"`
	Filter      *flow.QueryFilterGroup `json:"filter"`
	TagIDs      map[string]string      `json:"tag_ids"`
	OwnerUserID string                 `json:"owner_user_id"`
	TagRevision string                 `json:"tag_revision"`
	AsOf        string                 `json:"as_of"`
}

// Validate checks the stored envelope, not permissions or current definitions.
// Callers still reload current ownership, grants, policy and immutable bindings.
func (f TagFilter) Validate() error {
	owner, err := gouuid.Parse(f.OwnerUserID)
	if err != nil || owner == gouuid.Nil || owner.String() != f.OwnerUserID || f.Version != TagFilterVersion || f.TargetKind != "test" || f.Filter == nil || len(f.TagIDs) == 0 {
		return fmt.Errorf("alert: invalid current test tag filter configuration")
	}
	revision, err := strconv.ParseInt(f.TagRevision, 10, 64)
	clock, clockErr := time.Parse(time.RFC3339Nano, f.AsOf)
	if err != nil || revision <= 0 || strconv.FormatInt(revision, 10) != f.TagRevision || clockErr != nil || clock.IsZero() {
		return fmt.Errorf("alert: invalid test tag filter binding clock")
	}
	seen := map[string]bool{}
	for field, id := range f.TagIDs {
		parsed, err := gouuid.Parse(id)
		if !strings.HasPrefix(field, "tag.") || tags.ValidateKey(strings.TrimPrefix(field, "tag.")) != nil || err != nil || parsed == gouuid.Nil || parsed.String() != id || seen[id] {
			return fmt.Errorf("alert: invalid immutable test tag filter binding")
		}
		seen[id] = true
	}
	return nil
}
