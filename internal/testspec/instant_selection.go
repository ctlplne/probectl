// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package testspec

import (
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"
)

// InstantTestCapability marks an enrolled agent that accepts signed on-demand tests.
const InstantTestCapability = "agent.instant_tests.v1"

// InstantSelection names exactly one kind of vantage selection. The caller's
// authenticated scope selects the tenant and the eligible population.
type InstantSelection struct {
	AgentIDs []string         `json:"agent_ids,omitempty"`
	Site     string           `json:"site,omitempty"`
	Tag      *InstantAgentTag `json:"tag,omitempty"`
}

type InstantAgentTag struct {
	ContextID string `json:"context_id"`
	TagID     string `json:"tag_id"`
	Value     string `json:"value"`
}

var ErrInstantSelection = errors.New("testspec: select distinct agents, an exact site, or an exact agent tag")

// NormalizeInstantSelection sorts explicit agent IDs for idempotency while
// retaining the exact site or tag value supplied by the operator.
func NormalizeInstantSelection(input InstantSelection) (InstantSelection, error) {
	count := 0
	if len(input.AgentIDs) > 0 {
		count++
	}
	if input.Site != "" {
		count++
	}
	if input.Tag != nil {
		count++
	}
	if count != 1 {
		return InstantSelection{}, ErrInstantSelection
	}
	if input.Site != "" && strings.TrimSpace(input.Site) != input.Site {
		return InstantSelection{}, ErrInstantSelection
	}
	if tag := input.Tag; tag != nil && (!isInstantUUID(tag.ContextID) || !isInstantUUID(tag.TagID) || tag.Value == "") {
		return InstantSelection{}, ErrInstantSelection
	}
	if len(input.AgentIDs) > 0 {
		ids := slices.Clone(input.AgentIDs)
		slices.Sort(ids)
		for i, id := range ids {
			if !isInstantUUID(id) || i > 0 && id == ids[i-1] {
				return InstantSelection{}, ErrInstantSelection
			}
		}
		input.AgentIDs = ids
	}
	return input, nil
}

func isInstantUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}
