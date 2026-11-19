// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package configschema

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// ProspectCollectionEnd is the optional local end of a temporary collector.
// It limits the workload even when its control-plane channel is unavailable.
type ProspectCollectionEnd struct{ time.Time }

var errProspectCollectionEnded = errors.New("prospect collection ended")

func (e *ProspectCollectionEnd) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return err
	}
	end, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || end.IsZero() {
		return fmt.Errorf("prospect_collection_ends_at requires an RFC3339 timestamp with a time zone")
	}
	e.Time = end.UTC()
	return nil
}

// Context applies the local prospect end while preserving any earlier parent
// deadline. The zero value leaves the runtime bounded by its parent.
func (e ProspectCollectionEnd) Context(parent context.Context) (context.Context, context.CancelFunc) {
	if e.IsZero() {
		return context.WithCancel(parent)
	}
	return context.WithDeadlineCause(parent, e.Time, errProspectCollectionEnded)
}

// ProspectCollectionEnded distinguishes the local cutoff from ordinary probe
// cancellation, which can still produce an original runtime outcome.
func ProspectCollectionEnded(ctx context.Context) bool {
	return context.Cause(ctx) == errProspectCollectionEnded
}
