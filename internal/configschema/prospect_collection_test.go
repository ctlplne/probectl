// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package configschema

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestProspectCollectionEndRequiresAnExplicitInstant(t *testing.T) {
	type localConfig struct {
		End ProspectCollectionEnd `yaml:"prospect_collection_ends_at,omitempty"`
	}
	var config localConfig
	if err := DecodeStrictYAML([]byte("prospect_collection_ends_at: 2026-11-19T15:50:00.123456+05:30\n"), &config); err != nil {
		t.Fatal(err)
	}
	if got := config.End.Format(time.RFC3339Nano); got != "2026-11-19T10:20:00.123456Z" {
		t.Fatal("collector changed the configured instant", got)
	}
	for _, raw := range []string{"2026-11-19", "2026-11-19T15:50:00", "2026-11-19T25:00:00Z", "' '"} {
		if err := DecodeStrictYAML([]byte("prospect_collection_ends_at: "+raw+"\n"), &localConfig{}); err == nil {
			t.Fatal("collector accepted an invalid end", raw)
		}
	}
}

func TestProspectCollectionEndPreservesParentAndRefusesExpiredWork(t *testing.T) {
	parent, stop := context.WithTimeout(t.Context(), time.Minute)
	defer stop()
	parentEnd, _ := parent.Deadline()
	for _, configured := range []ProspectCollectionEnd{{}, {Time: parentEnd.Add(time.Hour)}} {
		ctx, cancel := configured.Context(parent)
		actual, ok := ctx.Deadline()
		cancel()
		if !ok || !actual.Equal(parentEnd) || ProspectCollectionEnded(ctx) {
			t.Fatal("collector extended the existing parent lifetime", actual)
		}
	}
	ctx, cancel := (ProspectCollectionEnd{Time: time.Now().Add(-time.Minute)}).Context(parent)
	defer cancel()
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) || !ProspectCollectionEnded(ctx) {
		t.Fatal("completed collector would be allowed to start", ctx.Err())
	}
}
