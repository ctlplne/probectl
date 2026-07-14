// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ebpf

import (
	"context"
	"testing"
	"time"
)

func TestFixtureSourceReplays(t *testing.T) {
	s, err := NewFixtureSource("testdata/flows.json")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ch, err := s.Flows(ctx)
	if err != nil {
		t.Fatal(err)
	}

	var n int
	for f := range ch {
		n++
		if f.TenantID == "" || f.Destination.Address == "" || f.Transport == "" {
			t.Errorf("incomplete replayed flow: %+v", f)
		}
	}
	if n != 3 {
		t.Errorf("replayed flows = %d, want 3", n)
	}
	if s.Drops() != 0 {
		t.Errorf("fixture drops = %d, want 0", s.Drops())
	}
}

func TestFixtureSourceMissingFile(t *testing.T) {
	if _, err := NewFixtureSource("testdata/does-not-exist.json"); err == nil {
		t.Error("expected error for missing fixture file")
	}
}
