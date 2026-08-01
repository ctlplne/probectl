// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ebpf

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFixtureSourcesBoundFiles(t *testing.T) {
	const maxBytes = 8 << 20

	tests := []struct {
		name string
		data string
		load func(string) error
	}{
		{
			name: "flows",
			data: `[{"tenant_id":"tenant-a","agent_id":"agent-a","destination_address":"192.0.2.1","network_transport":"tcp"}]`,
			load: func(path string) error {
				_, err := NewFixtureSource(path)
				return err
			},
		},
		{
			name: "layer-7",
			data: `[{"conn_id":1,"tenant_id":"tenant-a","kind":"request","text":"GET / HTTP/1.1"}]`,
			load: func(path string) error {
				_, err := NewFixtureL7Source(path)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exact := tt.data + strings.Repeat(" ", maxBytes-len(tt.data))
			exactPath := filepath.Join(t.TempDir(), "exact.json")
			if err := os.WriteFile(exactPath, []byte(exact), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := tt.load(exactPath); err != nil {
				t.Fatalf("load exact-limit fixture: %v", err)
			}

			oversizePath := filepath.Join(t.TempDir(), "oversize.json")
			if err := os.WriteFile(oversizePath, []byte(exact+" "), 0o600); err != nil {
				t.Fatal(err)
			}
			err := tt.load(oversizePath)
			if err == nil {
				t.Fatal("load one-byte-oversize fixture: expected error")
			}
			if !strings.Contains(err.Error(), "8388608-byte limit") {
				t.Fatalf("load one-byte-oversize fixture error = %q, want byte-limit detail", err)
			}
		})
	}
}

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
