// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package audit

import (
	"context"
	"testing"
	"time"
)

// TestRetentionPolicyLogic covers the pure policy logic with no database: a
// non-positive window disables pruning (keep-forever default), a positive one is
// enabled, and the cutoff is `now - window`.
func TestRetentionPolicyLogic(t *testing.T) {
	if (RetentionPolicy{}).Enabled() {
		t.Error("zero-window policy must be disabled (keep forever is the default)")
	}
	if (RetentionPolicy{Window: -time.Hour}).Enabled() {
		t.Error("negative window must be disabled")
	}
	p := RetentionPolicy{Window: 24 * time.Hour}
	if !p.Enabled() {
		t.Fatal("positive window must be enabled")
	}
	now := time.Unix(1_000_000, 0)
	if got := p.cutoff(now); !got.Equal(now.Add(-24 * time.Hour)) {
		t.Errorf("cutoff = %v, want now-window", got)
	}
}

// TestPruneFailsClosedWithoutDB asserts the guards that short-circuit BEFORE any
// SQL runs — so a misconfiguration can never delete audit history. With a nil
// pool these must return (0, nil) by hitting the guard, never panic on the pool.
func TestPruneFailsClosedWithoutDB(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	// Disabled policy: no-op even with a "watermark".
	if n, err := PruneProvider(ctx, nil, RetentionPolicy{}, 100, now); n != 0 || err != nil {
		t.Errorf("disabled policy prune = (%d,%v), want (0,nil)", n, err)
	}
	// Enabled policy but zero watermark (nothing proven exported): no-op.
	if n, err := PruneProvider(ctx, nil, RetentionPolicy{Window: time.Hour}, 0, now); n != 0 || err != nil {
		t.Errorf("zero-watermark prune = (%d,%v), want (0,nil)", n, err)
	}
	// Tenant prune: empty tenant id is a no-op.
	if n, err := PruneTenant(ctx, nil, "", RetentionPolicy{Window: time.Hour}, 100, now); n != 0 || err != nil {
		t.Errorf("empty-tenant prune = (%d,%v), want (0,nil)", n, err)
	}
	// Tenant prune: zero watermark is a no-op even with a tenant + window.
	if n, err := PruneTenant(ctx, nil, "t", RetentionPolicy{Window: time.Hour}, 0, now); n != 0 || err != nil {
		t.Errorf("zero-watermark tenant prune = (%d,%v), want (0,nil)", n, err)
	}
}

func TestAuditRetentionSequenceAnchorValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		head    streamHead
		wantErr bool
	}{
		{name: "empty", head: streamHead{}},
		{
			name: "partial prune",
			head: streamHead{
				HeadSeq: 8, HeadHash: "h8",
				PrunedSeq: 3, PrunedHash: "h3",
			},
		},
		{
			name: "fully pruned head",
			head: streamHead{
				HeadSeq: 5, HeadHash: "h5",
				PrunedSeq: 5, PrunedHash: "h5",
			},
		},
		{
			name: "rewound prune sequence",
			head: streamHead{
				HeadSeq: 4, HeadHash: "h4",
				PrunedSeq: 5, PrunedHash: "h5",
			},
			wantErr: true,
		},
		{
			name:    "missing durable head hash",
			head:    streamHead{HeadSeq: 4},
			wantErr: true,
		},
		{
			name: "hash without prune sequence",
			head: streamHead{
				HeadSeq: 4, HeadHash: "h4",
				PrunedHash: "h2",
			},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.head.validate("test")
			if (err != nil) != tc.wantErr {
				t.Fatalf("validate() error = %v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}
