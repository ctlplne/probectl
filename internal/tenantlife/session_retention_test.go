// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tenantlife

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/auth"
)

type sessionRetentionRecorder struct {
	tenant  string
	horizon time.Duration
	deleted int64
	err     error
}

func (r *sessionRetentionRecorder) PruneInactive(
	_ context.Context,
	tenantID string,
	replayHorizon time.Duration,
) (int64, error) {
	r.tenant = tenantID
	r.horizon = replayHorizon
	return r.deleted, r.err
}

func TestSessionRetentionUsesConfiguredTTLAndRecordsReceipt(t *testing.T) {
	const tenant = "00000000-0000-0000-0000-0000000000aa"
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	pruner := &sessionRetentionRecorder{deleted: 3}
	var action, target string
	var receipt map[string]any
	engine := New(nil, nil, nil, nil,
		func(_ context.Context, _, gotAction, gotTarget string, data map[string]any) error {
			action, target, receipt = gotAction, gotTarget, data
			return nil
		},
		"", slog.New(slog.NewTextHandler(io.Discard, nil)),
	).WithClock(func() time.Time { return now }).
		WithSessionRetention(pruner, 2*time.Hour)

	if err := engine.sweepSessionRetention(
		context.Background(),
		retentionSweepPolicy{tenant: tenant},
	); err != nil {
		t.Fatalf("sweep session retention: %v", err)
	}
	if pruner.tenant != tenant || pruner.horizon != 2*time.Hour {
		t.Fatalf("pruner scope = tenant %q horizon %s", pruner.tenant, pruner.horizon)
	}
	if action != "lifecycle.retention_sweep" || target != tenant {
		t.Fatalf("receipt action=%q target=%q", action, target)
	}
	if receipt["store"] != "sessions" || receipt["deleted"] != int64(3) ||
		receipt["replay_horizon"] != "2h0m0s" ||
		receipt["cutoff"] != now.Add(-2*time.Hour).Format(time.RFC3339Nano) {
		t.Fatalf("session retention receipt = %#v", receipt)
	}
}

func TestSessionRetentionDefaultsWithIssuerAndPropagatesPruneFailure(t *testing.T) {
	wantErr := errors.New("database unavailable")
	pruner := &sessionRetentionRecorder{err: wantErr}
	engine := New(nil, nil, nil, nil, nil, "", nil).
		WithSessionRetention(pruner, 0)

	err := engine.sweepSessionRetention(
		context.Background(),
		retentionSweepPolicy{tenant: "00000000-0000-0000-0000-0000000000bb"},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("sweep error = %v, want %v", err, wantErr)
	}
	if pruner.horizon != auth.DefaultSessionTTL {
		t.Fatalf("default cleanup horizon = %s, want issuer default %s", pruner.horizon, auth.DefaultSessionTTL)
	}
}

func TestSessionRetentionPropagatesReceiptFailure(t *testing.T) {
	wantErr := errors.New("audit unavailable")
	pruner := &sessionRetentionRecorder{deleted: 1}
	engine := New(nil, nil, nil, nil,
		func(context.Context, string, string, string, map[string]any) error {
			return wantErr
		},
		"", nil,
	).WithSessionRetention(pruner, time.Hour)

	err := engine.sweepSessionRetention(
		context.Background(),
		retentionSweepPolicy{tenant: "00000000-0000-0000-0000-0000000000cc"},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("receipt error = %v, want %v", err, wantErr)
	}
}
