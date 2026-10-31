// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"errors"
	"testing"
	"time"
)

type explorerFixtureReporter interface {
	Helper()
	Errorf(string, ...any)
}

type explorerFixtureDeleter interface {
	DeleteTenant(context.Context, string) (int64, error)
}

// A parent cannot pass while its synchronous fixture deletion is incomplete.
// Keep cleanup bounded independently of the already-finished test context.
func cleanupExplorerFixtureTenant(t explorerFixtureReporter, store explorerFixtureDeleter, tenant string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	remaining, err := store.DeleteTenant(ctx, tenant)
	if err != nil || remaining != 0 {
		t.Errorf("tenant fixture cleanup incomplete: remaining=%d,error=%v", remaining, err)
	}
}

type explorerFixtureReport struct{ failures int }

func (*explorerFixtureReport) Helper()                 {}
func (r *explorerFixtureReport) Errorf(string, ...any) { r.failures++ }

type explorerFixtureDeleteResult struct {
	remaining int64
	err       error
}

func (d explorerFixtureDeleteResult) DeleteTenant(context.Context, string) (int64, error) {
	return d.remaining, d.err
}

func TestExplorerFixtureCleanupReportsIncompleteDeletion(t *testing.T) {
	for _, tc := range []struct {
		name         string
		result       explorerFixtureDeleteResult
		wantFailures int
	}{
		{"backend error", explorerFixtureDeleteResult{-1, errors.New("fixture backend unavailable")}, 1},
		{"remaining rows", explorerFixtureDeleteResult{1, nil}, 1},
		{"verified zero", explorerFixtureDeleteResult{0, nil}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := new(explorerFixtureReport)
			cleanupExplorerFixtureTenant(report, tc.result, "owned-fixture")
			if report.failures != tc.wantFailures {
				t.Fatalf("cleanup reported %d failures,want%d; a passing parent would hide incomplete deletion", report.failures, tc.wantFailures)
			}
		})
	}
}
