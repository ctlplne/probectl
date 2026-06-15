// SPDX-License-Identifier: LicenseRef-probectl-TBD

package tenancy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// fakeRow / fakeQuerier let TestAssertDeploymentProfilePosture exercise the
// RED-001 fail-closed logic with NO live Postgres (sandbox-tier). The live
// "boot single-profile with 2 tenants -> startup refusal" path is the ci-tier
// complement (build tag isolation), but the decision logic is proven here.
type fakeRow struct {
	n   int
	err error
}

func (f fakeRow) Scan(dest ...any) error {
	if f.err != nil {
		return f.err
	}
	if len(dest) > 0 {
		if p, ok := dest[0].(*int); ok {
			*p = f.n
		}
	}
	return nil
}

type fakeQuerier struct {
	row    fakeRow
	called bool
}

func (q *fakeQuerier) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	q.called = true
	return q.row
}

func TestAssertDeploymentProfilePosture(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name        string
		profile     string
		chScoped    bool
		tenants     int
		wantErr     bool
		wantQueried bool // the tenant count is only queried in the degraded posture
	}{
		{"multi-tenant profile skips the check", "multi-tenant", false, 9, false, false},
		{"regulated profile skips the check", "regulated", false, 9, false, false},
		{"single but operator explicitly scoped CH", "single", true, 9, false, false},
		{"single, one tenant is fine", "single", false, 1, false, true},
		{"single, zero tenants is fine", "single", false, 0, false, true},
		{"single, two tenants REFUSES (fail closed)", "single", false, 2, true, true},
		{"single, many tenants REFUSES", "single", false, 50, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := &fakeQuerier{row: fakeRow{n: tc.tenants}}
			err := AssertDeploymentProfilePosture(ctx, q, tc.profile, tc.chScoped)
			if (err != nil) != tc.wantErr {
				t.Fatalf("AssertDeploymentProfilePosture err = %v, wantErr = %v", err, tc.wantErr)
			}
			if q.called != tc.wantQueried {
				t.Fatalf("tenant count queried = %v, want %v", q.called, tc.wantQueried)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "RED-001") {
				t.Errorf("refusal must cite RED-001 for traceability, got: %v", err)
			}
		})
	}
}

// A query error must surface (fail closed), not be swallowed.
func TestAssertDeploymentProfilePostureQueryError(t *testing.T) {
	q := &fakeQuerier{row: fakeRow{err: errors.New("boom")}}
	if err := AssertDeploymentProfilePosture(context.Background(), q, "single", false); err == nil {
		t.Fatal("a tenant-count query error must propagate, not be ignored")
	}
}
