// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestTenantErasureRefusesRequestAndInvalidResourcesBeforeSQL(t *testing.T) {
	f := newMessageCodecFixture(t)
	operational := tenancy.WithTenant(t.Context(), tenancy.ID(f.scope.TenantID))
	var j *Journal
	budget := CancellationBudget{Rows: 1, TimeLimit: time.Second}
	fenced := false
	fence := func(context.Context) error { fenced = true; return nil }
	allow := func(context.Context, string) error { return nil }
	for _, ctx := range []context.Context{t.Context(), f.requestContext(t), auth.WithPrincipal(operational, &auth.Principal{TenantID: f.scope.TenantID, UserID: f.scope.OwnerID})} {
		if _, err := j.EraseTenant(ctx, budget, allow, fence); !errors.Is(err, ErrMessageDenied) || fenced {
			t.Fatal("request/provider context or missing tenant reached destructive fence", err)
		}
	}
	for _, budget := range []CancellationBudget{{TimeLimit: time.Second}, {Rows: 1}} {
		if _, err := j.EraseTenant(operational, budget, allow, fence); !errors.Is(err, ErrMessageBudget) || fenced {
			t.Fatal("non-positive batch resources reached destructive fence", err)
		}
	}
	if _, err := j.EraseTenant(operational, budget, nil, fence); !errors.Is(err, ErrMessageDenied) || fenced {
		t.Fatal("missing independent authority reached destructive fence", err)
	}
	if _, err := j.EraseTenant(operational, budget, allow, nil); !errors.Is(err, ErrMessageBudget) {
		t.Fatal("missing canonical fence accepted", err)
	}
	if _, err := json.Marshal(TenantErasure{Installed: true, MessagesDeleted: math.MaxInt64}); err == nil {
		t.Fatal("private storage count became a public erasure attestation")
	}
}

func TestTenantErasureCountsRefuseOverflowAndHiddenCascade(t *testing.T) {
	for _, test := range []struct {
		before, deleted, after int64
		valid                  bool
	}{{0, 0, 0, true}, {math.MaxInt64, 1, math.MaxInt64 - 1, true}, {3, 1, 1, false}, {1, 2, 0, false}, {-1, 0, -1, false}, {math.MaxInt64, -1, math.MinInt64, false}} {
		if exactPurgeDelta(test.before, test.deleted, test.after) != test.valid {
			t.Fatal("purge count accepted an overflow or uncounted cascade", test)
		}
	}
}
