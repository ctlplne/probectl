// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// quarantiningRouter routes t-x and t-q to their own lanes (siloed) and
// refuses whatever the process quarantine holds, like the silo router.
type quarantiningRouter struct{}

func (quarantiningRouter) TargetsFor(_ context.Context, tenantID string) (tenancy.Targets, error) {
	if err := tenancy.CheckQuarantine(tenantID); err != nil {
		return tenancy.Targets{}, err
	}
	if tenantID == "t-x" || tenantID == "t-q" {
		return tenancy.Targets{Model: tenancy.IsolationSiloed, BusNamespace: "t-" + tenantID}, nil
	}
	return tenancy.Targets{Model: tenancy.IsolationPooled}, nil
}
func (quarantiningRouter) BusNamespaces(context.Context) ([]string, error) { return nil, nil }
func (quarantiningRouter) BusNamespaceTenants(context.Context) (map[string]string, error) {
	return nil, nil
}

func withQuarantinedRouter(t *testing.T, quarantined ...string) {
	t.Helper()
	prevQ, prevR := tenancy.CurrentQuarantine(), tenancy.CurrentRouter()
	t.Cleanup(func() { tenancy.SetQuarantine(prevQ); tenancy.SetRouter(prevR) })
	q := tenancy.NewQuarantine()
	for _, id := range quarantined {
		q.Enter(tenancy.QuarantineEntry{TenantID: id, Reason: tenancy.QuarantineReaderScopeUnproven})
	}
	tenancy.SetQuarantine(q)
	tenancy.SetRouter(quarantiningRouter{})
}

// DPR-369: with PRODUCTION-shaped keys (bus.TenantKey: "<tenant>|bN"), the
// lane gate every consumer runs first refuses a quarantined tenant's record —
// on the shared lane (where quarantine used to turn the misrouted-record
// refusal into "abstain") and on its own lane — and passes everyone else.
func TestLaneGateRefusesQuarantinedTenantsWithProductionKeys(t *testing.T) {
	withQuarantinedRouter(t, "t-q")
	ctx := context.Background()
	before := QuarantineDroppedTotal()
	for _, tc := range []struct {
		name       string
		key        []byte
		laneTenant string
		refuse     bool
	}{
		{"quarantined siloed tenant on the shared lane", bus.TenantKey("t-q", "agent-1"), "", true},
		{"quarantined tenant on its own lane", bus.TenantKey("t-q", "agent-1"), "t-q", true},
		{"healthy siloed tenant on the shared lane is misrouted", bus.TenantKey("t-x", "agent-1"), "", true},
		{"healthy siloed tenant on its own lane", bus.TenantKey("t-x", "agent-1"), "t-x", false},
		{"pooled tenant on the shared lane", bus.TenantKey("t-pooled", "agent-1"), "", false},
	} {
		if got := refuseSharedOrQuarantined(ctx, nil, "g", bus.Message{Key: tc.key, Topic: bus.NetworkResultsTopic}, tc.laneTenant); got != tc.refuse {
			t.Errorf("%s (key %q): refused = %v, want %v", tc.name, tc.key, got, tc.refuse)
		}
	}
	if got := QuarantineDroppedTotal() - before; got != 2 {
		t.Fatalf("quarantine drops = %d, want the 2 quarantined records counted", got)
	}
}

// A handler's own quarantine refusal never withholds the ack (which would
// stall every co-partitioned tenant); any other error still does.
func TestLaneGuardAcksAHandlersQuarantineRefusal(t *testing.T) {
	transient := errors.New("store timeout")
	h := guardQuarantined("g", func(_ context.Context, m bus.Message, _ string) error {
		if bus.TenantFromKey(m.Key) == "t-late" {
			return fmt.Errorf("persist: %w", &tenancy.QuarantinedError{})
		}
		return transient
	})
	if err := h(context.Background(), bus.Message{Key: bus.TenantKey("t-late", "a")}, ""); err != nil {
		t.Fatalf("a handler's quarantine refusal must be acknowledged, got %v", err)
	}
	if err := h(context.Background(), bus.Message{Key: bus.TenantKey("t-other", "a")}, ""); !errors.Is(err, transient) {
		t.Fatalf("another error must still refuse the ack, got %v", err)
	}
}
