// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type capacityCounterHistoryProbe struct {
	*flowstore.Memory
	calls     int
	after     func()
	transform func([]flowstore.CounterRow) ([]flowstore.CounterRow, error)
}

func (p *capacityCounterHistoryProbe) CounterPoints(ctx context.Context, query flowstore.CounterQuery) ([]flowstore.CounterRow, error) {
	p.calls++
	rows, err := p.Memory.CounterPoints(ctx, query)
	if err != nil {
		return nil, err
	}
	if p.after != nil {
		p.after()
	}
	if p.transform != nil {
		return p.transform(rows)
	}
	return rows, nil
}

// Real application-role PostgreSQL/RLS, current user grants and original
// capture writer/reader. Counter inputs, zero-duration poll clocks and the
// history backend are modeled. This is neither physical SNMP nor a ClickHouse
// or served billing proof; those original acceptance requirements remain.
func TestCapacityCounterReaderKeepsOriginalReceiptsAndCurrentTenantSourceAuthority(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	probe := &capacityCounterHistoryProbe{Memory: flowstore.NewMemory()}
	f.server.flowStore = probe
	budget := flowstore.CounterBudget{MemoryBytes: 128 << 20, WorkUnits: 128 << 20, Timeout: time.Minute}
	actors := map[string]*auth.Principal{}
	windows := map[string]flow.CapacityMeasurementWindow{}
	allRows := map[string][]flowstore.CounterRow{}
	for _, tenant := range f.tenants {
		var start time.Time
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			grants, err := (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[tenant])
			if err != nil {
				return err
			}
			actors[tenant] = auth.PrincipalWithPermissionGrants(&auth.Principal{TenantID: tenant, UserID: f.users[tenant], ViaBearerToken: true}, grants)
			return sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&start)
		})
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		reader := store.NewDeviceCounterCaptures(f.pool)
		for poll := range 2 {
			// The second modeled poll is inside the existing five-minute
			// clock-skew envelope; no source clock or erasure fence is edited.
			at := start.Add(time.Duration(poll) * 5 * time.Minute)
			input := entity.CounterCaptureInput{ConfiguredTarget: "192.0.2.1", PollStartedAt: at, PollCompletedAt: at, PointCount: 2}
			digest := [32]byte{byte(poll + 1), 255}
			ref, err := reader.CaptureAuthenticated(ctx, "role-snmp", f.serials[tenant+"role-snmp"], digest, input, 128<<20)
			if err != nil {
				t.Fatal("actual original-poll writer refused owned modeled inputs", err)
			}
			witness, err := reader.LookupWitness(ctx, "role-snmp", digest, input)
			if err != nil {
				t.Fatal(err)
			}
			var rows []flowstore.CounterRow
			for _, direction := range []string{"in", "out"} {
				value, width := uint64(1<<32-1000)+uint64(poll)*30000, uint32(32)
				if direction == "out" {
					value, width = ^uint64(0)-999+uint64(poll)*60000, 64
				} else {
					value %= 1 << 32
				}
				rows = append(rows, flowstore.CounterRow{TenantID: tenant,
					CounterSource: flowstore.CounterSource{ContextID: f.contextID, DeviceID: f.routerID, AgentID: "role-snmp", SourceRef: input.ConfiguredTarget,
						SourceAssignedAt: witness.SourceAssignedAt, AgentAssignedAt: witness.AgentAssignedAt},
					SenderSerial: witness.SenderSerial, CaptureKey: ref.Key, RawDigest: digest, CapturedAt: ref.CapturedAt, PollStartedAt: at, PollCompletedAt: at,
					Population: 2, IfIndex: 7, Name: "probectl.device.if." + direction + ".octets", Value: value, Width: width,
					UptimeTicks: 100000 + uint32(poll)*30000, UptimeKnown: true, DiscontinuityKnown: true})
			}
			if err := probe.InsertCounterPoll(ctx, rows, budget); err != nil {
				t.Fatal(err)
			}
			allRows[tenant] = append(allRows[tenant], rows...)
		}
		windows[tenant] = flow.CapacityMeasurementWindow{From: start, To: start.Add(5 * time.Minute), MaximumPollGap: 5 * time.Minute, MemoryBytes: 128 << 20, WorkUnits: 128 << 20}
	}
	selection := func(tenant string) capacityCounterSelection {
		return capacityCounterSelection{Scope: entity.Scope{TenantID: tenant, ContextID: f.contextID}, InterfaceID: f.interfaceID, PhysicalMaxBPS: 1_000_000}
	}
	read := func(tenant string) {
		t.Helper()
		member, err := f.server.readCapacityCounterMember(t.Context(), actors[tenant], selection(tenant), windows[tenant], budget)
		if err != nil || member.Source().TenantID != tenant || member.Source().InterfaceID != f.interfaceID {
			t.Fatal("actual source read lost tenant-scoped canonical ownership", member.Source(), err)
		}
		for _, direction := range []string{"in", "out"} {
			bps := "800"
			if direction == "out" {
				bps = "1600"
			}
			samples := member.Samples(direction)
			if len(samples) != 1 || !samples[0].Observed || !samples[0].Wrapped || samples[0].BPSNumerator != bps || samples[0].BPSDenominator != "1" {
				t.Fatal("actual source adapter rounded, zero-filled or lost original wrap evidence", samples)
			}
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	read(a)
	read(b)
	refused := func(ctx context.Context, actor *auth.Principal, target capacityCounterSelection, window flow.CapacityMeasurementWindow) {
		t.Helper()
		member, err := f.server.readCapacityCounterMember(ctx, actor, target, window, budget)
		if err == nil || !reflect.DeepEqual(member, flow.CapacityMeasuredMember{}) {
			t.Fatal("unavailable/foreign source produced a measured prefix", member, err)
		}
	}
	before := probe.calls
	refused(t.Context(), actors[a], selection(b), windows[b])
	refused(tenancy.WithTenant(t.Context(), tenancy.ID(b)), actors[a], selection(a), windows[a])
	if probe.calls != before {
		t.Fatal("contradictory tenant scope reached the telemetry backend")
	}
	// Two current canonical identities for the same device/index cannot be
	// selected as if they were distinct physical circuit members.
	const competingID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	if err := store.NewAgentIdentities(f.pool).Record(t.Context(), a, "counter-second-collector", crypto.EntitySPIFFEID(a, "counter-second-collector"), "counter-second-serial", time.Now().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES($1,'counter-second-collector',$2)`, a, f.contextID); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id) VALUES($1,'counter-second-collector','device_target','192.0.2.254',$2,$3)`, a, f.contextID, f.routerID); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label,parent_entity_id,source_agent_id,configured_ref,interface_index)
 VALUES($1,$2,$3,'interface','competing current physical index',$4,'counter-second-collector','192.0.2.254',7)`, a, f.contextID, competingID, f.routerID)
		return err
	})
	before = probe.calls
	refused(t.Context(), actors[a], selection(a), windows[a])
	if probe.calls != before {
		t.Fatal("ambiguous physical ownership reached counter history")
	}
	read(b)
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET expires_at=assigned_at WHERE tenant_id=$1 AND agent_id='counter-second-collector'`, a)
		return err
	})
	read(a) // an inactive retained identity is not a competing current owner
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entities WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, a, f.contextID, competingID)
		return err
	})
	read(a)
	probe.transform = func([]flowstore.CounterRow) ([]flowstore.CounterRow, error) { return allRows[b], nil }
	refused(t.Context(), actors[a], selection(a), windows[a])
	probe.transform = func(rows []flowstore.CounterRow) ([]flowstore.CounterRow, error) {
		// Reuse the first capture key with changed raw/poll metadata after
		// the receipt cache has already seen a legitimate sibling point.
		rows[len(rows)-1].CaptureKey = rows[0].CaptureKey
		return rows, nil
	}
	refused(t.Context(), actors[a], selection(a), windows[a])
	probe.transform = func(rows []flowstore.CounterRow) ([]flowstore.CounterRow, error) {
		return rows, errors.New("late backend failure")
	}
	refused(t.Context(), actors[a], selection(a), windows[a])
	probe.transform = nil
	probe.after = func() {
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='metrics.read'`, a, f.roles[a])
			return err
		})
	}
	refused(t.Context(), actors[a], selection(a), windows[a])
	probe.after = nil
	before = probe.calls
	refused(t.Context(), actors[a], selection(a), windows[a])
	if probe.calls != before {
		t.Fatal("withdrawn current source grant reached the telemetry backend")
	}
	read(b)
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], "metrics.read")
	})
	read(a)
	probe.after = func() {
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET assigned_at=clock_timestamp() WHERE tenant_id=$1 AND agent_id='role-snmp' AND source_kind='device_target'`, a)
			return err
		})
	}
	refused(t.Context(), actors[a], selection(a), windows[a])
	probe.after = nil
	read(b)
	// After proving the sibling was unaffected, erase only its modeled
	// receipt payloads. Remaining telemetry cannot replace original authority.
	probe.after = func() {
		f.in(b, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM device_counter_capture_sources WHERE tenant_id=$1`, b)
			return err
		})
	}
	refused(t.Context(), actors[b], selection(b), windows[b])
}
