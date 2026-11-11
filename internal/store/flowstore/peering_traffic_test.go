// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func peeringTrafficFixture(t *testing.T, tenant string, count int) (context.Context, PeeringTrafficQuery, []Row) {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Second)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	target, captures, base := peeringQueryFixture(t, tenant, at, count)
	states := []string{"eligible", "not_on_path", "ambiguous", "unavailable"}
	rows := make([]Row, count)
	for i := range captures {
		captures[i].Peering.Source = states[i%len(states)]
		captures[i].SourceIDs = []string{"original/source/" + states[i%len(states)]}
		captures[i].FactsID = [32]byte{31: byte(1 + i%len(states))}
		row := base
		var raw [32]byte
		binary.BigEndian.PutUint64(raw[:8], uint64(i+1))
		row.RawFlowDigest, row.RoutingCaptureKey = hex.EncodeToString(raw[:]), hex.EncodeToString(captures[i].Key[:])
		row.TS = at.Add(-5 * time.Second).Add(time.Duration(i%3) * 2 * time.Second)
		row.StartTS = row.TS
		row.InIf, row.OutIf = 1, 2
		if i%5 == 0 {
			row.InIf = 7
		}
		row.BytesScaled = ^uint64(0)
		rows[i] = row
	}
	data, err := NewPeeringQueryData(ctx, target, at, captures, 512<<20)
	if err != nil {
		t.Fatal(err)
	}
	role := InterfaceRoleProjection{Scope: target.Scope, RouterID: target.RouterID, InterfaceID: "44444444-4444-4444-8444-444444444444", Exporter: base.Exporter, Protocol: base.Protocol, Domain: base.ObsDomain, IfIndex: 1, Role: entity.InterfaceRoleTransit, Reason: "test-current", Sources: []string{"owned-source"}, ValidUntil: at.Add(time.Hour)}
	other := role
	other.IfIndex, other.Role, other.InterfaceID = 2, entity.InterfaceRoleIX, "55555555-5555-4555-8555-555555555555"
	roles, err := NewInterfaceRoleQueryData(ctx, tenant, at, []InterfaceRoleProjection{role, other}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, PeeringTrafficQuery{Data: data, Roles: roles, From: at.Add(-5 * time.Second), To: at, BucketSeconds: 2}, rows
}

func TestPeeringTrafficKeepsCompleteOwnedPopulationStatesAndExactPartialIntervals(t *testing.T) {
	const count = 50_001
	store := NewMemory()
	tenants := []string{"11111111-1111-4111-8111-111111111111", "66666666-6666-4666-8666-666666666666"}
	var first PeeringTrafficQuery
	for lane, tenant := range tenants {
		ctx, query, rows := peeringTrafficFixture(t, tenant, count)
		if lane == 0 {
			first = query
		}
		unowned := rows[0]
		unowned.Exporter = "192.0.2.2"
		unowned.RawFlowDigest = ""
		unowned.RoutingCaptureKey = ""
		unowned.RoutingCapturedUnixNanos = 0
		if err := store.Insert(ctx, append(slices.Clone(rows), unowned)); err != nil {
			t.Fatal(err)
		}
		batch, err := NewPlanBatch(ctx, store, tenant, 1)
		if err != nil {
			t.Fatal(err)
		}
		got, err := batch.PeeringTraffic(query)
		batch.Close()
		if err != nil {
			t.Fatal("complete peering traffic operation refused", err)
		}
		allBytes, allFlows := new(big.Int), new(big.Int)
		var unknown, partial bool
		states := map[string]bool{}
		for _, bucket := range got.Buckets {
			b, ok := new(big.Int).SetString(bucket.Bytes, 10)
			if !ok {
				t.Fatal(bucket)
			}
			allBytes.Add(allBytes, b)
			f, ok := new(big.Int).SetString(bucket.Flows, 10)
			if !ok {
				t.Fatal(bucket)
			}
			allFlows.Add(allFlows, f)
			unknown = unknown || bucket.InterfaceID == "" && bucket.Role == entity.InterfaceRoleOther
			partial = partial || bucket.End.Sub(bucket.Start) == time.Second && bucket.End.Equal(query.To)
			states[bucket.State] = true
		}
		want := new(big.Int).Mul(new(big.Int).SetUint64(^uint64(0)), big.NewInt(count))
		if allFlows.String() != strconv.Itoa(count) || allBytes.Cmp(want) != 0 || !unknown || !partial || len(states) != 4 || got.InputDigest != query.Data.digest || got.RoleDigest != query.Roles.digest {
			t.Fatal("peering aggregation dropped owned unknown/state traffic, included another router/tenant, truncated counters or lost partial intervals", allFlows, allBytes, unknown, partial, states)
		}
		if lane == 1 {
			if foreign, err := store.PeeringTraffic(ctx, first); !errors.Is(err, ErrRoutingQueryScope) || !reflect.DeepEqual(foreign, PeeringTrafficResult{}) {
				t.Fatal("peering storage accepted foreign tenant metadata", err)
			}
		}
	}
}

func TestPeeringTrafficRefusesMissingCurrentScopeBudgetAndInventedRows(t *testing.T) {
	ctx, query, rows := peeringTrafficFixture(t, "11111111-1111-4111-8111-111111111111", 20)
	store := NewMemory()
	if err := store.Insert(ctx, rows); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*PeeringTrafficQuery){
		func(q *PeeringTrafficQuery) { q.Data = nil }, func(q *PeeringTrafficQuery) { q.Roles = nil },
		func(q *PeeringTrafficQuery) {
			copyData := *q.Data
			copyData.target.RouterID = "99999999-9999-4999-8999-999999999999"
			q.Data = &copyData
		},
		func(q *PeeringTrafficQuery) { q.From = q.To },
	} {
		bad := query
		change(&bad)
		if got, err := store.PeeringTraffic(ctx, bad); err == nil || !reflect.DeepEqual(got, PeeringTrafficResult{}) {
			t.Fatal("invalid current peering target exposed traffic", err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := store.PeeringTraffic(canceled, query); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, PeeringTrafficResult{}) {
		t.Fatal("canceled peering query exposed partial traffic", err)
	}
	budget := DefaultExplorerBudget()
	budget.ReadRows = len(rows) - 1
	if err := AttachExplorerBudget(store, budget); err != nil {
		t.Fatal(err)
	}
	if got, err := store.PeeringTraffic(ctx, query); !errors.Is(err, ErrExplorerBudget) || !reflect.DeepEqual(got, PeeringTrafficResult{}) {
		t.Fatal("peering read returned an admitted prefix", err)
	}
	plan, err := normalizePeeringTraffic(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	valid := map[string]any{"bucket": "0", "interface_id": query.Roles.rows[0].InterfaceID, "role": "transit", "state": "eligible", "bytes": "184467440737095516160000", "flows": "10"}
	if got, err := decodePeeringTraffic(ctx, query, plan, "raw", []map[string]any{valid}, DefaultExplorerBudget()); err != nil || len(got.Buckets) != 1 {
		t.Fatal("exact peering decoder lost full counters", err)
	}
	for _, change := range []func(map[string]any){
		func(r map[string]any) { r["bucket"] = "3" }, func(r map[string]any) { r["bucket"] = "00" },
		func(r map[string]any) { r["bytes"] = "-1" }, func(r map[string]any) { r["flows"] = "0" },
		func(r map[string]any) { r["role"] = "customer" }, func(r map[string]any) { r["state"] = "assumed" },
		func(r map[string]any) { r["interface_id"] = "99999999-9999-4999-8999-999999999999" },
	} {
		bad := map[string]any{}
		for k, v := range valid {
			bad[k] = v
		}
		change(bad)
		if got, err := decodePeeringTraffic(ctx, query, plan, "raw", []map[string]any{valid, bad}, DefaultExplorerBudget()); err == nil || !reflect.DeepEqual(got, PeeringTrafficResult{}) {
			t.Fatal("malformed late peering aggregate exposed partial traffic", bad, err)
		}
	}
}

func TestPeeringTrafficSQLBindsTenantOriginalClockAndWholeStatePopulation(t *testing.T) {
	ctx, query, _ := peeringTrafficFixture(t, "11111111-1111-4111-8111-111111111111", 50_001)
	plan, err := normalizePeeringTraffic(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{sharedFlowsTable, sharedFlowRollupsTable} {
		sql, params, err := peeringTrafficSQL(query, plan, table, DefaultExplorerBudget())
		if err != nil || params["tenant"] != query.Data.target.TenantID {
			t.Fatal(err)
		}
		for _, term := range []string{"WHERE tenant_id={tenant:String} AND ts>=", "peer_owner.peer_tenant=tenant_id", "peer_iface.peer_tenant=tenant_id", "peer_iface.peer_domain=obs_domain", "peer_capture.peer_capture_tenant=tenant_id", "peer_capture.peer_key=routing_capture_key", "peer_capture.peer_clock=routing_captured_unix_nanos", "sum(toUInt256(bytes_scaled))", "GROUP BY bucket,interface_id,role,state"} {
			if !strings.Contains(sql, term) {
				t.Fatal("peering SQL lost complete scoped original inputs", term)
			}
		}
		for _, forbidden := range []string{" LIMIT ", "peer_state='eligible'", "HAVING", "max_result_rows=0", "overflow_mode='break'"} {
			if strings.Contains(sql, forbidden) {
				t.Fatal("peering SQL truncated or filtered the required population", forbidden)
			}
		}
	}
	external, err := peeringTrafficExternal(ctx, query, 64<<20)
	if err != nil || len(external) != 2 {
		t.Fatal(err)
	}
	var captures []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(external[1].rows), []byte("\n")) {
		var row map[string]any
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatal(err)
		}
		captures = append(captures, row)
	}
	if len(captures) != 50_001 {
		t.Fatal("peering external references truncated", len(captures))
	}
	for _, row := range captures {
		if row["peer_capture_tenant"] != query.Data.target.TenantID || row["peer_clock"] != strconv.FormatInt(query.Data.routing.asOf.UnixNano(), 10) || !validPeeringQueryState(row["peer_state"].(string)) {
			t.Fatal("peering external capture changed tenant, original clock or state")
		}
	}
	if got, err := peeringTrafficExternal(ctx, query, 1); !errors.Is(err, ErrExplorerBudget) || got != nil {
		t.Fatal("peering external admission exposed partial state", err)
	}
}
