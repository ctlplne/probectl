// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Seed a modeled long-lived source and complete historical receipts through
// actual application-role storage. Captures here are NOT claimed as network
// mTLS receipts: the real sender/witness writer has its separate standing proof.
// The serving root exercises real RLS/receipt joins and exact retained counters.
func seedCapacityBillingMonth(f *roleExplanationAPIFixture, memory *flowstore.Memory, tenant string, from, to time.Time) {
	seedCapacityCounterPeriod(f, memory, tenant, from, to, false)
}

func seedCapacityCounterPeriod(f *roleExplanationAPIFixture, memory *flowstore.Memory, tenant string, from, to time.Time, growing bool) {
	f.t.Helper()
	assigned := from.Add(-time.Hour)
	var captured time.Time
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if err := sourceepoch.PrepareInScope(ctx, sc); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `UPDATE entities SET created_at=$3 WHERE tenant_id=$1 AND context_id=$2`, tenant, f.contextID, assigned); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `UPDATE entity_agent_contexts SET assigned_at=$3 WHERE tenant_id=$1 AND context_id=$2`, tenant, f.contextID, assigned); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET assigned_at=$3 WHERE tenant_id=$1 AND context_id=$2`, tenant, f.contextID, assigned); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET issued_at=$3 WHERE tenant_id=$1 AND agent_id=$2`, tenant, "role-snmp", assigned); err != nil {
			return err
		}
		var allowed bool
		if err := sc.Q.QueryRow(ctx, `SELECT NOT invalidating AND observation_not_before<=$2 FROM flow_snapshot_epochs WHERE tenant_id=$1`, tenant, from).Scan(&allowed); err != nil {
			return err
		}
		if !allowed {
			return fmt.Errorf("modeled history is outside the actual erasure fence; fixture cannot lower it")
		}
		return sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&captured)
	})
	var keys, digests [][]byte
	var clocks []int64
	ctx := tenancy.WithTenant(f.t.Context(), tenancy.ID(tenant))
	inputBudget := flowstore.CounterBudget{MemoryBytes: 128 << 20, WorkUnits: 128 << 20, Timeout: time.Minute}
	inValue, outValue := uint64(1<<32-1000), ^uint64(0)-999
	ticks, phase, step := uint32(100000), uint64(1), uint64(0)
	count := int(to.Sub(from) / (5 * time.Minute))
	for i := 0; i <= count; i++ {
		at := from.Add(time.Duration(i) * 5 * time.Minute)
		var raw [16]byte
		binary.BigEndian.PutUint64(raw[:8], inValue)
		binary.BigEndian.PutUint64(raw[8:16], outValue)
		var digest [32]byte
		copy(digest[:], crypto.Hash(append(raw[:], []byte(strconv.FormatInt(at.UnixNano(), 10))...)))
		key, err := entity.CounterCaptureKey(tenant, "role-snmp", digest, entity.CounterCaptureInput{ConfiguredTarget: "192.0.2.1", PollStartedAt: at, PollCompletedAt: at, PointCount: 2})
		if err != nil {
			f.t.Fatal(err)
		}
		keys = append(keys, append([]byte(nil), key[:]...))
		digests = append(digests, append([]byte(nil), digest[:]...))
		clocks = append(clocks, at.UnixNano())
		rows := []flowstore.CounterRow{}
		for _, direction := range []string{"in", "out"} {
			value, width := inValue, uint32(32)
			if direction == "out" {
				value, width = outValue, 64
			}
			rows = append(rows, flowstore.CounterRow{TenantID: tenant,
				CounterSource: flowstore.CounterSource{ContextID: f.contextID, DeviceID: f.routerID, AgentID: "role-snmp", SourceRef: "192.0.2.1", SourceAssignedAt: assigned, AgentAssignedAt: assigned},
				SenderSerial:  f.serials[tenant+"role-snmp"], CaptureKey: key, RawDigest: digest, CapturedAt: captured, PollStartedAt: at, PollCompletedAt: at,
				Population: 2, IfIndex: 7, Name: "probectl.device.if." + direction + ".octets", Value: value, Width: width,
				UptimeTicks: ticks, UptimeKnown: true, DiscontinuityKnown: true})
		}
		if err := memory.InsertCounterPoll(ctx, rows, inputBudget); err != nil {
			f.t.Fatal(err)
		}
		if growing {
			bps := 8_000_000 + 800*step + 400 + 80*(step%288)
			inValue = (inValue + bps*300/8) % (1 << 32)
			outValue += 4_000_000 * 300 / 8
		} else {
			inValue = (inValue + phase*30000) % (1 << 32)
			outValue += 600000
		}
		step++
		phase = phase%20 + 1
		ticks += 30000
	}
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `INSERT INTO device_counter_captures(tenant_id,capture_key,captured_at)
 SELECT $1,k,$3 FROM unnest($2::bytea[]) AS input(k)`, tenant, keys, captured); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO device_counter_capture_sources
 (tenant_id,capture_key,context_id,device_id,agent_id,source_ref,sender_serial,source_assigned_at,agent_assigned_at,raw_digest,poll_started_unix_nanos,poll_completed_unix_nanos,point_count)
 SELECT $1,k,$4,$5,'role-snmp','192.0.2.1',$6,$7,$7,d,n,n,2
 FROM unnest($2::bytea[],$3::bytea[],$8::bigint[]) AS input(k,d,n)`, tenant, keys, digests, f.contextID, f.routerID, f.serials[tenant+"role-snmp"], assigned, clocks)
		return err
	})
}
