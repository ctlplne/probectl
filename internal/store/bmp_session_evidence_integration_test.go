// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package store

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestBMPSessionEvidenceKeepsOrderedScopedOriginals(t *testing.T) {
	f := newRoleInputsFixture(t)
	fence := tenancy.NewPostgresWriterFence(f.pool)
	const sharedConnection = "8b5641a6-6706-4c1e-b189-2932fb9276de"
	budget := bgp.PeerMessageBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20}
	for lane, tenant := range f.tenants {
		source := routingFixtureSource(f, lane)
		other := routingFixtureSource(f, 1-lane)
		write := func(input BMPSessionEvidenceInput) (bool, error) {
			var gap bool
			ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
			err := tenancy.FencedTenantWrite(ctx, fence, tenant, tenancy.ErrNoTenant, func(ctx context.Context) error {
				return tenancy.InTenant(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
					result, err := RecordBMPSessionEvidenceInScope(ctx, sc, input, budget, BMPSessionSignalPolicy{})
					gap = result.CoverageGap
					return err
				})
			})
			return gap, err
		}
		value := uint64(math.MaxUint64) - uint64(lane)
		frame := bmpIntegrationStatistics(value)
		input := BMPSessionEvidenceInput{CollectorAgentID: source.CollectorAgentID, SenderSerial: source.SenderSerial,
			SourceRef: source.SourceRef, OriginSerial: source.OriginSerial, ConnectionID: sharedConnection,
			Sequence: 1, ObservedAt: routingFixtureTime(f), Frame: frame}
		copy(input.Digest[:], crypto.Hash(frame))
		for range 2 {
			if gap, err := write(input); err != nil || gap {
				t.Fatal("complete original or exact retry failed", gap, err)
			}
		}
		conflict := input
		conflict.Frame = bmpIntegrationStatistics(42)
		copy(conflict.Digest[:], crypto.Hash(conflict.Frame))
		if _, err := write(conflict); !errors.Is(err, ErrBMPSessionEvidenceConflict) {
			t.Fatal("same sequence replaced original evidence", err)
		}
		foreign := input
		foreign.OriginSerial, foreign.Sequence = other.OriginSerial, 2
		if _, err := write(foreign); !errors.Is(err, ErrBGPRoutingSourceUnavailable) {
			t.Fatal("sibling origin credential selected this tenant's source", err)
		}
		closed := input
		closed.TransportClosed, closed.Frame, closed.Sequence = true, nil, 3
		copy(closed.Digest[:], crypto.Hash([]byte("transport close")))
		if gap, err := write(closed); err != nil || !gap {
			t.Fatal("an abrupt disconnect did not leave a coverage gap", gap, err)
		}
		input.Sequence = 4
		if _, err := write(input); !errors.Is(err, ErrBMPSessionEvidenceConflict) {
			t.Fatal("an authenticated retry reopened a closed connection", err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var storedTenant, storedGauge string
			var rows int
			err := sc.Q.QueryRow(ctx, `SELECT tenant_id::text,evidence#>>'{statistics,samples,0,value}',count(*) OVER ()
 FROM bmp_session_evidence ORDER BY source_sequence LIMIT 1`).Scan(&storedTenant, &storedGauge, &rows)
			if err != nil || storedTenant != tenant || storedGauge != strconv.FormatUint(value, 10) || rows != 2 {
				t.Fatal("unfiltered storage changed exact gauge or crossed tenant RLS", rows, err)
			}
			return nil
		})
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		if err := tenancy.InTenantReadSnapshot(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			selection := BMPSessionHistorySelection{Source: BMPSessionSource{ContextID: source.ContextID, RouterID: source.RouterID,
				CollectorAgentID: source.CollectorAgentID, SourceRef: source.SourceRef}, From: input.ObservedAt.Add(-time.Second),
				To: input.ObservedAt.Add(time.Second), Peer: "192.0.2.1", Limit: 1}
			profile := BGPRoutingBudget{MemoryBytes: 1 << 20, WorkUnits: 100}
			first, more, err := BMPSessionHistoryInScope(ctx, sc, selection, profile)
			if err != nil || !more || len(first) != 1 || first[0].Sequence != 3 || !first[0].CoverageGap {
				t.Fatal("first scoped page did not retain the same-clock transport gap", first, more, err)
			}
			selection.After = &first[0].BMPSessionHistoryPosition
			second, more, err := BMPSessionHistoryInScope(ctx, sc, selection, profile)
			if err != nil || more || len(second) != 1 || second[0].Sequence != 1 || second[0].Statistics == nil ||
				second[0].Statistics.Samples[0].Value != value || second[0].Nanos != first[0].Nanos {
				t.Fatal("same-clock continuation lost or crossed the original exact gauge", second, more, err)
			}
			selection.Source.SourceRef = "unassigned-router"
			if _, _, err := BMPSessionHistoryInScope(ctx, sc, selection, profile); !errors.Is(err, ErrBGPRoutingSourceUnavailable) {
				t.Fatal("unassigned router selected retained history", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func bmpIntegrationStatistics(value uint64) []byte {
	const prefix = 6 + 42 + 4
	frame := make([]byte, prefix+4+8)
	frame[0], frame[5] = 3, 1
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(frame)))
	copy(frame[28:32], []byte{192, 0, 2, 1})
	binary.BigEndian.PutUint32(frame[48:52], 1)
	binary.BigEndian.PutUint16(frame[prefix:prefix+2], 18)
	binary.BigEndian.PutUint16(frame[prefix+2:prefix+4], 8)
	binary.BigEndian.PutUint64(frame[prefix+4:], value)
	return frame
}
