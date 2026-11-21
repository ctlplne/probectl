// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/threat/dnstap"
)

func TestResolverDNSCapturePreservesOwnedIntervalsAndReplayPolicy(t *testing.T) {
	f := newRoleInputsFixture(t)
	registry := NewEntityRegistry(f.pool)
	fence := tenancy.NewPostgresWriterFence(f.pool)
	const sourceRef = "regional-resolver"
	const width = dnstap.ResolverInterval
	start := time.Now().UTC().Truncate(width).Add(-4 * width)
	assignment := start.Add(-width)
	policy := dnstap.PressurePolicy{Enabled: true, Rule: dnstap.DefaultPressureRule()}
	responsesByLane := [2]uint32{130, 140}
	var agents, serials [2]string
	write := func(tenant string, input ResolverDNSCaptureInput) (ResolverDNSCaptureResult, error) {
		var retained ResolverDNSCaptureResult
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		err := tenancy.FencedTenantWrite(ctx, fence, tenant, entity.ErrScopeMismatch, func(ctx context.Context) error {
			var err error
			retained, err = registry.CaptureResolverDNS(ctx, input)
			return err
		})
		return retained, err
	}
	read := func(tenant, scopeTenant, agent string) (ResolverDNSCoverage, error) {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		return registry.ReadResolverDNSCoverage(ctx, entity.Scope{TenantID: scopeTenant, ContextID: f.contextID},
			f.routerID, agent, sourceRef, 8)
	}
	for lane, tenant := range f.tenants {
		agent, serial := uuid.NewString(), strings.ReplaceAll(uuid.NewString(), "-", "")
		agents[lane], serials[lane] = agent, serial
		if err := NewAgentIdentities(f.pool).Record(t.Context(), tenant, agent, crypto.EntitySPIFFEID(tenant, agent), serial, start.Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (Agents{}).Register(ctx, sc, agent, "Resolver test sender", "127.0.0.1", "fixture", crypto.AgentSPIFFEID(tenant, agent), nil); err != nil {
				return err
			}
			if err := registry.AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: agent, Kind: entity.DNSResolver, SourceRef: sourceRef}, f.contextID, f.routerID); err != nil {
				return err
			}
			// Model a credential and assignment that were active for the
			// completed synthetic windows, using one identical clock per lane.
			for _, query := range []string{
				`UPDATE agent_identities SET issued_at=$3 WHERE tenant_id=$1 AND agent_id=$2`,
				`UPDATE entity_agent_contexts SET assigned_at=$3 WHERE tenant_id=$1 AND agent_id=$2`,
				`UPDATE entity_source_contexts SET assigned_at=$3 WHERE tenant_id=$1 AND agent_id=$2`,
			} {
				if _, err := sc.Q.Exec(ctx, query, tenant, agent, assignment); err != nil {
					return err
				}
			}
			return nil
		})
		if got, err := read(tenant, tenant, agent); err != nil || got.Status != "no_recent_capture" || len(got.Observations) != 0 {
			t.Fatalf("unobserved resolver: got %+v, err %v", got, err)
		}
	}
	for lane, tenant := range f.tenants {
		responses := responsesByLane[lane]
		first := dnstap.ResolverIntervalCounts{From: start, To: start.Add(width), Responses: responses, NameErrors: 70}
		input := ResolverDNSCaptureInput{AgentID: agents[lane], CertificateSerial: serials[lane], SourceRef: sourceRef,
			Digest: [32]byte{1}, Policy: policy,
			Capture: dnstap.ClosedCapture{Frames: responses, Selected: responses, Intervals: []dnstap.ResolverIntervalCounts{first}}}
		foreign := input
		foreign.CertificateSerial = serials[1-lane]
		if got, err := write(tenant, foreign); !errors.Is(err, ErrEvidenceIdentityInactive) || got.Identity.AgentID != "" {
			t.Fatalf("foreign certificate admitted in lane %d: got %+v, err %v", lane, got, err)
		}
		got, err := write(tenant, input)
		if err != nil || got.Identity.DeviceID != f.routerID || got.Identity.ContextID != f.contextID ||
			!got.Identity.SourceAssignedAt.Equal(assignment) || got.Policy != policy || len(got.Previous) != 0 {
			t.Fatalf("first owned capture in lane %d: got %+v, err %v", lane, got, err)
		}
		replay := input
		replay.Policy.Enabled = false
		if got, err := write(tenant, replay); err != nil || got.Policy != policy {
			t.Fatalf("exact replay must keep the original policy in lane %d: got %+v, err %v", lane, got, err)
		}
		replay.Digest = [32]byte{2}
		if got, err := write(tenant, replay); !errors.Is(err, ErrResolverDNSConflict) || got.Identity.AgentID != "" {
			t.Fatalf("different digest rewrote the original in lane %d: got %+v, err %v", lane, got, err)
		}
		next := first
		next.From, next.To = first.To, first.To.Add(width)
		input.Digest = [32]byte{3}
		input.Capture.Intervals = []dnstap.ResolverIntervalCounts{next}
		got, err = write(tenant, input)
		if err != nil || len(got.Previous) != 1 || got.Previous[0] != first {
			t.Fatalf("adjacent owned minute was lost in lane %d: got %+v, err %v", lane, got, err)
		}
	}
	for lane, tenant := range f.tenants {
		owned, err := read(tenant, tenant, agents[lane])
		if err != nil || owned.Status != "missing_closed_file_intervals" || owned.Expected != 8 || len(owned.Observations) != 2 ||
			owned.Observations[0].Responses != responsesByLane[lane] || !owned.Observations[0].To.Equal(owned.Observations[1].From) {
			t.Fatalf("coverage lost owned intervals or filled missing minutes in lane %d: got %+v, err %v", lane, owned, err)
		}
		if got, err := read(tenant, tenant, agents[1-lane]); !errors.Is(err, ErrResolverDNSUnavailable) || len(got.Observations) != 0 {
			t.Fatalf("foreign assignment visible in lane %d: got %+v, err %v", lane, got, err)
		}
		if got, err := read(tenant, f.tenants[1-lane], agents[1-lane]); !errors.Is(err, entity.ErrScopeMismatch) || len(got.Observations) != 0 {
			t.Fatalf("tenant context accepted mismatched scope in lane %d: got %+v, err %v", lane, got, err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var count, responses int64
			if err := sc.Q.QueryRow(ctx, `SELECT count(*), sum(client_responses) FROM resolver_dns_intervals`).Scan(&count, &responses); err != nil {
				return err
			}
			if count != 2 || responses != 2*int64(responsesByLane[lane]) {
				t.Fatalf("unfiltered SQL in lane %d saw %d intervals and %d responses", lane, count, responses)
			}
			return nil
		})
	}
}
