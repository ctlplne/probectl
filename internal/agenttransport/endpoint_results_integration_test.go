// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package agenttransport_test

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/endpoint"
	"github.com/ctlplne/probectl/internal/endpoint/wire"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestManagedEndpointEvidenceUsesTheCertificateTenantAndCurrentProcess(t *testing.T) {
	pool := setup(t.Context(), t)
	t.Cleanup(pool.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	server := startTestServer(ctx, t, pool)
	type device struct {
		tenant, id string
		client     agentv1.AgentServiceClient
	}
	var devices []device
	for _, name := range []string{"endpoint-evidence-red", "endpoint-evidence-blue"} {
		tenant, err := store.NewTenants(pool).Create(ctx, name+"-"+newUUID(t), name)
		if err != nil {
			t.Fatal(err)
		}
		client, id := agentClient(ctx, t, server, tenant.ID)
		devices = append(devices, device{tenant.ID, id, client})
	}
	red, blue := devices[0], devices[1]
	initial := wire.ManagedProcess{Platform: "darwin/arm64", RunID: newUUID(t)}
	withProcess := func(process wire.ManagedProcess) context.Context {
		return metadata.AppendToOutgoingContext(ctx, wire.ManagedProcessMetadata, process.HeaderValue())
	}
	register := func(d device, process wire.ManagedProcess) {
		t.Helper()
		resp, err := d.client.Register(withProcess(process), &agentv1.RegisterRequest{
			Hostname: "same-managed-host", AgentVersion: "0.0.0-dev",
		})
		if err != nil || resp.GetTenantId() != d.tenant || resp.GetAgentId() != d.id ||
			!slices.Contains(resp.GetServerCapabilities(), wire.ManagedProcessCapability) {
			t.Fatal("managed process registration was not confirmed", err)
		}
	}
	heartbeat := func(d device, claimedAgent string, process wire.ManagedProcess, want codes.Code) {
		t.Helper()
		_, err := d.client.Heartbeat(withProcess(process), &agentv1.HeartbeatRequest{AgentId: claimedAgent})
		if status.Code(err) != want {
			t.Fatalf("managed heartbeat: got %v, want %s", err, want)
		}
	}
	evidence := func(d device, wantRun, wantIdentity string, wantSeq int64) {
		t.Helper()
		scope := tenancy.WithTenant(ctx, tenancy.ID(d.tenant))
		err := tenancy.InTenant(scope, pool, func(ctx context.Context, sc tenancy.Scope) error {
			row, err := (store.Agents{}).Get(ctx, sc, d.id)
			if err != nil {
				return err
			}
			p := row.EndpointProcess
			if p == nil || p.RunID != wantRun || p.Sequence != wantSeq || p.ExecutableIdentity != wantIdentity ||
				(p.MeasuredAt != nil) != (wantIdentity != "") {
				t.Fatalf("registry stored the wrong process observation: %+v", p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// A run ID is just a local generation marker. Even a collision between
	// tenants must remain scoped to the certificate-bound agent and RLS row.
	register(red, initial)
	register(blue, initial)
	measured := initial
	measured.Sequence = 1
	measured.ExecutableIdentity = "cdhash:" + strings.Repeat("a", 40)
	heartbeat(blue, red.id, measured, codes.InvalidArgument)
	evidence(red, initial.RunID, "", 0)
	evidence(blue, initial.RunID, "", 0)
	heartbeat(red, red.id, measured, codes.OK)
	register(red, initial)
	heartbeat(red, red.id, measured, codes.FailedPrecondition)
	evidence(red, initial.RunID, measured.ExecutableIdentity, 1)
	evidence(blue, initial.RunID, "", 0)

	restarted := initial
	restarted.RunID = newUUID(t)
	register(red, restarted)
	measured.Sequence = 2
	heartbeat(red, red.id, measured, codes.FailedPrecondition)
	evidence(red, restarted.RunID, "", 0)
	heartbeat(blue, blue.id, measured, codes.OK)
	evidence(blue, initial.RunID, measured.ExecutableIdentity, 2)
	measured.Sequence = 3
	measured.ExecutableIdentity = ""
	heartbeat(blue, blue.id, measured, codes.OK)
	heartbeat(blue, blue.id, initial, codes.InvalidArgument)
	evidence(blue, initial.RunID, "", 3)
}

func TestEndpointResultsOverMTLSStayOnTheAuthenticatedTenantLane(t *testing.T) {
	pool := setup(t.Context(), t)
	t.Cleanup(pool.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	server := startTestServer(ctx, t, pool)
	type lane struct {
		tenant, agent, topic string
		client               agentv1.AgentServiceClient
	}
	var lanes []lane
	received := make(chan bus.Message, 2)
	for _, name := range []string{"endpoint-red", "endpoint-blue"} {
		tenant, err := store.NewTenants(pool).Create(ctx, name+"-"+newUUID(t), name)
		if err != nil {
			t.Fatal(err)
		}
		client, agent := agentClient(ctx, t, server, tenant.ID)
		reg, err := client.Register(ctx, &agentv1.RegisterRequest{Hostname: name, AgentVersion: "0.0.0-dev"})
		if err != nil || !slices.Contains(reg.GetServerCapabilities(), agenttransport.EndpointResultsCapability) {
			t.Fatal("endpoint ingress was not negotiated", err)
		}
		topic, err := bus.TopicFor(tenancy.BusNamespaceFor(tenant.Slug), bus.EndpointResultsTopic)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			_ = server.bus.Subscribe(ctx, topic, "endpoint-wire-test", func(_ context.Context, message bus.Message) error {
				select {
				case received <- message:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
		}()
		if !server.bus.WaitForSubscribers(ctx, topic, 1) {
			t.Fatal("endpoint lane did not subscribe")
		}
		lanes = append(lanes, lane{tenant.ID, agent, topic, client})
	}
	for i, own := range lanes {
		other := lanes[1-i]
		payload, err := proto.Marshal(&resultv1.Result{
			TenantId: other.tenant, AgentId: other.agent, CanaryType: endpoint.TypeAttribution,
			StartTimeUnixNano: time.Now().UnixNano(), Metrics: map[string]float64{"confidence": 0.6},
		})
		if err != nil {
			t.Fatal(err)
		}
		fresh, err := agenttransport.FreshnessMetadata(ctx)
		if err != nil {
			t.Fatal(err)
		}
		fresh = metadata.AppendToOutgoingContext(fresh, agenttransport.EndpointResultsMetadataKey, agenttransport.EndpointResultsCapability)
		stream, err := own.client.StreamResults(fresh)
		if err != nil {
			t.Fatal(err)
		}
		header, err := stream.Header()
		if err != nil || !slices.Equal(header.Get(agenttransport.EndpointResultsMetadataKey), []string{agenttransport.EndpointResultsCapability}) {
			t.Fatal("result stream did not negotiate endpoint routing", err)
		}
		if err := stream.Send(&agentv1.StreamResultsRequest{Type: agenttransport.EndpointResultsCapability, Payload: payload}); err != nil {
			t.Fatal(err)
		}
		if ack, err := stream.CloseAndRecv(); err != nil || ack.GetAccepted() != 1 {
			t.Fatalf("endpoint result ack for %s: %v %v", own.tenant, ack, err)
		}
		select {
		case message := <-received:
			var got resultv1.Result
			if err := proto.Unmarshal(message.Value, &got); err != nil || message.Topic != own.topic ||
				!bytes.Equal(message.Key, bus.TenantKey(own.tenant, own.agent)) ||
				got.GetTenantId() != own.tenant || got.GetAgentId() != own.agent || got.GetResultId() == "" {
				t.Fatalf("wrong endpoint lane or identity: %s %s/%s %v", message.Topic, got.GetTenantId(), got.GetAgentId(), err)
			}
		case <-ctx.Done():
			t.Fatal("tenant endpoint result was not delivered")
		}
	}
}
