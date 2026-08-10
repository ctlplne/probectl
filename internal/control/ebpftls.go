// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/crypto"
	ebpfv1 "github.com/ctlplne/probectl/internal/gen/probectl/ebpf/v1"
	"github.com/ctlplne/probectl/internal/pipeline"
	"github.com/ctlplne/probectl/internal/threat"
)

// EBPFTLSPostureConsumer projects only privacy-minimized TLS handshake and
// certificate metadata from eBPF L7 calls into the tenant posture inventory.
// It never copies method, resource, status, or application payload.
type EBPFTLSPostureConsumer struct {
	bus       bus.Bus
	postures  *threat.PostureStore
	analyzer  *threat.Analyzer
	binding   pipeline.TenantBinding
	nsTenants map[string]string
	log       *slog.Logger
}

// NewEBPFTLSPostureConsumer builds the always-on eBPF TLS read-model consumer.
func NewEBPFTLSPostureConsumer(b bus.Bus, ps *threat.PostureStore, analyzer *threat.Analyzer, log *slog.Logger) *EBPFTLSPostureConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &EBPFTLSPostureConsumer{bus: b, postures: ps, analyzer: analyzer, log: log}
}

// WithTenantBinding installs the production registry-backed identity check.
func (cs *EBPFTLSPostureConsumer) WithTenantBinding(binding pipeline.TenantBinding) *EBPFTLSPostureConsumer {
	cs.binding = binding
	return cs
}

// WithNamespaceTenants fans the consumer into siloed/hybrid lanes.
func (cs *EBPFTLSPostureConsumer) WithNamespaceTenants(ns map[string]string) *EBPFTLSPostureConsumer {
	cs.nsTenants = ns
	return cs
}

// LaneFanoutEnabled satisfies pipeline.LaneFanout.
func (cs *EBPFTLSPostureConsumer) LaneFanoutEnabled() bool { return true }

// Run builds the full per-replica posture view from pooled and namespaced eBPF lanes.
func (cs *EBPFTLSPostureConsumer) Run(ctx context.Context) error {
	return pipeline.RunLanes(ctx, cs.bus, bus.EBPFFlowsTopic, viewGroup("tls-posture-ebpf"), cs.nsTenants, cs.handleLane)
}

func (cs *EBPFTLSPostureConsumer) handle(ctx context.Context, msg bus.Message) error {
	return cs.handleLane(ctx, msg, "")
}

func (cs *EBPFTLSPostureConsumer) handleLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	if cs.postures == nil || cs.analyzer == nil {
		return nil
	}
	var batch ebpfv1.FlowBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		cs.log.Warn("ebpf tls posture: skipping malformed batch", "error", err)
		return nil
	}
	stampEBPFBatchLaneTenant(&batch, laneTenant)

	calls := make([]*ebpfv1.L7Call, 0, len(batch.GetL7Calls()))
	ids := make([]pipeline.Identity, 0, len(batch.GetL7Calls()))
	for _, call := range batch.GetL7Calls() {
		if call.GetTlsVisibility() == "" {
			continue
		}
		calls = append(calls, call)
		ids = append(ids, pipeline.Identity{Tenant: call.GetTenantId(), Agent: call.GetAgentId()})
	}
	if len(calls) == 0 {
		return nil
	}
	if cs.binding != nil {
		if _, _, err := pipeline.VerifyBatchTenant(ctx, cs.binding, laneTenant, ids); err != nil {
			cs.log.Error("REJECTED eBPF TLS posture batch: tenant verification failed (fail closed)",
				"claimed_tenant", calls[0].GetTenantId(), "agent_id", calls[0].GetAgentId(), "error", err.Error())
			return nil
		}
	} else if !homogeneousTLSIdentities(ids) {
		cs.log.Warn("ebpf tls posture: skipping unscoped or mixed-tenant batch")
		return nil
	}

	// Validate and parse the WHOLE batch before mutating the view. One malformed
	// record therefore cannot leave a partial posture update behind.
	type stagedPosture struct {
		tenant  string
		posture threat.Posture
	}
	staged := make([]stagedPosture, 0, len(calls))
	for _, call := range calls {
		obs, posture, ok := ebpfTLSObservation(call)
		if !ok {
			cs.log.Warn("ebpf tls posture: skipping malformed metadata batch", "agent_id", call.GetAgentId())
			return nil
		}
		if obs != nil {
			staged = append(staged, stagedPosture{tenant: call.GetTenantId(), posture: cs.analyzer.Analyze(ctx, *obs)})
		} else {
			staged = append(staged, stagedPosture{tenant: call.GetTenantId(), posture: *posture})
		}
	}
	for _, item := range staged {
		cs.postures.Record(item.tenant, item.posture)
	}
	return nil
}

func homogeneousTLSIdentities(ids []pipeline.Identity) bool {
	if len(ids) == 0 || ids[0].Tenant == "" || ids[0].Agent == "" {
		return false
	}
	for _, id := range ids[1:] {
		if id != ids[0] {
			return false
		}
	}
	return true
}

func ebpfTLSObservation(call *ebpfv1.L7Call) (*threat.TLSObservation, *threat.Posture, bool) {
	if call == nil || call.GetTenantId() == "" || call.GetAgentId() == "" || call.GetDestination() == "" || call.GetDestinationPort() == 0 {
		return nil, nil, false
	}
	target := call.GetTlsServerName()
	if target == "" {
		target = call.GetDestination()
	}
	target = net.JoinHostPort(target, strconv.Itoa(int(call.GetDestinationPort())))
	at := time.Unix(0, call.GetTlsHandshakeUnixNano())
	if call.GetTlsHandshakeUnixNano() <= 0 {
		at = time.Unix(0, call.GetStartUnixNano())
	}
	if at.UnixNano() <= 0 {
		return nil, nil, false
	}
	capture := call.GetTlsObservationSource()
	if capture == "" {
		capture = "unknown"
	}
	switch call.GetTlsVisibility() {
	case "encrypted_unknown", "sidecar_unknown", "unsupported":
		state := threat.PostureUnknown
		if call.GetTlsVisibility() == "unsupported" {
			state = threat.PostureUnsupported
		}
		return nil, &threat.Posture{
			Target: target, Source: "ebpf", State: state, Visibility: call.GetTlsVisibility(),
			Capture: capture, Confidence: int(call.GetTlsConfidence()), Freshness: "current",
			Severity: threat.SeverityInfo, ObservedAt: at,
		}, true
	case "observed":
		if call.GetTlsVersion() == "" || call.GetTlsConfidence() == 0 || call.GetTlsConfidence() > 100 {
			return nil, nil, false
		}
		obs := &threat.TLSObservation{
			Target: target, Source: "ebpf", TLSVersion: call.GetTlsVersion(), Cipher: call.GetTlsCipher(),
			ObservedAt: at, State: threat.PostureObserved, Visibility: "observed",
			Capture: capture, Confidence: int(call.GetTlsConfidence()),
		}
		switch call.GetTlsVerification() {
		case "verified":
			verified := true
			obs.Verified = &verified
		case "unverified":
			verified := false
			obs.Verified = &verified
		case "", "unknown":
		default:
			return nil, nil, false
		}
		if len(call.GetTlsPeerCertificateDer()) > 0 {
			cert, err := crypto.ParseCertificate(call.GetTlsPeerCertificateDer())
			if err != nil {
				return nil, nil, false
			}
			obs.Leaf = cert
		}
		return obs, nil, true
	default:
		return nil, nil, false
	}
}
