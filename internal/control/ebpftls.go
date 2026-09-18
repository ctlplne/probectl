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
	"sort"
	"strconv"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/crypto"
	ebpfv1 "github.com/ctlplne/probectl/internal/gen/probectl/ebpf/v1"
	"github.com/ctlplne/probectl/internal/pipeline"
	"github.com/ctlplne/probectl/internal/threat"
)

// Why a TLS-posture record could not be projected. These are closed, low-cardinality
// reasons, safe to log and to count: none of them carries tenant data, a target, a
// certificate or any payload. DPR-196 — one bare "malformed" said nothing, and the
// one an operator was actually seeing was not malformed at all.
const (
	tlsSkipEmptyRecord       = "empty_record"
	tlsSkipNoIdentity        = "no_tenant_or_agent"
	tlsSkipNoTarget          = "no_destination" // the live C-library uprobe has no 5-tuple
	tlsSkipNoTimestamp       = "no_usable_timestamp"
	tlsSkipNoVersion         = "observed_without_tls_version"
	tlsSkipBadConfidence     = "confidence_out_of_range"
	tlsSkipBadVerification   = "unrecognized_verification_state"
	tlsSkipBadCertificate    = "unparseable_peer_certificate"
	tlsSkipUnknownVisibility = "unrecognized_visibility_state"
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

	// DPR-196: skip reasons are counted and summarized, not logged per batch.
	skipMu     sync.Mutex
	skipTotals map[string]uint64
	skipNext   time.Time
	nowFn      func() time.Time
}

func (cs *EBPFTLSPostureConsumer) now() time.Time {
	if cs.nowFn != nil {
		return cs.nowFn()
	}
	return time.Now()
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
	// DPR-196: one unprojectable record discarded the WHOLE batch, and the live
	// uprobe puts one in every batch, so the eBPF plane contributed nothing to the
	// inventory at all — four hours of soak, 17,690 L7 calls captured, and not one
	// eBPF posture entry beside the synthetic ones.
	//
	// The all-or-nothing refusal itself is kept, because it is a posture and not
	// an accident: a value a correct producer never emits — an unparseable
	// certificate, a confidence outside 0..100, a visibility state that does not
	// exist — is evidence about the producer, and §7.10 says treat its content as
	// untrusted. What was wrong is that ONE reason in that set is not evidence of
	// anything: a record with no destination is the documented live-uprobe shape
	// (it has no 5-tuple to report), and a target-keyed inventory simply has no
	// row for it. That one is skipped and counted; everything else still refuses
	// the batch, and now says which property failed.
	skipped := map[string]int{}
	for _, call := range calls {
		obs, posture, reason := ebpfTLSObservation(call)
		if reason == tlsSkipNoTarget {
			skipped[reason]++
			continue
		}
		if reason != "" {
			skipped[reason]++
			cs.countSkipped(call.GetAgentId(), len(calls), 0, skipped)
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
	cs.countSkipped(calls[0].GetAgentId(), len(calls), len(staged), skipped)
	return nil
}

// countSkipped accumulates the reasons records were not projected and reports
// them at a human rate rather than per batch.
//
// DPR-196: the old code logged one WARN per rejected batch, which on this lab
// meant 6,086 identical lines in four hours for a single known structural gap —
// enough noise to bury anything real and not enough information to act on. The
// counters are the operator's number; the log line is a summary, at most one per
// reason per reporting interval, and it names the reason.
func (cs *EBPFTLSPostureConsumer) countSkipped(agentID string, seen, projected int, skipped map[string]int) {
	if len(skipped) == 0 {
		return
	}
	cs.skipMu.Lock()
	if cs.skipTotals == nil {
		cs.skipTotals = map[string]uint64{}
	}
	for reason, n := range skipped {
		cs.skipTotals[reason] += uint64(n)
	}
	due := cs.skipNext.IsZero() || cs.now().After(cs.skipNext)
	var totals map[string]uint64
	if due {
		cs.skipNext = cs.now().Add(tlsSkipReportInterval)
		totals = make(map[string]uint64, len(cs.skipTotals))
		for k, v := range cs.skipTotals {
			totals[k] = v
		}
	}
	cs.skipMu.Unlock()
	if !due {
		return
	}
	reasons := make([]string, 0, len(totals))
	for r := range totals {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	attrs := []any{"agent_id", agentID, "calls_in_batch", seen, "projected_in_batch", projected}
	for _, r := range reasons {
		attrs = append(attrs, "skipped_"+r, totals[r])
	}
	// no_destination alone is the documented live-uprobe gap, not a fault: say so
	// rather than leaving an operator to conclude their agents are broken.
	if len(totals) == 1 && totals[tlsSkipNoTarget] > 0 {
		cs.log.Info("ebpf tls posture: records carry no destination, so they cannot enter a target-keyed inventory "+
			"(the live C-library uprobe has no 5-tuple — docs/limitations.md); nothing is wrong with the agent", attrs...)
		return
	}
	cs.log.Warn("ebpf tls posture: some records could not be projected; the rest were recorded", attrs...)
}

// tlsSkipReportInterval bounds how often the skip summary is logged per replica.
const tlsSkipReportInterval = 10 * time.Minute

// skippedTotals reports the accumulated skip reasons for this replica. Used by
// the tests and safe to expose: closed reasons and counts, no tenant data.
func (cs *EBPFTLSPostureConsumer) skippedTotals() map[string]uint64 {
	cs.skipMu.Lock()
	defer cs.skipMu.Unlock()
	out := make(map[string]uint64, len(cs.skipTotals))
	for k, v := range cs.skipTotals {
		out[k] = v
	}
	return out
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

// ebpfTLSObservation projects one L7 call into the posture inventory. The third
// return is a REASON when the record cannot be projected, empty when it can.
//
// DPR-196: it used to return a bare bool, and the caller logged "skipping
// malformed metadata batch" with nothing but the agent id — 6,086 times in a
// four-hour soak, naming the one field that was fine. Every rejection below is a
// different problem with a different answer, and the one the lab was actually
// hitting is not malformed data at all: the live C-library uprobe has no
// 5-tuple, so it carries no destination (internal/ebpf/l7chunk.go). A posture is
// keyed on its target, so such a record genuinely cannot enter the inventory —
// but it is an expected shape, not corruption, and it must not be reported as
// corruption.
func ebpfTLSObservation(call *ebpfv1.L7Call) (*threat.TLSObservation, *threat.Posture, string) {
	switch {
	case call == nil:
		return nil, nil, tlsSkipEmptyRecord
	case call.GetTenantId() == "" || call.GetAgentId() == "":
		return nil, nil, tlsSkipNoIdentity
	case call.GetDestination() == "" || call.GetDestinationPort() == 0:
		// The known live-uprobe gap, named as itself.
		return nil, nil, tlsSkipNoTarget
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
		return nil, nil, tlsSkipNoTimestamp
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
		}, ""
	case "observed":
		if call.GetTlsVersion() == "" {
			return nil, nil, tlsSkipNoVersion
		}
		if call.GetTlsConfidence() == 0 || call.GetTlsConfidence() > 100 {
			return nil, nil, tlsSkipBadConfidence
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
			return nil, nil, tlsSkipBadVerification
		}
		if len(call.GetTlsPeerCertificateDer()) > 0 {
			cert, err := crypto.ParseCertificate(call.GetTlsPeerCertificateDer())
			if err != nil {
				return nil, nil, tlsSkipBadCertificate
			}
			obs.Leaf = cert
		}
		return obs, nil, ""
	default:
		return nil, nil, tlsSkipUnknownVisibility
	}
}
