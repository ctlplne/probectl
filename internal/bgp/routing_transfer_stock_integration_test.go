// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && linux

package bgp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
	"github.com/ctlplne/probectl/pkg/sdk"
)

const (
	transferStockAddress   = "203.0.113.200"
	transferStockPackets   = 768
	transferStockPayload   = 1200
	transferStockWireBytes = transferStockPackets * (transferStockPayload + 28) // fixed IPv4 and UDP headers
)

type transferStockLane struct {
	reg       edgeFlowRegistration
	counters  string
	exporter  string
	collector string
	portIDs   [2]string
	before    transferStockPoll
	after     transferStockPoll
}

// The outbound payload enters the lab router from the standby provider link.
// Actual FRRouting selects the other link, and the owned receiver counts each
// packet independently of the stock IPFIX and SNMP readers.
func TestFRRRoutingTransferUsesStockEgressAndIndependentSignedCounters(t *testing.T) {
	artifacts := newTransferArtifacts(t)
	lab := startRoutingLabNamed(t, "probectl-qa-beta-transfer-stock-"+strconv.FormatInt(time.Now().UnixNano()%1e8, 36))
	links, community := configureTransferStockHandoffs(t, lab)
	exporterImage := buildRoleRouterExporter(t, lab)
	st := shipped.Start(t, shipped.Options{Name: "transferstock", TenantBand: 4, Env: map[string]string{
		"PROBECTL_REMEDIATION_APPROVALS_ENABLED": "true",
		"PROBECTL_REMEDIATION_MAX_BLAST_RADIUS":  "512",
	}})
	first := registerEdgeFlowEvidence(t, st, lab.ip["rtr-a"])
	second := registerEdgeFlowEvidence(t, st, lab.ip["rtr-a"], registerSecondRouterTenant(t, st, first))
	lanes := [2]transferStockLane{{reg: first}, {reg: second}}
	const reviewerEmail = "alice@acme.example"
	reviewers := [2]string{
		st.SignIn(t, first.tenantID, reviewerEmail, "FX-2 Router"),
		st.SignIn(t, second.tenantID, reviewerEmail, "FX-2 Router Blue"),
	}
	prepareTransferStockCollectors(t, lab, st, links, community, exporterImage, &lanes)
	artifacts.startPCAP(t, lab, lanes)
	defer artifacts.exporterLogs(t, lanes)
	warmTransferStockExporters(t, lab, st, links[0], lanes)
	artifacts.bindings(t, st, lanes)
	installTransferStockWorkload(t, lab)
	probes := prepareTransferStockProbes(t, lab, st, lanes, links)
	assertTransferStockKernelPath(t, lab, links[0])

	// An empty flow table can still have warm-up packets in its capture ring.
	// Start fresh rings while keeping the authenticated collectors and bindings.
	for _, lane := range lanes {
		lab.docker(t, "restart", "-t", "2", lane.exporter)
		shipped.Await(t, "fresh stock exporter capture ring", 15*time.Second, func() bool {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			return exec.CommandContext(ctx, "docker", "exec", lane.exporter,
				"softflowctl", "-c", "/tmp/softflowd.ctl", "delete-all").Run() == nil
		})
	}
	started := time.Now().UTC()
	waitTransferStock(t, time.Minute, func() bool {
		now := time.Now().UTC()
		for i := range lanes {
			lanes[i].before = readTransferStockPoll(t, &lanes[i], links, started, now, false)
		}
		return !lanes[0].before.started.IsZero() && !lanes[1].before.started.IsZero()
	})
	comparisons, comparisonEnd := collectTransferStockComparisons(t, probes)
	sendTransferStockPayload(t, lab, links, artifacts)
	if wait := time.Until(comparisonEnd); wait > 0 {
		time.Sleep(wait)
	}
	finished := time.Now().UTC()
	waitTransferStock(t, time.Minute, func() bool {
		for i := range lanes {
			lanes[i].after = readTransferStockPoll(t, &lanes[i], links, finished, time.Now(), true)
		}
		return !lanes[0].after.started.IsZero() && !lanes[1].after.started.IsZero()
	})
	artifacts.counterBrackets(t, lanes)

	// The ring drain can transmit more frames than libpcap delivers to
	// softflowd. Keep that maintenance traffic after both signed brackets.
	artifacts.exporterState(t, lanes, "before-drain")
	if !transferStockCaptureComplete(t.Context(), lanes[0].exporter) ||
		!transferStockCaptureComplete(t.Context(), lanes[1].exporter) {
		drainTransferStockCapture(t, lab, links[0])
	}
	var complete [2]bool
	waitTransferStock(t, 12*time.Second, func() bool {
		for i, lane := range lanes {
			complete[i] = transferStockCaptureComplete(t.Context(), lane.exporter)
		}
		return complete[0] && complete[1]
	})
	artifacts.exporterState(t, lanes, "before-expire-all")
	for i, lane := range lanes {
		if !complete[i] {
			t.Errorf("lane %d stock capture missed the exact %d datagrams and %d wire bytes", i, transferStockPackets, transferStockWireBytes)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		out, err := exec.CommandContext(ctx, "docker", "exec", lane.exporter,
			"softflowctl", "-c", "/tmp/softflowd.ctl", "expire-all").CombinedOutput()
		cancel()
		artifacts.write(t, "exporter-"+strconv.Itoa(i)+"-expire-all.txt", out)
		if err != nil {
			t.Errorf("force lane %d stock flow export: %v %.300s", i, err, out)
		}
	}
	artifacts.exporterState(t, lanes, "after-expire-all")

	var inputs [2]sdk.RoutingTransferInput
	var measured [2]sdk.RoutingTransferInput
	var estimates [2]sdk.RoutingTransferResponse
	var bracketed, estimated [2]bool
	for i := range lanes {
		lane := &lanes[i]
		if lane.before.started.IsZero() {
			t.Errorf("lane %d has no complete pre-workload poll", i)
		}
		if lane.after.started.IsZero() {
			t.Errorf("lane %d has no complete post-workload poll", i)
		}
		if lane.before.started.IsZero() || lane.after.started.IsZero() {
			t.Logf("lane %d estimates require both independent counter brackets", i)
			continue
		}
		if !t.Run("signed-counters-"+strconv.Itoa(i), func(t *testing.T) {
			verifyTransferStockPolls(t, st, lane)
		}) {
			continue
		}
		if !t.Run("agreements-"+strconv.Itoa(i), func(t *testing.T) {
			inputs[i] = makeTransferStockRequest(t, st, lane, int64(4+3*i), int64(1+i))
		}) {
			continue
		}
		bracketed[i] = true
		measured[i] = inputs[i]
		measured[i].ProbeComparison = comparisons[i]
		if comparisons[i].Source.TestId == "" {
			t.Logf("lane %d recommendation requires both signed probe observations", i)
			continue
		}
		estimates[i], estimated[i] = awaitTransferStockPerformance(t, st, *lane, links[0].index, i, measured[i])
		if estimated[i] {
			estimated[i] = t.Run("arithmetic-"+strconv.Itoa(i), func(t *testing.T) {
				assertTransferStockEstimate(t, *lane, links, estimates[i], int64(4+3*i), int64(1+i))
			})
		}
	}
	artifacts.flowRows(t, st, lanes, links[0].index)
	for i, lane := range lanes {
		if !bracketed[i] {
			t.Logf("lane %d request controls require its independently bracketed agreements", i)
			continue
		}
		if bracketed[1-i] {
			foreign := inputs[i]
			foreign.Candidate = inputs[1-i].Candidate
			if code, _ := st.Do(t, lane.reg.cookie, http.MethodPost, "/v1/flows/routing-transfer-estimate", foreign); code != http.StatusNotFound {
				t.Errorf("lane %d accepted the sibling's agreement: HTTP %d", i, code)
			}
		} else {
			t.Logf("lane %d sibling-agreement control requires an independently bracketed sibling agreement", i)
		}
		if comparisons[i].Source.TestId != "" && comparisons[1-i].Candidate.TestId != "" {
			foreignProbe := measured[i]
			foreignProbe.ProbeComparison.Candidate = measured[1-i].ProbeComparison.Candidate
			if code, _ := st.Do(t, lane.reg.cookie, http.MethodPost, "/v1/flows/routing-transfer-estimate", foreignProbe); code != http.StatusNotFound {
				t.Errorf("lane %d accepted the sibling's measured probe: HTTP %d", i, code)
			}
		}
		limited := inputs[i]
		limited.Candidate.PhysicalBounds = append([]sdk.CapacityPhysicalBound(nil), limited.Candidate.PhysicalBounds...)
		// Use half of the observed moved rate as headroom. That admits
		// the real standby's control traffic but keeps the transfer infeasible.
		span := lane.after.started.Sub(lane.before.started)
		standbyBPS := transferStockRate(lane.after.octets[1]-lane.before.octets[1], span)
		midpoint := new(big.Rat).Add(standbyBPS, transferStockRate(transferStockWireBytes/2, span))
		ceiling := new(big.Int).Quo(midpoint.Num(), midpoint.Denom())
		limited.Candidate.PhysicalBounds[0].MaxBps = ceiling.String()
		code, body := st.Do(t, lane.reg.cookie, http.MethodPost, "/v1/flows/routing-transfer-estimate", limited)
		var refused sdk.RoutingTransferResponse
		if code != http.StatusOK || json.Unmarshal(body, &refused) != nil || refused.Estimate.Reason != "projected_egress_exceeds_capacity" || refused.Policy.ExactPrefix != "" {
			t.Errorf("lane %d used a candidate without enough measured headroom: HTTP %d %s", i, code, body)
		}

		missing := inputs[i]
		missing.ObservedFrom = lane.before.started.Add(-45 * time.Minute).Format(time.RFC3339Nano)
		code, body = st.Do(t, lane.reg.cookie, http.MethodPost, "/v1/flows/routing-transfer-estimate", missing)
		var incomplete sdk.RoutingTransferResponse
		if code != http.StatusOK || json.Unmarshal(body, &incomplete) != nil || incomplete.Estimate.Status != "unavailable" ||
			incomplete.Estimate.NetChargeChange != "" || incomplete.Policy.ExactPrefix != "" {
			t.Errorf("lane %d priced a window without original coverage: HTTP %d %s", i, code, body)
		}
	}
	if estimated[0] && estimated[1] && !t.Failed() {
		t.Run("human-review", func(t *testing.T) {
			approved := proveTransferStockHumanReview(t, lab, st, lanes, measured, estimates, reviewers, reviewerEmail)
			proveTransferStockApprovedForwarding(t, lab, st, reviewers[0], links, approved[0])
		})
	} else {
		t.Log("human review and forwarding require complete owned measurement")
	}
	assertTransferStockKernelPath(t, lab, links[0])
}

func waitTransferStock(t *testing.T, within time.Duration, ready func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if ready() {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-t.Context().Done():
			return false
		case <-time.After(250 * time.Millisecond):
		}
	}
}

type transferStockApproval struct {
	id     string
	review sdk.RoutingTransferReview
}

func proveTransferStockHumanReview(t *testing.T, lab *routingLab, st *shipped.Stack, lanes [2]transferStockLane,
	inputs [2]sdk.RoutingTransferInput, estimates [2]sdk.RoutingTransferResponse, reviewers [2]string, reviewerEmail string) [2]transferStockApproval {
	t.Helper()
	const reviewPath = "/v1/remediation/routing-transfer-reviews"
	router := lab.docker(t, "exec", lab.container("rtr-a"), "vtysh", "-c", "show running-config")
	type selection struct {
		ArchiveID string                   `json:"archive_id"`
		Estimate  sdk.RoutingTransferInput `json:"estimate"`
	}
	var selections [2]selection
	var reviews [2]transferStockApproval
	for lane, owned := range lanes {
		var archive sdk.DeviceConfigVersion
		transferStockReviewRequest(t, st, owned.reg.cookie, http.MethodPost, "/v1/device/configs", sdk.DeviceConfigArchiveRequest{
			Device: "FRRouting transfer lab", Source: "operator-submitted", Content: router,
			Binding: &sdk.DeviceConfigBindingInput{ContextId: owned.reg.contextID, DeviceEntityId: owned.reg.deviceID,
				AgentId: owned.counters, SourceRef: lab.ip["rtr-a"]},
		}, http.StatusCreated, &archive)
		if archive.Id == "" || archive.TenantId != owned.reg.tenantID {
			t.Fatalf("lane %d lost its owned FRRouting archive", lane)
		}
		selections[lane] = selection{ArchiveID: archive.Id, Estimate: inputs[lane]}
	}
	for lane, owned := range lanes {
		cookie, other := owned.reg.cookie, reviewers[1-lane]
		estimate := estimates[lane]
		var preview sdk.RoutingTransferDryRun
		transferStockReviewRequest(t, st, cookie, http.MethodPost, "/v1/remediation/routing-transfer-dry-run",
			selections[lane], http.StatusOK, &preview)
		if preview.ArchiveId != selections[lane].ArchiveID || preview.RouterId != owned.reg.deviceID ||
			preview.ExactPrefix != estimate.Policy.ExactPrefix || preview.CandidatePeer != estimate.Policy.CandidatePeer ||
			preview.CandidateAsn != estimate.Policy.CandidateAsn || preview.MovedPeakBps != estimate.Estimate.MovedPeakBps ||
			len(preview.PreviewFingerprint) != 64 || len(preview.Configure) == 0 || len(preview.Withdraw) == 0 {
			t.Fatalf("lane %d dry run lost its measured route, traffic or owned archive: %+v", lane, preview)
		}
		foreign := selections[lane]
		foreign.ArchiveID = selections[1-lane].ArchiveID
		transferStockReviewRequest(t, st, cookie, http.MethodPost, "/v1/remediation/routing-transfer-dry-run",
			foreign, http.StatusNotFound, nil)

		var proposal sdk.RemediationProposal
		transferStockReviewRequest(t, st, cookie, http.MethodPost, reviewPath, map[string]any{
			"selection": selections[lane], "preview_fingerprint": preview.PreviewFingerprint, "max_moved_bps": preview.MovedPeakBps,
		}, http.StatusCreated, &proposal)
		if proposal.Id == "" || proposal.TenantId != owned.reg.tenantID || proposal.State != "proposed" ||
			proposal.Target != preview.ExactPrefix || proposal.DryRun.BlastRadius != 256 {
			t.Fatalf("lane %d did not record a pending and bounded review: %+v", lane, proposal)
		}

		path := reviewPath + "/" + proposal.Id
		var review sdk.RoutingTransferReview
		transferStockReviewRequest(t, st, other, http.MethodGet, path, nil, http.StatusNotFound, nil)
		transferStockReviewRequest(t, st, reviewers[lane], http.MethodGet, path, nil, http.StatusOK, &review)
		if len(review.Fingerprint) != 64 || review.Preview.PreviewFingerprint != preview.PreviewFingerprint ||
			!slices.Equal(review.Preview.Configure, preview.Configure) || !slices.Equal(review.Preview.Withdraw, preview.Withdraw) ||
			review.Decision.ApprovedBy != "" {
			t.Fatalf("lane %d did not display the exact pending policy and rollback", lane)
		}
		approval := sdk.RoutingTransferApprovalInput{Fingerprint: review.Fingerprint}
		transferStockReviewRequest(t, st, cookie, http.MethodPost, path+"/approve", approval, http.StatusForbidden, nil)
		transferStockReviewRequest(t, st, other, http.MethodPost, path+"/approve", approval, http.StatusNotFound, nil)
		var accepted sdk.RemediationProposal
		code, raw := st.Do(t, reviewers[lane], http.MethodPost, path+"/approve", approval)
		if code != http.StatusOK || json.Unmarshal(raw, &accepted) != nil {
			// Record the current read-only result without retrying approval or
			// applying anything. This distinguishes preview drift from a
			// conflict while publishing the saved review.
			currentCode, currentRaw := st.Do(t, reviewers[lane], http.MethodPost, "/v1/remediation/routing-transfer-dry-run", selections[lane])
			var current sdk.RoutingTransferDryRun
			_ = json.Unmarshal(currentRaw, &current)
			t.Fatalf("lane %d approval HTTP %d: %.500s; current dry run HTTP %d preview %q vs %q estimate %q vs %q validity %q vs %q",
				lane, code, raw, currentCode, current.PreviewFingerprint, preview.PreviewFingerprint,
				current.EstimateDigest, preview.EstimateDigest, current.SourceValidUntil, preview.SourceValidUntil)
		}
		var approved sdk.RoutingTransferReview
		transferStockReviewRequest(t, st, reviewers[lane], http.MethodGet, path, nil, http.StatusOK, &approved)
		validUntil, err := time.Parse(time.RFC3339Nano, approved.ValidUntil)
		if accepted.Id != proposal.Id || accepted.State != "approved" || approved.Fingerprint != review.Fingerprint ||
			approved.Decision.ApprovedBy != "user:"+reviewerEmail || approved.Decision.ApprovedAt == "" ||
			approved.ValidUntil != approved.Decision.ValidUntil || err != nil || !validUntil.After(time.Now()) {
			t.Fatalf("lane %d approval lost its reviewer, exact review or live deadline", lane)
		}
		running := lab.docker(t, "exec", lab.container("rtr-a"), "vtysh", "-c", "show running-config")
		attachment := "neighbor " + preview.CandidatePeer + " route-map "
		if !strings.Contains(running, attachment+preview.CurrentInboundPolicy+" in") ||
			strings.Contains(running, attachment+preview.ProposedInboundPolicy+" in") {
			t.Fatalf("lane %d recording approval changed the running FRR attachment", lane)
		}
		reviews[lane] = transferStockApproval{id: proposal.Id, review: approved}
	}
	return reviews
}

func transferStockReviewRequest(t *testing.T, st *shipped.Stack, cookie, method, path string, body any, expected int, out any) {
	t.Helper()
	code, response := st.Do(t, cookie, method, path, body)
	if code != expected {
		t.Fatalf("%s %s returned %d, want %d: %.500s", method, path, code, expected, response)
	}
	if out != nil {
		if err := json.Unmarshal(response, out); err != nil {
			t.Fatalf("%s %s returned invalid JSON: %v", method, path, err)
		}
	}
}

func assertTransferStockKernelPath(t *testing.T, lab *routingLab, selected roleRouterLink) {
	t.Helper()
	raw := lab.docker(t, "exec", lab.container("rtr-a"), "ip", "-j", "-4", "route", "get", transferStockAddress)
	var routes []struct {
		Gateway string `json:"gateway"`
		Device  string `json:"dev"`
	}
	if err := json.Unmarshal([]byte(raw), &routes); err != nil || len(routes) != 1 ||
		routes[0].Gateway != selected.peerIP || routes[0].Device != selected.iface {
		t.Fatalf("kernel does not use the selected physical upstream: %s", raw)
	}
}

func configureTransferStockHandoffs(t *testing.T, lab *routingLab) ([2]roleRouterLink, string) {
	t.Helper()
	links := [2]roleRouterLink{
		addRoleRouterLink(t, lab, "source", "edge", 234, edgeASN, entity.InterfaceRoleTransit),
		addRoleRouterLink(t, lab, "candidate", "rtr-b", 233, rtrBASN, entity.InterfaceRoleTransit),
	}
	router := lab.container("rtr-a")
	if forwarding := lab.docker(t, "exec", router, "cat", "/proc/sys/net/ipv4/ip_forward"); strings.TrimSpace(forwarding) != "1" {
		t.Fatal("the pinned routing lab needs IPv4 forwarding for its workload")
	}
	lab.docker(t, "exec", router, "vtysh", "-c", "configure terminal",
		"-c", "route-map FX23-SOURCE permit 10", "-c", "set local-preference 200", "-c", "exit",
		"-c", "route-map FX23-CANDIDATE permit 10", "-c", "set local-preference 100", "-c", "exit",
		"-c", "router bgp "+strconv.Itoa(rtrAASN),
		"-c", "neighbor "+lab.ip["edge"]+" shutdown",
		"-c", "no neighbor "+links[0].peerIP6, "-c", "no neighbor "+links[1].peerIP6,
		// Suppress periodic keepalives on the two owned fixture BGP sessions.
		// A TCP keepalive and ACK can land in the same IPFIX millisecond.
		"-c", "neighbor "+links[0].peerIP+" timers 0 0",
		"-c", "neighbor "+links[1].peerIP+" timers 0 0",
		"-c", "address-family ipv4 unicast",
		"-c", "neighbor "+links[0].peerIP+" route-map FX23-SOURCE in",
		"-c", "neighbor "+links[1].peerIP+" route-map FX23-CANDIDATE in", "-c", "exit-address-family",
		"-c", "bmp targets probectl", "-c", "bmp monitor ipv4 unicast loc-rib",
		"-c", "bmp stats interval 1000", "-c", "end")
	lab.docker(t, "exec", lab.container("rtr-b"), "vtysh", "-c", "configure terminal",
		"-c", "router bgp "+strconv.Itoa(rtrBASN), "-c", "no bgp network import-check",
		"-c", "address-family ipv4 unicast", "-c", "network "+prefixA, "-c", "end")
	// Renegotiate the hold times before collecting any signed samples.
	lab.docker(t, "exec", router, "vtysh", "-c", "clear bgp "+links[0].peerIP, "-c", "clear bgp "+links[1].peerIP)
	lab.docker(t, "exec", lab.container("edge"), "ip", "address", "add", transferStockAddress+"/32", "dev", "lo")
	lab.docker(t, "exec", lab.container("rtr-b"), "ip", "route", "replace", transferStockAddress+"/32", "via", links[1].routerIP)
	community := startRouterSNMP(t, lab, "rtr-a")
	for i := range links {
		link := &links[i]
		sidecar := lab.name + "-rtr-a-snmp"
		index := queryEdgeSNMP(t, sidecar, community, ".1.3.6.1.2.1.4.20.1.2."+link.routerIP)
		n, err := strconv.ParseUint(index, 10, 32)
		if err != nil || n == 0 {
			t.Fatal("stock exporter needs the original SNMP index", index, err)
		}
		link.index = uint32(n)
		link.iface = strings.Trim(queryEdgeSNMP(t, sidecar, community, ".1.3.6.1.2.1.2.2.1.2."+index), "\"")
		kernel := lab.docker(t, "exec", router, "cat", "/sys/class/net/"+link.iface+"/ifindex")
		if strings.TrimSpace(kernel) != index {
			t.Fatal("SNMP and passive capture selected different router interfaces")
		}
		// These handoffs measure IPv4 forwarding. Neighbor discovery on the
		// former IPv6 links can create single-packet exporter intervals.
		lab.docker(t, "exec", router, "ip", "link", "set", "dev", link.iface, "addrgenmode", "none")
		lab.docker(t, "exec", router, "ip", "-6", "address", "flush", "dev", link.iface)
	}
	if links[0].index == links[1].index {
		t.Fatal("both physical handoffs resolved to the same kernel interface")
	}
	return links, community
}

func prepareTransferStockCollectors(t *testing.T, lab *routingLab, st *shipped.Stack, links [2]roleRouterLink,
	community, exporterImage string, lanes *[2]transferStockLane) {
	t.Helper()
	routerIP := lab.ip["rtr-a"]
	pool := st.ApplicationReadPool(t)
	outgoingMAC := strings.TrimSpace(lab.docker(t, "exec", lab.container("rtr-a"), "cat", "/sys/class/net/"+links[0].iface+"/address"))
	ethernet, err := net.ParseMAC(outgoingMAC)
	if err != nil || len(ethernet) != 6 {
		t.Fatal("physical egress needs a canonical Ethernet address")
	}
	// The pinned exporter identifies the capture interface in both IPFIX
	// interface fields. Select frames actually transmitted from that NIC.
	egressOnly := "ether src " + ethernet.String()
	for i := range lanes {
		lane := &lanes[i]
		suffix := "transfer-" + strconv.Itoa(i)
		requireRoleSourceBinding(t, st, lane.reg, map[string]string{"agent_id": lane.reg.agentID, "source_kind": "flow_exporter", "source_ref": routerIP,
			"context_id": lane.reg.contextID, "anchor_entity_id": lane.reg.deviceID})
		lane.counters = startShippedEdgeSNMP(t, st, lane.reg, suffix, routerIP, community)
		awaitEdgeSNMPEvidence(t, st, lane.reg, lane.counters, routerIP)
		ids := awaitRoleRouterInterfaces(t, st, lane.reg, links[:])
		lane.portIDs = [2]string{ids[links[0].index], ids[links[1].index]}
		listener := startRouterBMPEvidenceListenerNamed(t, st, lab, lane.reg, lane.reg.deviceID, suffix)
		putFRRSelectedRIBBinding(t, st, lane.reg, listener, routerIP, "", true, 1)
		listener.reconnectBMP()
		awaitFRRSelectedPath(t, pool, lane.reg, transferStockAddress, prefixA, []uint32{edgeASN, originA}, netip.MustParseAddr(links[0].peerIP))
		awaitFRROwnedAlternates(t, pool, lane.reg, transferStockAddress, map[netip.Addr]netip.Addr{
			netip.MustParseAddr(links[0].peerIP): netip.MustParseAddr(links[0].routerIP),
			netip.MustParseAddr(links[1].peerIP): netip.MustParseAddr(links[1].routerIP),
		})
		destination := startShippedRouterFlow(t, st, lab, lane.reg, routerIP)
		lane.collector = destination
		export := links[0]
		export.name = suffix
		lane.exporter = startRoleRouterExporter(t, lab, exporterImage, destination, export, egressOnly)
	}
}

func warmTransferStockExporters(t *testing.T, lab *routingLab, st *shipped.Stack, link roleRouterLink, lanes [2]transferStockLane) {
	t.Helper()
	// A collector learns its signed exporter identity from the first packet.
	// Establish that identity before measuring. Raw ingestion can arrive before
	// the first identity RPC and permanently record ownership as unavailable.
	pool := st.ApplicationReadPool(t)
	reader := store.NewInterfaceRoleInputs(pool)
	exporter := netip.MustParseAddr(lab.ip["rtr-a"])
	budget := entity.InterfaceRolePolicyBudget{MemoryBytes: 32 << 20, WorkUnits: 32 << 20}
	for i, lane := range lanes {
		t.Run(fmt.Sprintf("warm-exporter-%d", i), func(t *testing.T) {
			emitRoleRouterCapturedTraffic(t, lab, lane.exporter, link, link.routerIP, link.peerIP, "1", false)
		})
	}
	var bound [2]bool
	waitTransferStock(t, 30*time.Second, func() bool {
		for i, lane := range lanes {
			scope := entity.Scope{TenantID: lane.reg.tenantID, ContextID: lane.reg.contextID}
			ctx := tenancy.WithTenant(t.Context(), tenancy.ID(scope.TenantID))
			var found bool
			err := tenancy.InTenantReadSnapshot(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
				bindings, err := reader.FlowBindingsInScope(ctx, sc, scope, budget)
				if err != nil {
					return err
				}
				found = slices.ContainsFunc(bindings, func(binding store.InterfaceRoleFlowBinding) bool {
					return binding.Scope == scope && binding.RouterID == lane.reg.deviceID && binding.AgentID == lane.reg.agentID &&
						binding.Exporter == exporter && binding.Protocol == flow.ProtoIPFIX && binding.Domain == 0 && binding.ValidUntil.After(time.Now())
				})
				return nil
			})
			bound[i] = err == nil && found
		}
		return bound[0] && bound[1]
	})
	for i, ready := range bound {
		if !ready {
			t.Errorf("lane %d stock IPFIX exporter has no current signed tenant binding", i)
		}
	}
}

// softflowd can leave a partial libpcap block waiting. Pace small frames to the
// owned peer so the drain can complete that block without overrunning the ring.
// The test takes both final signed counter observations before sending them.
func drainTransferStockCapture(t *testing.T, lab *routingLab, selected roleRouterLink) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	args := []string{"exec", "--user", "0", lab.container("rtr-a"), "ping",
		"-q", "-i", "0.002", "-I", selected.iface, "-c", "2048", "-s", "8", "-W", "1", selected.peerIP}
	if out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil {
		t.Errorf("flush the owned exporter capture buffer: %v %.400s", err, out)
	}
}

func transferStockCaptureComplete(ctx context.Context, exporter string) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	packets := strconv.Itoa(transferStockPackets)
	octets := strconv.Itoa(transferStockWireBytes)
	out, err := exec.CommandContext(ctx, "docker", "exec", exporter, "softflowctl", "-c", "/tmp/softflowd.ctl", "dump-flows").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "["+transferStockAddress+"]:37200 proto:17") &&
			strings.Contains(line, "octets>:"+octets+" packets>:"+packets+" octets<:0 packets<:0 ") {
			return true
		}
	}
	return false
}

func makeTransferStockRequest(t *testing.T, st *shipped.Stack, lane *transferStockLane, sourcePrice, candidatePrice int64) sdk.RoutingTransferInput {
	t.Helper()
	book := func(id string, price int64) sdk.RoutingTransferBillingSelection {
		t.Helper()
		input := flow.SaveCapacityAgreement{Definition: flow.CapacityAgreementDefinition{
			Name: "Observed physical transit", ValidFrom: lane.before.started.Add(-time.Hour).Format(time.RFC3339Nano),
			Target:     flow.CapacityTarget{Kind: "interface", ContextID: lane.reg.contextID, InterfaceID: id},
			BillingDay: 1, Timezone: "UTC", Direction: "out", Currency: "USD", CommitBPS: "0", UnitBPS: "1000", UnitPrice: strconv.FormatInt(price, 10),
		}}
		code, body := st.Do(t, lane.reg.cookie, http.MethodPost, "/v1/flows/capacity/agreements", input)
		var agreement flow.CapacityAgreement
		if code != http.StatusCreated || json.Unmarshal(body, &agreement) != nil || agreement.ID == "" {
			t.Fatalf("physical handoff terms were not saved: HTTP %d %s", code, body)
		}
		return sdk.RoutingTransferBillingSelection{AgreementId: agreement.ID, AgreementVersion: agreement.Version, EgressInterfaceId: id,
			PhysicalBounds: []sdk.CapacityPhysicalBound{{ContextId: lane.reg.contextID, InterfaceId: id, MaxBps: "10000000"}}}
	}
	return sdk.RoutingTransferInput{ContextId: lane.reg.contextID, DestinationPrefix: prefixA, LocalPreference: 300,
		ObservedFrom: lane.before.started.Format(time.RFC3339Nano), ObservedTo: lane.after.started.Format(time.RFC3339Nano), MaximumPollGap: "40s",
		Source: book(lane.portIDs[0], sourcePrice), Candidate: book(lane.portIDs[1], candidatePrice)}
}

func assertTransferStockEstimate(t *testing.T, lane transferStockLane, links [2]roleRouterLink, output sdk.RoutingTransferResponse, sourcePrice, candidatePrice int64) {
	t.Helper()
	span := lane.after.started.Sub(lane.before.started)
	if lane.after.octets[0] < lane.before.octets[0] || lane.after.octets[1] < lane.before.octets[1] || span <= 0 {
		t.Fatal("independent counters reset or reversed their time")
	}
	sourceBefore := transferStockRate(lane.after.octets[0]-lane.before.octets[0], span)
	candidateBefore := transferStockRate(lane.after.octets[1]-lane.before.octets[1], span)
	moved := transferStockRate(transferStockWireBytes, span)
	remaining, shifted := new(big.Rat).Sub(sourceBefore, moved), new(big.Rat).Add(candidateBefore, moved)
	chargeChange := new(big.Rat).Mul(moved, big.NewRat(candidatePrice-sourcePrice, 1000))
	got := output.Estimate
	if output.ContextId != lane.reg.contextID || output.Policy.ExactPrefix != prefixA ||
		output.Policy.CurrentPeer != links[0].peerIP || output.Policy.CandidatePeer != links[1].peerIP ||
		output.Policy.CandidateAsn != rtrBASN || output.Policy.LocalPreference != 300 ||
		got.MovedPeakBps != moved.RatString() || got.CandidatePeakBps != shifted.RatString() || got.NetChargeChange != chargeChange.RatString() {
		t.Errorf("served result differs from hand arithmetic: got %+v, moved %s, shifted %s, USD change %s", got, moved, shifted, chargeChange)
	}
	for _, sample := range []struct {
		observed sdk.CapacityPercentileResult
		want     *big.Rat
	}{
		{got.Source.BeforeP95, sourceBefore}, {got.Source.AfterP95, remaining},
		{got.Candidate.BeforeP95, candidateBefore}, {got.Candidate.AfterP95, shifted},
	} {
		want := sample.want
		if sample.observed.BpsNumerator != want.Num().String() || sample.observed.BpsDenominator != want.Denom().String() {
			t.Errorf("P95 differs from the independent out-octets: got %+v, want %s", sample.observed, want)
		}
	}
}

func transferStockRate(octets uint64, window time.Duration) *big.Rat {
	bits := new(big.Int).Mul(new(big.Int).SetUint64(octets), big.NewInt(8_000_000_000))
	return new(big.Rat).SetFrac(bits, big.NewInt(int64(window)))
}
