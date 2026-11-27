// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && linux

package bgp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
	"github.com/ctlplne/probectl/pkg/sdk"
)

const transferProbeTarget = "203.0.113.201"
const transferProbeResultPrefix = "routing-probe-measurement "

type transferStockProbe struct {
	tenant string
	pid    string
	routerProbeEnrollment
	client *agent.EvidenceClient
}

func prepareTransferStockProbes(t *testing.T, lab *routingLab, st *shipped.Stack,
	lanes [2]transferStockLane, links [2]roleRouterLink) [2][2]transferStockProbe {
	t.Helper()
	var probes [2][2]transferStockProbe
	var addresses [2][2]string
	for side, link := range links {
		provider := lab.container(link.peer)
		providerIF := transferProbeInterface(t, lab, provider, link.peerIP)
		peerMAC := strings.TrimSpace(lab.docker(t, "exec", provider, "cat", "/sys/class/net/"+providerIF+"/address"))
		if mac, err := net.ParseMAC(peerMAC); err != nil || len(mac) != 6 || mac.String() != peerMAC {
			t.Fatalf("provider %s has no canonical Ethernet address", link.peer)
		}
		lab.docker(t, "exec", "--user", "0", provider, "ip", "address", "add", transferProbeTarget+"/32", "dev", "lo")
		for lane, customer := range lanes {
			name := fmt.Sprintf("probe-%d-%d", lane, side)
			container := lab.name + "-" + name
			subnet := netip.MustParsePrefix(link.prefix)
			address := subnet.Addr().As4()
			address[3] = byte(21 + lane)
			source := netip.AddrFrom4(address).String()
			addresses[lane][side] = source
			lab.docker(t, "create", "--pull=never", "--label", "qa.owner=probectl-beta", "--name", container,
				"--network", lab.name+"-"+link.name, "--ip", source, "--cap-add", "NET_ADMIN",
				"--entrypoint", "/bin/sleep", frrImage, "600")
			t.Cleanup(func() { _ = exec.Command("docker", "rm", "-fv", container).Run() })
			lab.docker(t, "start", container)
			iface := transferProbeInterface(t, lab, container, source)
			lab.docker(t, "exec", "--user", "0", container, "ip", "route", "replace", transferProbeTarget+"/32",
				"via", link.peerIP, "dev", iface, "src", source)
			pid := strings.TrimSpace(lab.docker(t, "inspect", "--format", "{{.State.Pid}}", container))
			if value, err := strconv.Atoi(pid); err != nil || value <= 1 {
				t.Fatalf("could not identify the owned probe namespace: %q", pid)
			}
			params := map[string]string{"count": "3", testspec.RoutingProbeHandoffParam: customer.portIDs[side],
				testspec.RoutingProbePeerParam: link.peerIP, testspec.RoutingProbeInterfaceParam: iface,
				testspec.RoutingProbeSourceParam: source, testspec.RoutingProbePeerMACParam: peerMAC}
			enrolled := enrollOwnedRouterProbe(t, st, customer.reg, name, transferProbeTarget, params)
			client, err := agent.DialEntityEvidence(st.AgentAddr, enrolled.cert, enrolled.private, enrolled.ca, "localhost")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if tenant, agentID := client.Identity(); tenant != customer.reg.tenantID || agentID != enrolled.agent {
				t.Fatal("physical probe got the wrong issued identity")
			}
			probes[lane][side] = transferStockProbe{tenant: customer.reg.tenantID, pid: pid, routerProbeEnrollment: enrolled, client: client}
		}
		if side == 0 {
			plantTransferProbeImpairments(t, lab, provider, providerIF, [2]string{addresses[0][side], addresses[1][side]})
		}
	}
	return probes
}

func transferProbeInterface(t *testing.T, lab *routingLab, container, source string) string {
	t.Helper()
	var interfaces []struct {
		Name    string `json:"ifname"`
		Details []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	body := lab.docker(t, "exec", container, "ip", "-j", "-4", "address", "show")
	if err := json.Unmarshal([]byte(body), &interfaces); err != nil {
		t.Fatalf("read owned namespace interfaces: %v", err)
	}
	for _, link := range interfaces {
		for _, detail := range link.Details {
			if detail.Local == source && entity.ValidICMPEgressInterface(link.Name) {
				return link.Name
			}
		}
	}
	t.Fatalf("no owned interface carries %s", source)
	return ""
}

// Only replies from the lab's dedicated synthetic target to its two bound
// sources enter the delay/loss queues. Router traffic and BGP bypass them.
func plantTransferProbeImpairments(t *testing.T, lab *routingLab, provider, iface string, addresses [2]string) {
	t.Helper()
	run := func(args ...string) {
		lab.docker(t, append([]string{"exec", "--user", "0", provider, "tc"}, args...)...)
	}
	run("qdisc", "add", "dev", iface, "root", "handle", "1:", "prio", "bands", "4")
	run("qdisc", "add", "dev", iface, "parent", "1:3", "handle", "30:", "netem", "delay", "90ms")
	run("qdisc", "add", "dev", iface, "parent", "1:4", "handle", "40:", "netem", "loss", "100%")
	for lane, address := range addresses {
		run("filter", "add", "dev", iface, "protocol", "ip", "parent", "1:0", "prio", strconv.Itoa(lane+1),
			"u32", "match", "ip", "protocol", "1", "0xff", "match", "ip", "src", transferProbeTarget+"/32",
			"match", "ip", "dst", address+"/32", "flowid", "1:"+strconv.Itoa(lane+3))
	}
}

// TestRoutingTransferProbeChild runs the actual egress canary after the test
// parent enters a fresh fixture namespace. Only its probe definition and
// measurement cross the process boundary. The parent owns all credentials.
func TestRoutingTransferProbeChild(t *testing.T) {
	input := os.Getenv("PROBECTL_TEST_ROUTING_TRANSFER_PROBE")
	if input == "" {
		return
	}
	raw, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	var definition testspec.ExecutableDefinition
	if err := json.Unmarshal(raw, &definition); err != nil {
		t.Fatal(err)
	}
	binding, err := testspec.ParseRoutingProbeBinding(definition.Type, definition.Target, definition.Params)
	if err != nil || binding == nil {
		t.Fatalf("invalid owned probe definition: %v", err)
	}
	source, err := netip.ParseAddr(binding.Egress.Source)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := net.ParseMAC(binding.Egress.PeerMAC)
	if err != nil || len(mac) != 6 {
		t.Fatal("invalid owned peer MAC")
	}
	egress := canary.ICMPEgress{Interface: binding.Egress.Interface, Source: source}
	copy(egress.PeerMAC[:], mac)
	probe, err := canary.NewICMPWithEgress(canary.Config{Type: definition.Type, Target: definition.Target, Params: definition.Params,
		Interval: time.Duration(definition.IntervalSeconds) * time.Second, Timeout: time.Duration(definition.TimeoutSeconds) * time.Second}, egress)
	if err != nil {
		t.Fatal(err)
	}
	result, err := probe.Run(t.Context())
	if err != nil || result.ICMP == nil || !result.ICMP.Complete() || result.ICMP.Egress == nil {
		t.Fatalf("physical probe did not witness every request: %v %s", err, result.Error)
	}
	body, err := json.Marshal(result.ICMP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stdout.Write(append([]byte(transferProbeResultPrefix), append(body, '\n')...)); err != nil {
		t.Fatal(err)
	}
}

func (probe transferStockProbe) command(ctx context.Context, t *testing.T) *exec.Cmd {
	t.Helper()
	raw, err := json.Marshal(probe.definition)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(t.TempDir(), "probe.json")
	if err := os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--target", probe.pid, "--net", "--", "env", "PROBECTL_TEST_ROUTING_TRANSFER_PROBE=" + config,
		executable, "-test.run=^TestRoutingTransferProbeChild$"}
	program := "nsenter"
	if os.Geteuid() != 0 {
		args = append([]string{"-n", program}, args...)
		program = "sudo"
	}
	return exec.CommandContext(ctx, program, args...)
}

func readTransferStockProbeResult(output []byte) (canary.ICMPMeasurement, error) {
	var measurement []byte
	for line := range bytes.SplitSeq(output, []byte{'\n'}) {
		if body, found := bytes.CutPrefix(line, []byte(transferProbeResultPrefix)); found {
			measurement = body
			break
		}
	}
	var measured canary.ICMPMeasurement
	if err := json.Unmarshal(measurement, &measured); err != nil {
		return canary.ICMPMeasurement{}, fmt.Errorf("decode original probe result: %w", err)
	}
	if !measured.Complete() || measured.Egress == nil ||
		len(measured.RoundTripNanos) != measured.Replies {
		return canary.ICMPMeasurement{}, errors.New("fixture did not return a complete witnessed measurement")
	}
	return measured, nil
}

func collectTransferStockProbePair(t *testing.T, pair [2]transferStockProbe) ([2]canary.ICMPMeasurement, time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()
	group, ctx := errgroup.WithContext(ctx)
	commands := [2]*exec.Cmd{pair[0].command(ctx, t), pair[1].command(ctx, t)}
	from := time.Now().UTC()
	var measured [2]canary.ICMPMeasurement
	for i, command := range commands {
		group.Go(func() error {
			output, err := command.CombinedOutput()
			if err != nil {
				return fmt.Errorf("owned probe %d failed: %w %.600s", i, err, output)
			}
			measured[i], err = readTransferStockProbeResult(output)
			return err
		})
	}
	if err := group.Wait(); err != nil {
		t.Fatal(err)
	}
	return measured, from
}

func (probe transferStockProbe) submit(t *testing.T, source canary.ICMPMeasurement) {
	t.Helper()
	if source.Expected != 3 || !source.ReadComplete || source.Transmitted != 3 || len(source.NetworkErrors) != 0 ||
		source.Egress == nil || source.Egress.Transmitted != 3 || source.Replies < 0 || source.Replies > 3 {
		t.Fatal("a partial probe cannot stand in for the physical test")
	}
	digest, err := testspec.DefinitionHash(probe.definition)
	if err != nil {
		t.Fatal(err)
	}
	id, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	witness := source.Egress
	claim := entity.Observation{ID: id, ObservedAt: source.CompletedAt, SourceRef: "icmp:configured-test",
		Source: entity.SourceKey{AgentID: probe.agent, Kind: entity.PathAgent, SourceRef: probe.test},
		Alias:  entity.AliasKey{Kind: entity.AddressAlias, Value: source.TargetIP},
		ICMP: &entity.ICMPMeasurement{Version: entity.ICMPVersionEgress, DefinitionHash: digest,
			StartedAt: source.StartedAt, CompletedAt: source.CompletedAt, Requested: 3, Attempted: 3, Transmitted: 3,
			Replies: uint32(source.Replies), ReadComplete: true, Responders: source.Responders,
			RoundTrips: &entity.ICMPRoundTrips{Nanos: source.RoundTripNanos, ExecutionNanos: source.ExecutionNanos},
			Egress: &entity.ICMPEgressWitness{Interface: witness.Interface, Source: witness.Source.String(),
				PeerMAC: net.HardwareAddr(witness.PeerMAC[:]).String(), Transmitted: 3}}}
	if accepted, unresolved, err := probe.client.Submit(t.Context(), []entity.Observation{claim}); err != nil || accepted != 1 || unresolved != 0 {
		t.Fatalf("tenant %s's physical original did not reach mTLS storage: accepted %d unresolved %d err %v",
			probe.tenant, accepted, unresolved, err)
	}
}

func collectTransferStockComparisons(t *testing.T, probes [2][2]transferStockProbe) ([2]sdk.RoutingTransferProbeComparisonInput, time.Time) {
	t.Helper()
	var out [2]sdk.RoutingTransferProbeComparisonInput
	var lastWindowEnd time.Time
	for lane, pair := range probes {
		t.Run("physical-probes-"+strconv.Itoa(lane), func(t *testing.T) {
			// Start both probes before submitting either result. A lossy source
			// or a delayed receipt write must not postpone the candidate probe.
			measured, from := collectTransferStockProbePair(t, pair)
			interval := time.Duration(pair[0].definition.IntervalSeconds) * time.Second
			to := from.Add(interval)
			if to.After(lastWindowEnd) {
				lastWindowEnd = to
			}
			for i, sample := range measured {
				if sample.StartedAt.Before(from) || !sample.CompletedAt.Before(to) {
					t.Errorf("handoff %d observation fell outside the common closed interval", i)
				}
			}
			before, after := measured[0], measured[1]
			if after.Replies != 3 || (lane == 0 && (before.Replies != 3 || before.RoundTripNanos[0] < uint64(80*time.Millisecond))) ||
				(lane == 1 && before.Replies != 0) {
				t.Errorf("the physical lane did not observe its planted impairment: tenant %d replies %d→%d", lane, before.Replies, after.Replies)
			}
			if t.Failed() {
				return
			}
			for i, sample := range measured {
				t.Run("signed-observation-"+strconv.Itoa(i), func(t *testing.T) {
					pair[i].submit(t, sample)
				})
			}
			if !t.Failed() {
				out[lane] = sdk.RoutingTransferProbeComparisonInput{
					Source:    sdk.RoutingTransferProbeTestSelection{TestId: pair[0].test, AgentId: pair[0].agent},
					Candidate: sdk.RoutingTransferProbeTestSelection{TestId: pair[1].test, AgentId: pair[1].agent},
					From:      from.Format(time.RFC3339Nano), To: to.Format(time.RFC3339Nano),
					Mode: "improve_performance", MaximumCandidateP95RttNanos: "500000000", MaximumAddedCharge: "0",
				}
			}
		})
	}
	return out, lastWindowEnd
}

func awaitTransferStockPerformance(t *testing.T, st *shipped.Stack, lane transferStockLane, ifIndex uint32, index int,
	input sdk.RoutingTransferInput) (sdk.RoutingTransferResponse, bool) {
	t.Helper()
	const endpoint = "/v1/flows/routing-transfer-estimate"
	var result sdk.RoutingTransferResponse
	var status int
	ready := waitTransferStock(t, time.Minute, func() bool {
		code, body := st.Do(t, lane.reg.cookie, http.MethodPost, endpoint, input)
		status = code
		result = sdk.RoutingTransferResponse{}
		return code == http.StatusOK && json.Unmarshal(body, &result) == nil && result.Estimate.Status == "estimated" &&
			result.UpstreamPerformance.Recommendation == "move_prefix"
	})
	if !ready {
		t.Errorf("lane %d performance estimate HTTP %d: status %q, reason %q, comparison %+v",
			index, status, result.Estimate.Status, result.Estimate.Reason, result.UpstreamPerformance)
		if result.Estimate.Reason == "original_egress_ownership_incomplete" {
			logTransferStockFlowCaptures(t, st, lane, ifIndex)
		}
		return result, false
	}
	performance := result.UpstreamPerformance
	wantReplies := [2]int{3, 0}[index]
	if performance.Target != transferProbeTarget || performance.PairedRounds != 1 ||
		performance.Source.TestId != input.ProbeComparison.Source.TestId || performance.Source.AgentId != input.ProbeComparison.Source.AgentId ||
		performance.Candidate.TestId != input.ProbeComparison.Candidate.TestId || performance.Candidate.AgentId != input.ProbeComparison.Candidate.AgentId ||
		performance.Source.Transmitted != 3 || performance.Source.Replies != wantReplies ||
		performance.Candidate.Transmitted != 3 || performance.Candidate.Replies != 3 ||
		performance.Candidate.P95RttNanos == "" || (performance.Source.P95RttNanos == "") != (wantReplies == 0) {
		t.Errorf("lane %d served recommendation lost its exact two physical probe populations: %+v", index, performance)
		return result, false
	}
	return result, true
}

// The fixture operator applies and withdraws the actual approved commands.
// Both the FIB and transmitted bytes must move to the intended provider and
// back. All route edits are confined to the ephemeral lab router.
func proveTransferStockApprovedForwarding(t *testing.T, lab *routingLab, st *shipped.Stack, operator string,
	links [2]roleRouterLink, approved transferStockApproval) {
	t.Helper()
	review := approved.review
	deadline, err := time.Parse(time.RFC3339Nano, review.ValidUntil)
	preview := review.Preview
	if err != nil || !time.Now().Before(deadline) || review.Decision.ApprovedAt == "" || review.Decision.ApprovedBy == "" ||
		review.Decision.ValidUntil != review.ValidUntil || preview.CandidatePeer != links[1].peerIP || preview.ExactPrefix != prefixA ||
		len(preview.Configure) == 0 || len(preview.Withdraw) == 0 {
		t.Fatal("the fixture operator requires a current approval for the exact candidate")
	}
	router := lab.container("rtr-a")
	// An independent client enters the DUT through the lab bridge. Traffic
	// originating on the DUT would not exercise its forwarding path.
	client := lab.container("rrc")
	clientIP := lab.ip["rrc"]
	ingress := transferProbeInterface(t, lab, router, lab.ip["rtr-a"])
	lab.docker(t, "exec", "--user", "0", client, "ip", "route", "replace", transferProbeTarget+"/32", "via", lab.ip["rtr-a"])
	checkTransferProbeForwarding(t, lab, router, client, clientIP, ingress, links[0], links[1])
	apply := func(commands []string) {
		args := []string{"exec", router, "vtysh", "-c", "configure terminal"}
		for _, command := range commands {
			args = append(args, "-c", command)
		}
		raw := lab.docker(t, append(args, "-c", "end")...)
		if strings.Contains(raw, "% Unknown command") || strings.Contains(raw, "% Command incomplete") {
			t.Fatalf("the lab router rejected an approved command: %.500s", raw)
		}
		lab.docker(t, "exec", router, "vtysh", "-c", "clear bgp "+links[1].peerIP+" soft in")
	}
	if !time.Now().Before(deadline) {
		t.Fatal("the approved scope expired before the fixture operator could apply it")
	}
	installed := true
	t.Cleanup(func() {
		if installed {
			apply(preview.Withdraw)
		}
	})
	apply(preview.Configure)
	checkTransferProbeForwarding(t, lab, router, client, clientIP, ingress, links[1], links[0])
	path := "/v1/remediation/routing-transfer-reviews/" + approved.id
	var saved remediation.RoutingTransferRollback
	transferStockReviewRequest(t, st, operator, http.MethodGet, path+"/rollback", nil, http.StatusOK, &saved)
	if saved.Fingerprint != review.Fingerprint || saved.RouterID != preview.RouterId || !saved.ApprovalExpiresAt.Equal(deadline) ||
		saved.ExactPrefix != preview.ExactPrefix || !slices.Equal(saved.Withdraw, preview.Withdraw) {
		t.Fatal("the operator lost the exact approved rollback after forwarding changed")
	}
	var request remediation.RoutingTransferRollback
	transferStockReviewRequest(t, st, operator, http.MethodPost, path+"/withdraw",
		map[string]string{"review_fingerprint": saved.Fingerprint}, http.StatusOK, &request)
	if request.State != remediation.RoutingTransferWithdrawalRequested || !slices.Equal(request.Withdraw, saved.Withdraw) {
		t.Fatal("the withdrawal request did not preserve the exact approved rollback")
	}
	transferStockReviewRequest(t, st, operator, http.MethodGet, path, nil, http.StatusConflict, nil)
	checkTransferProbeForwarding(t, lab, router, client, clientIP, ingress, links[1], links[0])
	apply(request.Withdraw)
	installed = false
	checkTransferProbeForwarding(t, lab, router, client, clientIP, ingress, links[0], links[1])
	running := lab.docker(t, "exec", router, "vtysh", "-c", "show running-config")
	attach := "neighbor " + preview.CandidatePeer + " route-map "
	if !strings.Contains(running, attach+preview.CurrentInboundPolicy+" in") ||
		strings.Contains(running, attach+preview.ProposedInboundPolicy+" in") {
		t.Fatal("withdrawal did not restore the original candidate attachment")
	}
}

func checkTransferProbeForwarding(t *testing.T, lab *routingLab, router, client, clientIP, ingress string,
	expected, standby roleRouterLink) {
	t.Helper()
	shipped.Await(t, "owned kernel route uses the expected handoff", 15*time.Second, func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		raw, err := exec.CommandContext(ctx, "docker", "exec", router, "ip", "-j", "-4", "route", "get",
			transferProbeTarget, "from", clientIP, "iif", ingress).Output()
		var paths []struct {
			Gateway string `json:"gateway"`
			Device  string `json:"dev"`
		}
		return err == nil && json.Unmarshal(raw, &paths) == nil && len(paths) == 1 && paths[0].Gateway == expected.peerIP &&
			paths[0].Device == expected.iface
	})
	octets := func(iface string) uint64 {
		raw := lab.docker(t, "exec", router, "cat", "/sys/class/net/"+iface+"/statistics/tx_bytes")
		value, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			t.Fatal("could not read the owned egress counter", err)
		}
		return value
	}
	before, standbyBefore := octets(expected.iface), octets(standby.iface)
	const payload, count = 1000, 4
	body := lab.docker(t, "exec", "--user", "0", client, "ping", "-s", strconv.Itoa(payload), "-c", strconv.Itoa(count),
		"-i", "0.2", "-W", "2", transferProbeTarget)
	after, standbyAfter := octets(expected.iface), octets(standby.iface)
	if (!strings.Contains(body, "4 packets received") && !strings.Contains(body, "4 received")) ||
		after < before || after-before < count*payload || standbyAfter < standbyBefore || standbyAfter-standbyBefore >= count*payload {
		t.Fatalf("approved transit did not use only the expected handoff: selected %s %d→%d, standby %s %d→%d",
			expected.iface, before, after, standby.iface, standbyBefore, standbyAfter)
	}
}
