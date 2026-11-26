// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestFRRRoutingTransferPreservesMoreSpecificRoutesAndWithdraws(t *testing.T) {
	const image = "quay.io/frrouting/frr:10.7.1@sha256:e995beaa50fdc9edb35eadcfefa29b7f062cc06f2b812613789b68fa541554d2"
	imageCtx, cancelImage := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancelImage()
	if out, err := exec.CommandContext(imageCtx, "docker", "image", "inspect", image).CombinedOutput(); err != nil {
		if !testsupport.RequireServices() {
			t.Skipf("pinned local FRRouting fixture unavailable: %v %s", err, out)
		}
		// The BGP package may start in parallel. Required integration tests
		// fetch their own pinned fixture instead of waiting for that package.
		transferFRRDocker(t, imageCtx, "pull", image)
	}
	cancelImage()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	name := "probectl-qa-beta-transfer-frr-" + uuid.NewString()[:8]
	sourceLink, candidateLink, clientLink := name+"-source", name+"-candidate", name+"-client"
	for _, network := range []string{sourceLink, candidateLink, clientLink} {
		// Fixture bridges carry routed packets between the lab endpoints. Keep
		// the bridge without a host gateway or masquerading and clear each
		// fixture namespace's default route before introducing test traffic.
		transferFRRDocker(t, ctx, "network", "create", "--driver", "bridge", "--ipv6=false",
			"--opt", "com.docker.network.bridge.inhibit_ipv4=true", "--opt", "com.docker.network.bridge.enable_ip_masquerade=false",
			"--label", "qa.owner=probectl-beta", network)
		t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", network).Run() })
	}
	router := startTransferFRR(t, ctx, image, sourceLink, "router")
	source := startTransferFRR(t, ctx, image, sourceLink, "upstream")
	candidate := startTransferFRR(t, ctx, image, candidateLink, "upstream")
	client := startTransferFRR(t, ctx, image, clientLink, "workload")
	for _, network := range []string{candidateLink, clientLink} {
		transferFRRDocker(t, ctx, "network", "connect", network, router.name)
	}
	for _, node := range []transferFRRNode{router, source, candidate, client} {
		for _, family := range []string{"-4", "-6"} {
			transferFRRDocker(t, ctx, "exec", "--user", "0", node.name, "ip", family, "route", "flush", "exact", "default")
			if routes := transferFRRDocker(t, ctx, "exec", node.name, "ip", family, "route", "show", "exact", "default"); strings.TrimSpace(routes) != "" {
				t.Fatalf("fixture %s retained an outbound default route: %s", node.name, routes)
			}
		}
	}
	if forwarding := transferFRRDocker(t, ctx, "exec", router.name, "cat", "/proc/sys/net/ipv4/ip_forward"); strings.TrimSpace(forwarding) != "1" {
		t.Fatal("the owned router has IPv4 forwarding disabled")
	}
	onCandidate := transferFRRAddress(t, ctx, router.name, candidateLink)
	onClient := transferFRRAddress(t, ctx, router.name, clientLink)
	sourceIf := transferFRRInterface(t, ctx, router.name, router.address)
	candidateIf := transferFRRInterface(t, ctx, router.name, onCandidate)
	clientIf := transferFRRInterface(t, ctx, router.name, onClient)
	if sourceIf == candidateIf {
		t.Fatal("the two physical handoffs share one kernel interface")
	}
	const exact, moreSpecific, denied = "203.0.113.0/24", "203.0.113.0/25", "198.51.100.0/24"
	original := []string{
		"ip prefix-list DENIED seq 10 permit " + denied,
		"route-map SOURCE-IN permit 10", "set local-preference 200", "exit",
		"route-map CANDIDATE-IN deny 10", "match ip address prefix-list DENIED", "exit",
		"route-map CANDIDATE-IN permit 20", "set local-preference 125", "exit",
		"router bgp 64496", "bgp router-id " + router.address, "no bgp ebgp-requires-policy",
		"neighbor " + source.address + " remote-as 64497", "neighbor " + candidate.address + " remote-as 64498",
		"address-family ipv4 unicast", "neighbor " + source.address + " route-map SOURCE-IN in",
		"neighbor " + candidate.address + " route-map CANDIDATE-IN in", "exit-address-family", "exit",
	}
	transferFRRConfig(t, ctx, router.name, original)
	for i, upstream := range []transferFRRNode{source, candidate} {
		localPeer := []string{router.address, onCandidate}[i]
		commands := []string{
			"router bgp " + fmt.Sprint(64497+i), "bgp router-id " + upstream.address,
			"no bgp ebgp-requires-policy", "no bgp network import-check", "neighbor " + localPeer + " remote-as 64496",
			"address-family ipv4 unicast", "network " + exact, "network " + moreSpecific,
		}
		if i == 1 {
			commands = append(commands, "network "+denied)
		}
		transferFRRConfig(t, ctx, upstream.name, append(commands, "exit-address-family", "exit"))
	}
	awaitTransferFRRBestPath(t, ctx, router.name, exact, source.address, 2)
	awaitTransferFRRBestPath(t, ctx, router.name, moreSpecific, source.address, 2)
	awaitTransferFRRBestPath(t, ctx, router.name, denied, "", 0)
	const workload = "203.0.113.200"
	for i, upstream := range []transferFRRNode{source, candidate} {
		transferFRRDocker(t, ctx, "exec", "--user", "0", upstream.name, "ip", "address", "add", workload+"/32", "dev", "lo")
		transferFRRDocker(t, ctx, "exec", "--user", "0", upstream.name, "ip", "route", "replace", client.address+"/32",
			"via", []string{router.address, onCandidate}[i])
	}
	transferFRRDocker(t, ctx, "exec", "--user", "0", client.name, "ip", "route", "replace", exact, "via", onClient)
	proveTransferForwarding(t, ctx, router.name, client, clientIf, workload, sourceIf, candidateIf)
	before := transferFRRDocker(t, ctx, "exec", router.name, "vtysh", "-c", "show running-config")
	draft, err := draftFRRTransfer(ctx, before, netip.MustParseAddr(candidate.address), 64498, netip.MustParsePrefix(exact), 300, 128<<10)
	if err != nil || len(draft.Configure) == 0 || len(draft.Withdraw) == 0 {
		t.Fatalf("original FRRouting archive could not be rendered: %v", err)
	}
	assertTransferFRRPolicy(t, ctx, router.name, draft, false)
	// Execute the two separate test-owner steps only against this fixture's
	// isolated Docker networks after the read-only product preview is checked.
	transferFRRConfig(t, ctx, router.name, draft.Configure)
	transferFRRDocker(t, ctx, "exec", router.name, "vtysh", "-c", "clear bgp "+candidate.address+" soft in")
	assertTransferFRRPolicy(t, ctx, router.name, draft, true)
	awaitTransferFRRBestPath(t, ctx, router.name, exact, candidate.address, 2)
	proveTransferForwarding(t, ctx, router.name, client, clientIf, workload, candidateIf, sourceIf)
	awaitTransferFRRBestPath(t, ctx, router.name, moreSpecific, source.address, 2)
	awaitTransferFRRBestPath(t, ctx, router.name, denied, "", 0)
	transferFRRConfig(t, ctx, router.name, draft.Withdraw)
	transferFRRDocker(t, ctx, "exec", router.name, "vtysh", "-c", "clear bgp "+candidate.address+" soft in")
	awaitTransferFRRBestPath(t, ctx, router.name, exact, source.address, 2)
	awaitTransferFRRBestPath(t, ctx, router.name, moreSpecific, source.address, 2)
	awaitTransferFRRBestPath(t, ctx, router.name, denied, "", 0)
	proveTransferForwarding(t, ctx, router.name, client, clientIf, workload, sourceIf, candidateIf)
	assertTransferFRRPolicy(t, ctx, router.name, draft, false)
}

func assertTransferFRRPolicy(t *testing.T, ctx context.Context, router string, policy frrTransferDryRun, applied bool) {
	t.Helper()
	expected := policy.BeforeMap
	if applied {
		expected = policy.AfterMap
	}
	raw := transferFRRDocker(t, ctx, "exec", router, "vtysh", "-c", "show running-config")
	current, err := readFRRInboundPolicy(ctx, raw, netip.MustParseAddr(policy.CandidatePeer), "ipv4", "", 128<<10)
	if err != nil || current.mapName != expected || current.peerASN != policy.CandidateASN {
		t.Fatalf("candidate has attachment %q in AS%d, want %q in AS%d: %v", current.mapName, current.peerASN, expected, policy.CandidateASN, err)
	}
	var mapPresent, listPresent bool
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[0] == "route-map" && fields[1] == policy.AfterMap {
			mapPresent = true
		}
		if fields[0] == "ip" && fields[1] == "prefix-list" && fields[2] == policy.AfterMap {
			listPresent = true
		}
	}
	if mapPresent != applied || listPresent != applied {
		t.Fatal("the generated route map and prefix list have the wrong lifetime")
	}
}

type transferFRRNode struct{ name, address string }

func startTransferFRR(t *testing.T, ctx context.Context, image, network, role string) transferFRRNode {
	t.Helper()
	name := network + "-" + role
	args := []string{"create", "--pull=never", "--label", "qa.owner=probectl-beta", "--name", name,
		"--network", network, "--cap-add", "NET_ADMIN", "--cap-add", "SYS_ADMIN", "--ulimit", "nofile=4096:4096"}
	if role == "router" {
		args = append(args, "--sysctl", "net.ipv4.ip_forward=1")
	}
	transferFRRDocker(t, ctx, append(args, image)...)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	config := t.TempDir()
	for file, body := range map[string]string{
		"daemons":    "zebra=yes\nbgpd=yes\nvtysh_enable=yes\nzebra_options=\"-A 127.0.0.1 -s 90000000\"\nbgpd_options=\"-A 127.0.0.1\"\n",
		"vtysh.conf": "service integrated-vtysh-config\n",
		"frr.conf":   "frr defaults traditional\nhostname " + role + "\n",
	} {
		path := filepath.Join(config, file)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		transferFRRDocker(t, ctx, "cp", path, name+":/etc/frr/"+file)
	}
	transferFRRDocker(t, ctx, "start", name)
	for {
		if ctx.Err() != nil {
			t.Fatal("FRRouting never started", role)
		}
		if err := exec.CommandContext(ctx, "docker", "exec", name, "vtysh", "-d", "bgpd", "-c", "show version").Run(); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return transferFRRNode{name, transferFRRAddress(t, ctx, name, network)}
}

func transferFRRAddress(t *testing.T, ctx context.Context, name, network string) string {
	t.Helper()
	address := strings.TrimSpace(transferFRRDocker(t, ctx, "inspect", name, "--format",
		`{{(index .NetworkSettings.Networks "`+network+`").IPAddress}}`))
	if parsed, err := netip.ParseAddr(address); err != nil || !parsed.Is4() || !parsed.IsPrivate() {
		t.Fatalf("fixture router %s did not receive a private IPv4 address", name)
	}
	return address
}

func transferFRRInterface(t *testing.T, ctx context.Context, router, local string) string {
	t.Helper()
	var interfaces []struct {
		Name      string `json:"ifname"`
		Addresses []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	raw := transferFRRDocker(t, ctx, "exec", router, "ip", "-j", "-4", "address", "show")
	if err := json.Unmarshal([]byte(raw), &interfaces); err != nil {
		t.Fatalf("read the owned router's kernel interfaces: %v", err)
	}
	for _, iface := range interfaces {
		for _, address := range iface.Addresses {
			if address.Local == local && iface.Name != "" && !strings.Contains(iface.Name, "/") {
				return iface.Name
			}
		}
	}
	t.Fatalf("owned router has no kernel interface for %s", local)
	return ""
}

// The lab operator observes the workload entering the router and the bytes
// transmitted on both uplinks. The kernel lookup is checked separately.
func proveTransferForwarding(t *testing.T, ctx context.Context, router string, client transferFRRNode,
	clientIf, destination, selected, standby string) {
	t.Helper()
	var lookup []struct {
		Interface string `json:"dev"`
	}
	forwarding := transferFRRDocker(t, ctx, "exec", router, "ip", "-j", "route", "get", destination,
		"from", client.address, "iif", clientIf)
	if err := json.Unmarshal([]byte(forwarding), &lookup); err != nil || len(lookup) != 1 || lookup[0].Interface != selected {
		t.Fatalf("kernel lookup for the owned workload selected a different link: %s (%v)", forwarding, err)
	}
	read := func(iface, counter string) uint64 {
		raw := transferFRRDocker(t, ctx, "exec", router, "cat", "/sys/class/net/"+iface+"/statistics/"+counter)
		value, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			t.Fatalf("read %s %s counter: %v", iface, counter, err)
		}
		return value
	}
	activeBefore, standbyBefore := read(selected, "tx_bytes"), read(standby, "tx_bytes")
	ingressBefore := read(clientIf, "rx_bytes")
	const count, payload = 4, 1200
	result, err := exec.CommandContext(ctx, "docker", "exec", "--user", "0", client.name, "ping",
		"-c", strconv.Itoa(count), "-s", strconv.Itoa(payload), "-i", "0.2", "-W", "2", destination).CombinedOutput()
	ingress := read(clientIf, "rx_bytes")
	active, other := read(selected, "tx_bytes"), read(standby, "tx_bytes")
	if ingress < ingressBefore || ingress-ingressBefore < count*payload {
		t.Fatalf("owned workload did not reach the router on %s: %d→%d bytes, probe error %v: %s",
			clientIf, ingressBefore, ingress, err, result)
	}
	if err != nil || (!strings.Contains(string(result), "4 packets received") && !strings.Contains(string(result), "4 received")) {
		t.Fatalf("owned probe failed (%v), ingress %s %d→%d, kernel path %s, selected %s %d→%d, standby %s %d→%d: %s",
			err, clientIf, ingressBefore, ingress, forwarding, selected, activeBefore, active, standby, standbyBefore, other, result)
	}
	if active < activeBefore || other < standbyBefore ||
		active-activeBefore < count*payload || other-standbyBefore >= count*payload {
		t.Fatalf("kernel forwarding did not move across the exact links: selected %s %d→%d, standby %s %d→%d",
			selected, activeBefore, active, standby, standbyBefore, other)
	}
}

func transferFRRConfig(t *testing.T, ctx context.Context, router string, commands []string) {
	t.Helper()
	args := []string{"exec", router, "vtysh", "-c", "configure terminal"}
	for _, command := range commands {
		args = append(args, "-c", command)
	}
	transferFRRDocker(t, ctx, append(args, "-c", "end")...)
}

func transferFRRDocker(t *testing.T, ctx context.Context, args ...string) string {
	t.Helper()
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil || strings.Contains(string(output), "% Unknown command") || strings.Contains(string(output), "% Command incomplete") {
		t.Fatalf("owned routing fixture command failed: %v %s", err, output)
	}
	return string(output)
}

func awaitTransferFRRBestPath(t *testing.T, ctx context.Context, router, prefix, want string, paths int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		var view struct {
			Paths []struct {
				BestPath *struct {
					Overall bool `json:"overall"`
				} `json:"bestpath"`
				NextHops []struct {
					IP string `json:"ip"`
				} `json:"nexthops"`
			} `json:"paths"`
		}
		output, err := exec.CommandContext(ctx, "docker", "exec", router, "vtysh", "-c", "show bgp ipv4 unicast "+prefix+" json").Output()
		if err == nil && json.Unmarshal(output, &view) == nil && len(view.Paths) == paths {
			if paths == 0 {
				return
			}
			for _, path := range view.Paths {
				if path.BestPath != nil && path.BestPath.Overall && len(path.NextHops) == 1 && path.NextHops[0].IP == want {
					return
				}
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("owned FRRouting did not converge for %s to %q with %d paths", prefix, want, paths)
}
