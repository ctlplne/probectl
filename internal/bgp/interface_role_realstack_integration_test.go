// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bgp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type roleRouterLink struct {
	name, peer, routerIP, peerIP, prefix, iface string
	routerIP6, peerIP6, prefix6                 string
	index                                       uint32
	role                                        entity.InterfaceRole
}

type servedRouterRole struct {
	entity.Scope
	InterfaceID   string               `json:"interface_id"`
	Role          entity.InterfaceRole `json:"role"`
	Reason        string               `json:"reason"`
	Sources       []string             `json:"sources"`
	SNMPCurrent   bool                 `json:"snmp_current"`
	PrefixCurrent bool                 `json:"prefix_current"`
}

// The PeeringDB envelope is explicitly synthetic. FRR sessions, kernel SNMP,
// softflowd captures, issued sender certificates, TLS, bus and stores are real.
// Stale/down source clocks and remaining lifecycle controls retain their
// separate required proofs; implementation alone does not close FX4.
func TestInterfaceRoleFRRSameRouterKeepsThreeRolesFlowAndOverride(t *testing.T) {
	if runtime.GOOS != "linux" {
		testsupport.SkipOrFatal(t, "same-router role proof requires a Linux host route to the private FRR Docker bridge")
	}
	lab := startRoutingLabNamed(t, "probectl-qa-beta-role-router-"+strconv.FormatInt(time.Now().UnixNano()%1e8, 36))
	primary := lab.ip["rtr-a"]
	links := []roleRouterLink{addRoleRouterLink(t, lab, "transit", "edge", 234, edgeASN, entity.InterfaceRoleTransit), addRoleRouterLink(t, lab, "ix", "rrc", 232, rrcASN, entity.InterfaceRoleIX), addRoleRouterLink(t, lab, "customer", "rtr-b", 233, rtrBASN, entity.InterfaceRoleCustomer)}
	// Keep management reachable, but use only the three distinct physical
	// relationship links for BGP. The initial old peer has no monitored routes.
	lab.docker(t, "exec", lab.container("rtr-a"), "vtysh", "-c", "configure terminal", "-c", "router bgp "+strconv.Itoa(rtrAASN), "-c", "neighbor "+lab.ip["edge"]+" shutdown", "-c", "bmp targets probectl", "-c", "bmp monitor ipv6 unicast pre-policy", "-c", "bmp monitor ipv6 unicast post-policy", "-c", "end")

	community := startRouterSNMP(t, lab, "rtr-a")
	sidecar := lab.name + "-rtr-a-snmp"
	indexes := map[uint32]bool{}
	for i := range links {
		index := queryEdgeSNMP(t, sidecar, community, ".1.3.6.1.2.1.4.20.1.2."+links[i].routerIP)
		value, err := strconv.ParseUint(index, 10, 32)
		if err != nil || value == 0 || indexes[uint32(value)] {
			t.Fatal("three physical relationships lost distinct SNMP interface identities", links[i].name, index, err)
		}
		links[i].index = uint32(value)
		indexes[links[i].index] = true
		links[i].iface = strings.Trim(queryEdgeSNMP(t, sidecar, community, ".1.3.6.1.2.1.2.2.1.2."+index), "\"")
		kernel := strings.TrimSpace(lab.docker(t, "exec", lab.container("rtr-a"), "cat", "/sys/class/net/"+links[i].iface+"/ifindex"))
		if kernel != index {
			t.Fatal("SNMP interface did not come from the same FRR kernel", links[i].name, index, kernel)
		}
	}
	ixFile := filepath.Join(t.TempDir(), "ixpfx.json")
	raw, err := json.Marshal(map[string]any{"version": 1, "object": "ixpfx", "observed_at": time.Now().UTC().Add(-time.Second), "complete": true, "record_count": 2, "data": []map[string]any{{"id": 7, "ixlan_id": 11, "protocol": "IPv4", "prefix": links[1].prefix, "status": "ok"}, {"id": 8, "ixlan_id": 11, "protocol": "IPv6", "prefix": links[1].prefix6, "status": "ok"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ixFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	st := shipped.Start(t, shipped.Options{Name: "rolesrouter", TenantBand: 4, Env: map[string]string{"PROBECTL_FLOW_ENRICH_IX_PREFIX_FILE": ixFile}})
	reg := registerEdgeFlowEvidence(t, st, primary)
	requireRoleSourceBinding(t, st, reg, map[string]string{"agent_id": reg.agentID, "source_kind": "flow_exporter", "source_ref": primary, "context_id": reg.contextID, "anchor_entity_id": reg.deviceID})
	deviceAgent := startShippedEdgeSNMP(t, st, reg, "role-primary", primary, community)
	awaitEdgeSNMPEvidence(t, st, reg, deviceAgent, primary)
	ids := awaitRoleRouterInterfaces(t, st, reg, links)
	listener := startRouterBMPEvidenceListener(t, st, lab, reg, reg.deviceID)
	policy := putRoleRouterPolicy(t, st, reg, entity.InterfaceRolePolicyRecord{}, []uint32{edgeASN}, []uint32{rtrBASN})
	awaitRoleRouterLabels(t, st, reg, links, ids)

	other := registerSecondRouterTenant(t, st, reg)
	otherAgent := startShippedEdgeSNMP(t, st, other, "role-paired", primary, community)
	awaitEdgeSNMPEvidence(t, st, other, otherAgent, primary)
	assertRouterTenantSplit(t, st, reg, other, primary)
	for _, id := range ids {
		code, _ := st.Do(t, other.cookie, http.MethodGet, roleRouterPath(reg, id), nil)
		if code != http.StatusNotFound {
			t.Fatalf("foreign tenant could select the primary router's role identity: HTTP %d", code)
		}
	}

	// Real captured packets on every handoff use the SAME observed kernel index.
	// Pinned softflowd1.1.0 accepts -i index:interface; it does not infer Linux
	// indices itself. Never replace these packets with a constructed UDP frame.
	destination := startShippedRouterFlow(t, st, lab, reg, primary)
	image := buildRoleRouterExporter(t, lab)
	observed := time.Now()
	for _, link := range links {
		exporter := startRoleRouterExporter(t, lab, image, destination, link)
		emitRoleRouterTraffic(t, lab, exporter, link)
		emitRoleRouterCapturedTraffic(t, lab, exporter, link, link.routerIP6, link.peerIP6, "58", true)
	}
	awaitRoleRouterFlow(t, st, reg, links, observed)

	// Actual operator removal is a negative control for origin authority.
	// An inferred peer device must not substitute for the emitting router.
	requireRoleSourceBinding(t, st, reg, routerBMPSourceBinding(listener.collectorID, listener.routerID, reg.contextID, ""))
	without := append([]roleRouterLink(nil), links...)
	without[0].role, without[2].role = entity.InterfaceRoleOther, entity.InterfaceRoleOther
	awaitRoleRouterLabels(t, st, reg, without, ids)
	requireRoleSourceBinding(t, st, reg, routerBMPSourceBinding(listener.collectorID, listener.routerID, reg.contextID, reg.deviceID))
	awaitRoleRouterLabels(t, st, reg, links, ids)

	overridePath := strings.TrimSuffix(roleRouterPath(reg, ids[links[2].index]), "/role") + "/role-override"
	code, body := st.Do(t, reg.cookie, http.MethodPut, overridePath, map[string]any{"expected_id": "", "expected_revision": "0", "role": entity.InterfaceRolePrivate})
	var override entity.InterfaceRoleOverrideRecord
	if code != http.StatusOK || json.Unmarshal(body, &override) != nil || override.ID == "" {
		t.Fatalf("real-router override was not saved: HTTP %d", code)
	}
	policy = putRoleRouterPolicy(t, st, reg, policy, []uint32{edgeASN, rtrBASN}, nil)
	overridden := append([]roleRouterLink(nil), links...)
	overridden[2].role = entity.InterfaceRolePrivate
	awaitRoleRouterLabels(t, st, reg, overridden, ids)

	// A real failed poll must invalidate automatic facts, while the explicit
	// operator override stays readable without inventing source freshness.
	lab.docker(t, "stop", sidecar)
	awaitRoleRouterUnavailable(t, st, reg, links, ids, links[2].index)
	lab.docker(t, "start", sidecar)
	awaitRoleRouterLabels(t, st, reg, overridden, ids)
	code, _ = st.Do(t, reg.cookie, http.MethodDelete, overridePath, map[string]any{"expected_id": override.ID, "expected_revision": override.Revision, "confirmed": true})
	if code != http.StatusNoContent {
		t.Fatalf("real-router explicit override reset: HTTP %d", code)
	}
	links[2].role = entity.InterfaceRoleTransit
	awaitRoleRouterLabels(t, st, reg, links, ids)
	otherIDs := awaitRoleRouterInterfaces(t, st, other, links)
	renderRoleRouterSurfaces(t, st, reg, other, links, ids, otherIDs, observed)

	if t.Failed() {
		return
	}
	proveRoleRouterStdio(t, st, reg, other, links, ids, otherIDs)
	if t.Failed() {
		return
	}
	// Revoke only the primary tenant's actual issued source credential. The
	// identical physical addresses in the sibling tenant retain their authority.
	code, body = st.Do(t, reg.cookie, http.MethodPost, "/v1/agents/"+deviceAgent+"/revoke", nil)
	var revoked struct {
		AgentID  string `json:"agent_id"`
		SPIFFEID string `json:"spiffe_id"`
		Serials  int    `json:"live_serials_revoked"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &revoked) != nil || revoked.AgentID != deviceAgent || revoked.SPIFFEID != crypto.EntitySPIFFEID(reg.tenantID, deviceAgent) || revoked.Serials == 0 {
		t.Fatalf("real role source credential was not revoked: HTTP%d", code)
	}
	awaitRoleRouterUnavailable(t, st, reg, links, ids, 0)
	awaitRoleRouterLabels(t, st, other, []roleRouterLink{links[1]}, otherIDs)
	if policy.Revision == "0" {
		t.Fatal("real-router reclassification did not retain a versioned policy")
	}
	t.Log("real-integration: same FRR router/three distinct kernel interfaces, current SNMP/BMP and captured IPFIX roles; synthetic ixpfx; origin-removal and paired-tenant controls; override survives reclassification")
}

func requireRoleSourceBinding(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, body map[string]string) {
	t.Helper()
	code, _ := st.Do(t, reg.cookie, http.MethodPut, "/v1/entity-source-contexts", body)
	if code != http.StatusOK {
		t.Fatalf("real-router source binding: HTTP %d", code)
	}
}

func roleRouterPath(reg edgeFlowRegistration, id string) string {
	return "/v1/entity-contexts/" + reg.contextID + "/interfaces/" + id + "/role"
}

func putRoleRouterPolicy(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, old entity.InterfaceRolePolicyRecord, providers, customers []uint32) entity.InterfaceRolePolicyRecord {
	t.Helper()
	revision := old.Revision
	if revision == "" {
		revision = "0"
	}
	code, body := st.Do(t, reg.cookie, http.MethodPut, "/v1/entity-contexts/"+reg.contextID+"/interface-role-policy", map[string]any{"expected_id": old.ID, "expected_revision": revision, "definition": entity.InterfaceRolePolicyDefinition{ProviderASNs: providers, CustomerASNs: customers, DescriptionRules: []entity.InterfaceRoleDescriptionRule{}}})
	var got entity.InterfaceRolePolicyRecord
	if code != http.StatusOK || json.Unmarshal(body, &got) != nil || got.TenantID != reg.tenantID || got.ContextID != reg.contextID || got.ID == "" {
		t.Fatalf("real-router policy: HTTP %d", code)
	}
	return got
}

func awaitRoleRouterInterfaces(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, links []roleRouterLink) map[uint32]string {
	t.Helper()
	ids := map[uint32]string{}
	shipped.Await(t, "same-router SNMP canonical interfaces", 60*time.Second, func() bool {
		found := map[uint32]string{}
		cursor := ""
		seen := map[string]bool{}
		for {
			path := "/v1/entities?context_id=" + reg.contextID + "&limit=100"
			if cursor != "" {
				path += "&cursor=" + cursor
			}
			code, body := st.Do(t, reg.cookie, http.MethodGet, path, nil)
			var page entity.Page
			if code != http.StatusOK || json.Unmarshal(body, &page) != nil || page.Scope.TenantID != reg.tenantID || page.Scope.ContextID != reg.contextID {
				return false
			}
			for _, node := range page.Items {
				for _, link := range links {
					if node.Kind == entity.Interface && node.Label == "ifIndex "+strconv.FormatUint(uint64(link.index), 10) {
						found[link.index] = node.ID
					}
				}
			}
			cursor = page.NextCursor
			if cursor == "" {
				break
			}
			if seen[cursor] {
				t.Fatal("same-router interface walk repeated its cursor")
			}
			seen[cursor] = true
		}
		if len(found) != len(links) {
			return false
		}
		ids = found
		return true
	})
	return ids
}

func awaitRoleRouterLabels(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, links []roleRouterLink, ids map[uint32]string) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	diagnostic := "no role returned"
	for time.Now().Before(deadline) {
		complete := true
		for _, link := range links {
			code, body := st.Do(t, reg.cookie, http.MethodGet, roleRouterPath(reg, ids[link.index]), nil)
			var got servedRouterRole
			if code != http.StatusOK || json.Unmarshal(body, &got) != nil || got.TenantID != reg.tenantID || got.ContextID != reg.contextID || got.InterfaceID != ids[link.index] || got.Role != link.role || (link.role != entity.InterfaceRoleOther && len(got.Sources) == 0) || !got.SNMPCurrent || !got.PrefixCurrent {
				complete = false
				diagnostic = fmt.Sprintf("%s HTTP%d role=%s expected=%s SNMP=%t prefix=%t", link.name, code, got.Role, link.role, got.SNMPCurrent, got.PrefixCurrent)
				break
			}
			if link.role == entity.InterfaceRoleIX && !strings.Contains(strings.Join(got.Sources, ","), "peeringdb/ixpfx/7/ixlan/11/snapshot/") {
				t.Fatal("real IX interface lost the complete IPv4 prefix generation")
			}
			if link.role == entity.InterfaceRoleIX && !strings.Contains(strings.Join(got.Sources, ","), "peeringdb/ixpfx/8/ixlan/11/snapshot/") {
				t.Fatal("real IX interface lost the complete IPv6 prefix generation")
			}
			if link.role == entity.InterfaceRolePrivate && got.Reason != "operator_override" {
				t.Fatal("real router override lost its source")
			}
			if link.role == entity.InterfaceRoleOther && (got.Reason != "insufficient_evidence" || len(got.Sources) != 0) {
				t.Fatal("unbound BMP origin invented a relationship source", got)
			}
		}
		if complete {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("same-router real roles lost current source or explicit origin authority", diagnostic)
}

func addRoleRouterLink(t *testing.T, lab *routingLab, name, peer string, family, peerASN int, role entity.InterfaceRole) roleRouterLink {
	t.Helper()
	network := lab.name + "-" + name
	var base, prefix6, base6 string
	for attempt := 0; attempt < 8; attempt++ {
		part := (time.Now().Nanosecond()/1000+attempt*37)%250 + 1
		candidate := fmt.Sprintf("10.%d.%d.", family, part)
		candidate6 := fmt.Sprintf("fd42:%x:%x::", family, part)
		out, err := exec.Command("docker", "network", "create", "--subnet", candidate+"0/24", "--ipv6", "--subnet", candidate6+"/64", network).CombinedOutput()
		if err == nil {
			base, base6, prefix6 = candidate, candidate6, candidate6+"/64"
			break
		}
		if !strings.Contains(string(out), "overlap") {
			t.Fatalf("create owned role network: %v %.400s", err, out)
		}
	}
	if base == "" {
		t.Fatal("no free private subnet for owned role relationship")
	}
	t.Cleanup(func() {
		for _, router := range []string{"rtr-a", peer} {
			_ = exec.Command("docker", "network", "disconnect", "--force", network, lab.container(router)).Run()
		}
		_ = exec.Command("docker", "network", "rm", network).Run()
	})
	link := roleRouterLink{name: name, peer: peer, routerIP: base + "11", peerIP: base + "12", prefix: base + "0/24", role: role, routerIP6: base6 + "11", peerIP6: base6 + "12", prefix6: prefix6}
	lab.docker(t, "network", "connect", "--ip", link.routerIP, "--ip6", link.routerIP6, network, lab.container("rtr-a"))
	lab.docker(t, "network", "connect", "--ip", link.peerIP, "--ip6", link.peerIP6, network, lab.container(peer))
	for _, side := range []struct {
		router, neighbor string
		asn, remote      int
	}{{"rtr-a", link.peerIP, rtrAASN, peerASN}, {peer, link.routerIP, peerASN, rtrAASN}} {
		lab.docker(t, "exec", lab.container(side.router), "vtysh", "-c", "configure terminal", "-c", "router bgp "+strconv.Itoa(side.asn), "-c", "neighbor "+side.neighbor+" remote-as "+strconv.Itoa(side.remote), "-c", "address-family ipv4 unicast", "-c", "neighbor "+side.neighbor+" activate", "-c", "end")
	}
	shipped.Await(t, "real FRR "+name+" session", 45*time.Second, func() bool {
		raw, err := exec.Command("docker", "exec", lab.container("rtr-a"), "vtysh", "-c", "show bgp ipv4 unicast summary json").Output()
		if err != nil {
			return false
		}
		return roleRouterSessionEstablished(raw, link.peerIP)
	})
	for _, side := range []struct {
		router, neighbor string
		asn, remote      int
	}{{"rtr-a", link.peerIP6, rtrAASN, peerASN}, {peer, link.routerIP6, peerASN, rtrAASN}} {
		// Do not send IPv4 NLRI over IPv6 transport: use the actual native AFI.
		lab.docker(t, "exec", lab.container(side.router), "vtysh", "-c", "configure terminal", "-c", "router bgp "+strconv.Itoa(side.asn), "-c", "no bgp network import-check", "-c", "neighbor "+side.neighbor+" remote-as "+strconv.Itoa(side.remote), "-c", "address-family ipv4 unicast", "-c", "no neighbor "+side.neighbor+" activate", "-c", "exit-address-family", "-c", "address-family ipv6 unicast", "-c", "neighbor "+side.neighbor+" activate", "-c", "network "+link.prefix6, "-c", "end")
	}
	shipped.Await(t, "real FRR IPv6 "+name+" session", 45*time.Second, func() bool {
		raw, err := exec.Command("docker", "exec", lab.container("rtr-a"), "vtysh", "-c", "show bgp ipv6 unicast summary json").Output()
		if err != nil {
			return false
		}
		return roleRouterSessionEstablished(raw, link.peerIP6)
	})
	return link
}

func buildRoleRouterExporter(t *testing.T, lab *routingLab) string {
	t.Helper()
	image := lab.name + "-softflowd:1.1.0"
	cmd := exec.Command("docker", "build", "-q", "-t", image, "-")
	cmd.Stdin = strings.NewReader("FROM alpine:3.22.6@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8\nRUN apk add --no-cache softflowd=1.1.0-r0\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build pinned real-router exporter: %v %.1000s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", image).Run() })
	return image
}

func startRoleRouterExporter(t *testing.T, lab *routingLab, image, destination string, link roleRouterLink) string {
	t.Helper()
	if link.index > 65535 {
		t.Fatal("pinned softflowd1.1.0 cannot represent the observed kernel index; different real exporter required", link.index)
	}
	name := lab.name + "-" + link.name + "-flow"
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "--force", name).Run() })
	lab.docker(t, "create", "--name", name, "--network", "container:"+lab.container("rtr-a"), "--cap-add", "NET_RAW", image, "softflowd", "-d", "-N", "-i", strconv.FormatUint(uint64(link.index), 10)+":"+link.iface, "-v", "10", "-B", "65536", "-n", destination, "-c", "/tmp/softflowd.ctl")
	lab.docker(t, "start", name)
	shipped.Await(t, "same-router "+link.name+" capture", 30*time.Second, func() bool {
		return exec.Command("docker", "exec", name, "softflowctl", "-c", "/tmp/softflowd.ctl", "statistics").Run() == nil
	})
	return name
}

func emitRoleRouterTraffic(t *testing.T, lab *routingLab, exporter string, link roleRouterLink) {
	t.Helper()
	emitRoleRouterCapturedTraffic(t, lab, exporter, link, link.routerIP, link.peerIP, "1", false)
}

func emitRoleRouterCapturedTraffic(t *testing.T, lab *routingLab, exporter string, link roleRouterLink, source, destination, protocol string, ipv6 bool) {
	t.Helper()
	lab.docker(t, "exec", exporter, "softflowctl", "-c", "/tmp/softflowd.ctl", "delete-all")
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	args := []string{"exec", exporter, "ping"}
	if ipv6 {
		args = append(args, "-6")
	}
	args = append(args, "-A", "-q", "-I", link.iface, "-c", "4096", "-s", "1200", "-W", "1", destination)
	if out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("real %s traffic: %v %.400s", link.name, err, out)
	}
	shipped.Await(t, "real captured "+link.name+" packets", 10*time.Second, func() bool {
		dump, err := exec.Command("docker", "exec", exporter, "softflowctl", "-c", "/tmp/softflowd.ctl", "dump-flows").Output()
		return err == nil && strings.Contains(string(dump), source) && strings.Contains(string(dump), destination) && strings.Contains(string(dump), "proto:"+protocol)
	})
	lab.docker(t, "exec", exporter, "softflowctl", "-c", "/tmp/softflowd.ctl", "expire-all")
}

func awaitRoleRouterFlow(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, links []roleRouterLink, observed time.Time) {
	t.Helper()
	want := map[uint32]entity.InterfaceRole{}
	for _, link := range links {
		want[link.index] = link.role
	}
	shipped.Await(t, "real same-router IPFIX role groups", 60*time.Second, func() bool {
		plan := flow.QueryPlan{From: observed.Add(-time.Minute), To: time.Now().Add(time.Minute), View: "table", GroupBy: []string{"in_if_role", "out_if_role", "net_type"}, Metrics: []flow.QueryMetric{{Measure: "flows", Calculation: "total", Role: "primary"}}}
		code, body := st.Do(t, reg.cookie, http.MethodPost, "/v1/explorer/query", map[string]any{"source": "flow", "flow": plan})
		var got struct {
			Flow *flowstore.PlanResult `json:"flow"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &got) != nil || got.Flow == nil || got.Flow.RoleTenantID != reg.tenantID || len(got.Flow.RoleDigest) != 64 {
			return false
		}
		seen := map[string]bool{}
		for _, row := range got.Flow.Rows {
			if row.Metrics["flows:total"] != "" && row.Metrics["flows:total"] != "0" {
				for _, field := range []string{"in_if_role", "out_if_role"} {
					seen[row.Group[field]+"/"+row.Group["net_type"]] = true
				}
			}
		}
		for _, link := range links {
			if !seen[string(link.role)+"/ipv4"] || !seen[string(link.role)+"/ipv6"] {
				return false
			}
		}
		indexes := map[uint32]bool{}
		for _, source := range got.Flow.RoleSources {
			expected, targeted := want[source.IfIndex]
			if !targeted {
				expected = entity.InterfaceRoleOther
			}
			if source.TenantID != reg.tenantID || source.ContextID != reg.contextID || source.RouterID != reg.deviceID || source.Role != expected {
				t.Fatal("real flow source crossed router/tenant/interface authority", source)
			}
			if targeted {
				indexes[source.IfIndex] = true
			}
		}
		return len(indexes) == len(links)
	})
}

// These are real served pages, not mocked API/DOM fixtures. Fresh contexts use
// the real tenant session and shipped theme toggle. The same WCAG tags as the
// standing browser gate apply to the complete final page in each theme.
func renderRoleRouterSurfaces(t *testing.T, st *shipped.Stack, first, second edgeFlowRegistration, links []roleRouterLink, firstIDs, secondIDs map[uint32]string, observed time.Time) {
	t.Helper()
	for _, pair := range []struct {
		reg, other edgeFlowRegistration
		ids        map[uint32]string
		name       string
	}{{first, second, firstIDs, "primary"}, {second, first, secondIDs, "paired"}} {
		plan := flow.QueryPlan{From: observed.Add(-time.Minute), To: time.Now().Add(time.Minute), View: "table", GroupBy: []string{"in_if_role", "out_if_role"}, Metrics: []flow.QueryMetric{{Measure: "flows", Calculation: "total", Role: "primary"}}}
		code, raw := st.Do(t, pair.reg.cookie, http.MethodPost, "/v1/explorer/query", map[string]any{"source": "flow", "flow": plan})
		var query struct {
			Flow *flowstore.PlanResult `json:"flow"`
		}
		if code != http.StatusOK || json.Unmarshal(raw, &query) != nil || query.Flow == nil || query.Flow.RoleTenantID != pair.reg.tenantID || len(query.Flow.RoleDigest) != 64 {
			t.Fatalf("served role browser prerequisite current tenant query: HTTP%d", code)
		}
		if pair.reg.tenantID == second.tenantID && (len(query.Flow.RoleSources) != 0 || query.Flow.Totals["flows:total"] != "0") {
			t.Fatal("paired browser tenant received another tenant's physical flow source")
		}
		code, raw = st.Do(t, pair.reg.cookie, http.MethodPost, "/v1/explorer/flow-views", map[string]any{"definition": flow.QueryViewDefinition{Name: "Same-router role provenance", Visibility: "private", Time: flow.QueryViewTime{Mode: "absolute"}, Plan: plan}})
		var saved flow.SavedQueryView
		if code != http.StatusCreated || json.Unmarshal(raw, &saved) != nil || saved.ID == "" {
			t.Fatalf("save served role view: HTTP%d", code)
		}
		for _, theme := range []string{"light", "dark"} {
			label := theme + "/" + pair.name
			t.Run(label+"/admin", func(t *testing.T) {
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL: st.BaseURL + "/ui/admin", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: pair.reg.cookie}},
					TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile, Theme: theme, Accessibility: true,
					Expect: []string{"Interface roles"}, Absent: []string{pair.other.deviceID},
					Steps: []testsupport.RenderStep{
						{Select: "[data-interface-roles] select >> nth=0", Value: pair.reg.contextID},
						{Select: "[data-interface-roles] select >> nth=1", Value: pair.ids[links[1].index]},
						{Click: "Refresh role explanation", Within: "[aria-label='Current interface role']", Expect: []string{"ix peering", "Current interface evidence.", "Complete current prefixes.", "peeringdb/ixpfx/7/ixlan/11/snapshot/", "peeringdb/ixpfx/8/ixlan/11/snapshot/"}, ExpectWithin: "[aria-label='Current interface role']"},
						{Click: "Add description rule", Expect: []string{"Description pattern 1"}},
						{Fill: "[data-interface-roles] input >> nth=2", Value: "^not-a-live-router-interface$"},
						{Click: "Save complete role policy", Expect: []string{"Complete role policy saved."}},
						{Click: "Remove rule 1", Expect: []string{"0 description rules; page 1 of 1."}},
						{Click: "Save complete role policy", Expect: []string{"Complete role policy saved."}},
						{Select: "[data-interface-roles] select >> nth=2", Value: "private_peering"},
						{Click: "Save manual role override", Expect: []string{"Current override: private peering."}},
						{Click: "Refresh role explanation", Within: "[aria-label='Current interface role']", Expect: []string{"private peering", "operator override"}, ExpectWithin: "[aria-label='Current interface role']"},
						{Click: "Reset manual role override", Expect: []string{"Reset manual interface role?"}},
						{Click: "Confirm role reset", Within: "[role='dialog']", Gone: true},
						{Click: "Refresh role explanation", Within: "[aria-label='Current interface role']", Expect: []string{"ix peering", "Complete current prefixes."}, ExpectWithin: "[aria-label='Current interface role']"},
					},
				})
			})
			t.Run(label+"/flow", func(t *testing.T) {
				expected := []string{"Roles describe current evidence at query time."}
				if pair.reg.tenantID == first.tenantID {
					expected = append(expected, pair.reg.deviceID, firstIDs[links[1].index], "ix peering", "transit")
				} else {
					expected = append(expected, "No current owned interface metadata matched this result.")
				}
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL: st.BaseURL + "/ui/explore?native_flow=1&flow_view=" + saved.ID, Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: pair.reg.cookie}},
					TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile, Theme: theme, Accessibility: true,
					Expect: []string{"Flow explorer"}, Absent: []string{pair.other.deviceID},
					Steps: []testsupport.RenderStep{
						{Click: "Run flow query", Expect: []string{"Frozen flow results"}},
						{Click: fmt.Sprintf("Interface role sources (%d)", len(query.Flow.RoleSources)), Expect: expected},
					},
				})
			})
		}
	}
}

func awaitRoleRouterUnavailable(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, links []roleRouterLink, ids map[uint32]string, manual uint32) {
	t.Helper()
	shipped.Await(t, "real role source failure or revocation withdraws automatic metadata", 90*time.Second, func() bool {
		for _, link := range links {
			code, body := st.Do(t, reg.cookie, http.MethodGet, roleRouterPath(reg, ids[link.index]), nil)
			var got servedRouterRole
			if code != http.StatusOK || json.Unmarshal(body, &got) != nil || got.TenantID != reg.tenantID || got.ContextID != reg.contextID || got.InterfaceID != ids[link.index] || got.SNMPCurrent || got.PrefixCurrent {
				return false
			}
			if link.index == manual {
				if got.Role != entity.InterfaceRolePrivate || got.Reason != "operator_override" || len(got.Sources) != 1 || !strings.HasPrefix(got.Sources[0], "override/") {
					t.Fatal("real source loss changed the explicit override or invented automatic authority", got)
				}
			} else if got.Role != entity.InterfaceRoleOther || got.Reason != "insufficient_evidence" || len(got.Sources) != 0 {
				return false
			}
		}
		return true
	})
}

// Actual compiled command processes use the same current stores, local IX
// generation, least-privilege serve login and production credential refresh.
func proveRoleRouterStdio(t *testing.T, st *shipped.Stack, first, second edgeFlowRegistration, links []roleRouterLink, firstIDs, secondIDs map[uint32]string) {
	t.Helper()
	pool, err := pgxpool.New(t.Context(), st.AdminDSN)
	if err != nil {
		t.Fatal("owned role process credential store", err)
	}
	defer pool.Close()
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		t.Run("stdio/"+wire, func(t *testing.T) {
			type client struct {
				reg               edgeFlowRegistration
				encoder           *json.Encoder
				decoder           *json.Decoder
				user, interfaceID string
			}
			clients := make([]client, 0, 2)
			for lane, reg := range []edgeFlowRegistration{first, second} {
				code, _ := st.Do(t, reg.cookie, http.MethodPut, "/v1/governance/policy", map[string]any{"ai_remote_egress": true, "redact_export": true})
				if code != http.StatusOK {
					t.Fatalf("owned role process requires explicit audited tenant consent: HTTP%d", code)
				}
				code, raw := st.Do(t, reg.cookie, http.MethodGet, "/v1/me", nil)
				var me struct {
					UserID   string `json:"user_id"`
					TenantID string `json:"tenant_id"`
				}
				if code != http.StatusOK || json.Unmarshal(raw, &me) != nil || me.UserID == "" || me.TenantID != reg.tenantID {
					t.Fatal("owned role process credential has no current tenant user")
				}
				issued := strings.Split(strings.TrimSpace(st.Subcommand(t, "mcp-token", "--tenant", reg.tenantID, "--user", me.UserID, "--name", "role-process-"+wire, "--scope", "read,ai.query", "--expires-days", "1")), "\n")
				token := issued[len(issued)-1]
				input, output := st.MCPStdio(t, fmt.Sprintf("role-stdio-%s-%d", wire, lane), token)
				selected := firstIDs[links[1].index]
				if lane == 1 {
					selected = secondIDs[links[1].index]
				}
				c := client{reg: reg, encoder: json.NewEncoder(input), decoder: json.NewDecoder(output), user: me.UserID, interfaceID: selected}
				if wire == "2025-11-25" {
					if err := c.encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": map[string]any{"protocolVersion": wire, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "owned-router-client", "version": "1"}}}); err != nil {
						t.Fatal(err)
					}
					var init struct {
						Result struct {
							Version string `json:"protocolVersion"`
						} `json:"result"`
					}
					if c.decoder.Decode(&init) != nil || init.Result.Version != wire {
						t.Fatal("shipped role process did not negotiate legacy protocol")
					}
					if err := c.encoder.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
						t.Fatal(err)
					}
				}
				clients = append(clients, c)
			}
			call := func(c client, interfaceID string, wantOK bool) {
				t.Helper()
				params := map[string]any{"name": "interface_role_explain", "arguments": map[string]any{"context_id": c.reg.contextID, "interface_id": interfaceID}}
				if wire == "2026-07-28" {
					params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": wire, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
				}
				if err := c.encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}); err != nil {
					t.Fatal("shipped role process input", err)
				}
				var reply struct {
					Error  json.RawMessage `json:"error"`
					Result struct {
						IsError    bool            `json:"isError"`
						ResultType string          `json:"resultType"`
						Data       json.RawMessage `json:"structuredContent"`
						Content    []struct {
							Text string `json:"text"`
						} `json:"content"`
					} `json:"result"`
				}
				if c.decoder.Decode(&reply) != nil {
					t.Fatal("shipped role process lost a complete RPC frame")
				}
				success := len(reply.Error) == 0 && !reply.Result.IsError && len(reply.Result.Data) > 0 && string(reply.Result.Data) != "null"
				if success != wantOK {
					t.Fatal("shipped role process current authority mismatch", success, wantOK)
				}
				if !success {
					if len(reply.Result.Data) > 0 && string(reply.Result.Data) != "null" {
						t.Fatal("refused shipped role process disclosed role data")
					}
					return
				}
				if wire == "2026-07-28" && reply.Result.ResultType != "complete" || wire == "2025-11-25" && reply.Result.ResultType != "" {
					t.Fatal("shipped role process used the wrong revision")
				}
				if len(reply.Result.Content) != 1 || strings.TrimSpace(reply.Result.Content[0].Text) != strings.TrimSpace(string(reply.Result.Data)) {
					t.Fatal("shipped role process text and structured data differ")
				}
				var got servedRouterRole
				if json.Unmarshal(reply.Result.Data, &got) != nil || got.TenantID != c.reg.tenantID || got.ContextID != c.reg.contextID || got.InterfaceID != c.interfaceID || got.Role != entity.InterfaceRoleIX || !got.SNMPCurrent || !got.PrefixCurrent || !strings.Contains(strings.Join(got.Sources, ","), "peeringdb/ixpfx/7/ixlan/11/snapshot/") || !strings.Contains(strings.Join(got.Sources, ","), "peeringdb/ixpfx/8/ixlan/11/snapshot/") {
					t.Fatal("shipped role process lost canonical current dual-stack IX evidence")
				}
			}
			for lane, c := range clients {
				call(c, c.interfaceID, true)
				call(c, clients[1-lane].interfaceID, false)
			}
			if err := store.NewMCPTokens(pool).RevokeForUser(t.Context(), first.tenantID, clients[0].user); err != nil {
				t.Fatal("owned role process credential revocation", err)
			}
			call(clients[0], clients[0].interfaceID, false)
			call(clients[1], clients[1].interfaceID, true)
		})
	}
}

// A family-specific FRR summary has peers at its root. AFI/SAFI wrappers are
// emitted only by wildcard summaries; each caller selects the explicit family.
func roleRouterSessionEstablished(raw []byte, neighbor string) bool {
	var summary struct {
		Peers map[string]struct {
			State string `json:"state"`
		} `json:"peers"`
	}
	return json.Unmarshal(raw, &summary) == nil && summary.Peers[neighbor].State == "Established"
}
