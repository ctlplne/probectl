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
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type roleRouterLink struct {
	name, peer, routerIP, peerIP, prefix, iface string
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
// IPv6, stale/down source clocks, served themes and the remaining lifecycle
// controls retain their separate required proofs; this root does not close FX4.
func TestInterfaceRoleFRRSameRouterKeepsThreeRolesFlowAndOverride(t *testing.T) {
	if runtime.GOOS != "linux" {
		testsupport.SkipOrFatal(t, "same-router role proof requires a Linux host route to the private FRR Docker bridge")
	}
	lab := startRoutingLabNamed(t, "probectl-qa-beta-role-router-"+strconv.FormatInt(time.Now().UnixNano()%1e8, 36))
	primary := lab.ip["rtr-a"]
	addr, err := netip.ParseAddr(primary)
	if err != nil {
		t.Fatal(err)
	}
	links := []roleRouterLink{{name: "transit", peer: "edge", routerIP: primary, peerIP: lab.ip["edge"], prefix: netip.PrefixFrom(addr, 24).Masked().String(), role: entity.InterfaceRoleTransit}, addRoleRouterLink(t, lab, "ix", "rrc", 232, rrcASN, entity.InterfaceRoleIX), addRoleRouterLink(t, lab, "customer", "rtr-b", 233, rtrBASN, entity.InterfaceRoleCustomer)}
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
	raw, err := json.Marshal(map[string]any{"version": 1, "object": "ixpfx", "observed_at": time.Now().UTC().Add(-time.Second), "complete": true, "record_count": 1, "data": []map[string]any{{"id": 7, "ixlan_id": 11, "protocol": "IPv4", "prefix": links[1].prefix, "status": "ok"}}})
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
	code, _ = st.Do(t, reg.cookie, http.MethodDelete, overridePath, map[string]any{"expected_id": override.ID, "expected_revision": override.Revision, "confirmed": true})
	if code != http.StatusNoContent {
		t.Fatalf("real-router explicit override reset: HTTP %d", code)
	}
	links[2].role = entity.InterfaceRoleTransit
	awaitRoleRouterLabels(t, st, reg, links, ids)
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
				t.Fatal("real IX interface lost the complete prefix generation")
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
	var base string
	for attempt := 0; attempt < 8; attempt++ {
		candidate := fmt.Sprintf("10.%d.%d.", family, (time.Now().Nanosecond()/1000+attempt*37)%250+1)
		out, err := exec.Command("docker", "network", "create", "--subnet", candidate+"0/24", network).CombinedOutput()
		if err == nil {
			base = candidate
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
	link := roleRouterLink{name: name, peer: peer, routerIP: base + "11", peerIP: base + "12", prefix: base + "0/24", role: role}
	lab.docker(t, "network", "connect", "--ip", link.routerIP, network, lab.container("rtr-a"))
	lab.docker(t, "network", "connect", "--ip", link.peerIP, network, lab.container(peer))
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
		var summary struct {
			IPv4 struct {
				Peers map[string]struct {
					State string `json:"state"`
				} `json:"peers"`
			} `json:"ipv4Unicast"`
		}
		return json.Unmarshal(raw, &summary) == nil && summary.IPv4.Peers[link.peerIP].State == "Established"
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
	lab.docker(t, "exec", exporter, "softflowctl", "-c", "/tmp/softflowd.ctl", "delete-all")
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "exec", exporter, "ping", "-A", "-q", "-I", link.iface, "-c", "4096", "-s", "1200", "-W", "1", link.peerIP).CombinedOutput(); err != nil {
		t.Fatalf("real %s traffic: %v %.400s", link.name, err, out)
	}
	shipped.Await(t, "real captured "+link.name+" packets", 10*time.Second, func() bool {
		dump, err := exec.Command("docker", "exec", exporter, "softflowctl", "-c", "/tmp/softflowd.ctl", "dump-flows").Output()
		return err == nil && strings.Contains(string(dump), link.routerIP) && strings.Contains(string(dump), link.peerIP) && strings.Contains(string(dump), "proto:1")
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
		plan := flow.QueryPlan{From: observed.Add(-time.Minute), To: time.Now().Add(time.Minute), View: "table", GroupBy: []string{"in_if_role", "out_if_role"}, Metrics: []flow.QueryMetric{{Measure: "flows", Calculation: "total", Role: "primary"}}}
		code, body := st.Do(t, reg.cookie, http.MethodPost, "/v1/explorer/query", map[string]any{"source": "flow", "flow": plan})
		var got struct {
			Flow *flowstore.PlanResult `json:"flow"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &got) != nil || got.Flow == nil || got.Flow.RoleTenantID != reg.tenantID || len(got.Flow.RoleDigest) != 64 {
			return false
		}
		seen := map[entity.InterfaceRole]bool{}
		for _, row := range got.Flow.Rows {
			if row.Metrics["flows:total"] != "" && row.Metrics["flows:total"] != "0" {
				for _, field := range []string{"in_if_role", "out_if_role"} {
					seen[entity.InterfaceRole(row.Group[field])] = true
				}
			}
		}
		for _, link := range links {
			if !seen[link.role] {
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
