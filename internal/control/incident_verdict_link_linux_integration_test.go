// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && linux

package control

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

func TestIncidentVerdictLinuxLinkFailureKeepsTenantScope(t *testing.T) {
	if os.Getenv("PROBECTL_TEST_REQUIRE_DEPENDENCY_LAB") != "1" {
		testsupport.SkipOptIn(t, "PROBECTL_TEST_REQUIRE_DEPENDENCY_LAB", "isolated Linux router and link namespaces")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the required Linux link proof needs namespace privileges")
	}
	f := newRoleExplanationAPIFixture(t)
	f.server.WithFlowStore(flowstore.NewMemory()).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	seedInterfaceRoleMCPConsent(f)
	newSender := newVerdictEvidenceSender(t, f)
	var incidents [2]string
	var windows [2]incident.VerdictInput
	for lane, tenant := range f.tenants {
		network := newDependencyPhysicalNetwork(t)
		sender := newSender(tenant, "role-snmp")
		index, before := readVerdictLinuxLink(t, network.router, "to-child")
		if *before.AdminStatus != 1 || *before.OperStatus != 1 {
			t.Fatal("the lab backbone did not start administratively and operationally up")
		}
		alias := strconv.FormatUint(uint64(index), 10)
		source := entity.SourceKey{AgentID: "role-snmp", Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"}
		claim := entity.Observation{
			ID: gouuid.NewString(), Source: source,
			Alias: entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: alias}, SourceRef: "snmp:ifIndex:" + alias,
			InterfaceName: "to-child", ObservedAt: f.observedAt(tenant), SNMPInterfaceState: &before,
		}
		if accepted, unresolved, err := sender.Submit(t.Context(), verdictLinuxLinkPoll(claim)); err != nil || accepted != 2 || unresolved != 0 {
			t.Fatal("the authenticated baseline link observation did not persist", accepted, unresolved, err)
		}
		id := gouuid.NewString()
		incidents[lane] = id
		var interfaceID string
		var actor *auth.Principal
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permIncidentRead, permTestRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			if err := sc.Q.QueryRow(ctx, `SELECT id::text FROM entities
 WHERE tenant_id=$1 AND context_id=$2 AND parent_entity_id=$3 AND kind='interface'
 AND source_agent_id=$4 AND configured_ref=$5 AND interface_index=$6`,
				tenant, f.contextID, f.routerID, source.AgentID, source.SourceRef, int64(index)).Scan(&interfaceID); err != nil {
				return err
			}
			if _, err := (store.InterfaceRoleConfiguration{}).PutOverride(ctx, sc, f.contextID, interfaceID, "", "0", entity.InterfaceRoleBackbone); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO incidents(tenant_id,id,title,entity_context_id,entity_id,identity_lookup_attempted)
 VALUES($1,$2,'isolated Linux link event',$3,$4,true)`, tenant, id, f.contextID, interfaceID); err != nil {
				return err
			}
			current, err := readCurrentUserAuthorityScope(ctx, sc, f.users[tenant])
			if err == nil {
				actor = auth.ClonePrincipal(current.principal)
			}
			return err
		})
		if lane == 0 {
			// Lower only the other end. The observed router interface stays
			// administratively up and loses carrier in the kernel.
			dependencyLabCommand(t, "ip", "-n", network.child, "link", "set", "to-router", "down")
		}
		var state entity.SNMPInterfaceState
		shipped.Await(t, "isolated router link reached its planted state", 3*time.Second, func() bool {
			currentIndex, current := readVerdictLinuxLink(t, network.router, "to-child")
			if currentIndex != index || *current.AdminStatus != 1 {
				t.Fatal("the lab changed the identity or administration of the observed interface")
			}
			state = current
			if lane == 0 {
				return *state.OperStatus == 2 || *state.OperStatus == 7
			}
			return *state.OperStatus == 1
		})
		at := f.observedAt(tenant)
		claim.ID, claim.ObservedAt, claim.SNMPInterfaceState = gouuid.NewString(), at, &state
		if accepted, unresolved, err := sender.Submit(t.Context(), verdictLinuxLinkPoll(claim)); err != nil || accepted != 2 || unresolved != 0 {
			t.Fatal("the authenticated lab link observation did not persist", accepted, unresolved, err)
		}
		input := incident.VerdictInput{From: at, To: f.observedAt(tenant)}
		shipped.Await(t, "the verdict window is no longer in the future", 5*time.Second, func() bool {
			return !input.To.After(time.Now())
		})
		windows[lane] = input
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		got, err := f.server.computeIncidentVerdict(ctx, actor, id, input.From, input.To, 128<<20)
		want, citations := incident.FaultYourNetwork, got.Hypotheses
		if lane == 1 {
			want = incident.FaultUnknown
		}
		if err != nil || got.Domain != want || len(citations) != 4 {
			t.Fatal("the routed link verdict lost the actual link state or tenant scope", got.Domain, want, got.Reason, citations, err)
		}
		originals := citations[0].For
		if lane == 1 {
			originals = citations[0].Against
		}
		if len(originals) != 1 || originals[0].EntityID != interfaceID || !originals[0].ObservedAt.Equal(at) {
			t.Fatal("the local verdict lost its exact interface observation", originals)
		}
		proveIncidentVerdictServedReaders(t, f, tenant, id, input, got)
		proveIncidentVerdictSignedExport(t, f, tenant, id, input, got)
	}
	for lane, tenant := range f.tenants {
		proveIncidentVerdictForeignReaderRefusal(t, f, tenant, incidents[1-lane], windows[1-lane])
	}
}

// Interface roles use the interface row from the current device poll. Both
// observations share the poll clock and the same authenticated source.
func verdictLinuxLinkPoll(link entity.Observation) []entity.Observation {
	root := entity.Observation{
		ID: gouuid.NewString(), Source: link.Source, ObservedAt: link.ObservedAt,
		Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: link.Source.SourceRef}, SourceRef: "snmp:configured-target",
	}
	return []entity.Observation{root, link}
}

// The lab adapts kernel ifindex and link flags to the existing IF-MIB evidence
// shape. Socket delivery and mTLS are real; this adapter is test-only.
func readVerdictLinuxLink(t *testing.T, namespace, device string) (uint32, entity.SNMPInterfaceState) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "-n", namespace, "-j", "link", "show", "dev", device).CombinedOutput()
	if err != nil {
		t.Fatalf("read the lab link state: %v: %s", err, out)
	}
	var links []struct {
		Index uint32   `json:"ifindex"`
		Flags []string `json:"flags"`
		Oper  string   `json:"operstate"`
	}
	if err := json.Unmarshal(out, &links); err != nil || len(links) != 1 || links[0].Index == 0 {
		t.Fatalf("invalid lab link readout: %v: %s", err, out)
	}
	link := links[0]
	admin, oper := uint32(2), uint32(4)
	if slices.Contains(link.Flags, "UP") {
		admin = 1
	}
	switch link.Oper {
	case "UP":
		oper = 1
	case "DOWN":
		oper = 2
	case "LOWERLAYERDOWN":
		oper = 7
	}
	return link.Index, entity.SNMPInterfaceState{Version: 1, AdminStatus: &admin, OperStatus: &oper}
}
