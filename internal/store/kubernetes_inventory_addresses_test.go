// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestKubernetesAddressProjectionPreservesHandoffsAndSharedAddressGaps(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	const contextID = "22222222-2222-4222-8222-222222222222"
	tick := func(second int) time.Time { return time.Unix(int64(1_700_000_000+second), 0).UTC() }
	snapshot := KubernetesInventorySnapshot{
		Scope: entity.Scope{TenantID: tenant, ContextID: contextID},
		Sources: []KubernetesInventorySource{
			{ID: "33333333-3333-4333-8333-333333333333", ContextID: contextID, ClusterID: "44444444-4444-4444-8444-444444444444", Namespace: "blue", AssignedAt: tick(0)},
			{ID: "55555555-5555-4555-8555-555555555555", ContextID: contextID, ClusterID: "66666666-6666-4666-8666-666666666666", Namespace: "blue", AssignedAt: tick(0)},
		},
	}
	claim := func(lane, generation int, kind agentv1.KubernetesInventoryKind, uid, name, ip string, from, until int) {
		witness := KubernetesInventoryFact{
			SourceID: snapshot.Sources[lane].ID, GenerationID: fmt.Sprintf("00000000-0000-4000-8000-%012d", generation),
			Serial: "a", From: tick(from), Until: tick(until), WitnessKind: kind, WitnessUID: uid,
		}
		object, address := witness, witness
		object.Name, address.Address = name, ip
		snapshot.Facts = append(snapshot.Facts, address, object)
	}
	const reusedIP = "10.244.0.5"
	claim(0, 1, kubernetesPod, "old-pod", "web", reusedIP, 1, 8)
	claim(0, 2, kubernetesPod, "old-pod", "web", reusedIP, 3, 12)
	claim(1, 3, kubernetesPod, "old-pod", "web", reusedIP, 9, 13)
	claim(0, 4, kubernetesPod, "new-pod", "web", reusedIP, 12, 16)
	claim(0, 5, kubernetesService, "service", "web", "10.96.1.2", 2, 16)
	got, err := snapshot.AddressProjection(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr(reusedIP)
	cluster := snapshot.Sources[0].ClusterID
	want := []KubernetesAddressSpan{
		{netip.MustParseAddr("10.96.1.2"), tick(2), tick(16), KubernetesObjectIdentity{ClusterID: cluster, Namespace: "blue", UID: "service", Name: "web", Kind: kubernetesService}},
		{address, tick(1), tick(9), KubernetesObjectIdentity{ClusterID: cluster, Namespace: "blue", UID: "old-pod", Name: "web", Kind: kubernetesPod}},
		{address, tick(13), tick(16), KubernetesObjectIdentity{ClusterID: cluster, Namespace: "blue", UID: "new-pod", Name: "web", Kind: kubernetesPod}},
	}
	if got.Scope != snapshot.Scope || !slices.Equal(got.Spans, want) {
		t.Fatalf("address projection lost a proven owner or bridged the handoff: %+v", got)
	}
	for _, query := range []struct {
		from, until int
		uid         string
	}{{1, 9, "old-pod"}, {9, 10, ""}, {8, 14, ""}, {13, 16, "new-pod"}, {15, 17, ""}} {
		owner, ok := got.Resolve(address, tick(query.from), tick(query.until))
		if owner.UID != query.uid || ok != (query.uid != "") {
			t.Fatalf("resolution for [%d,%d) = (%+v, %t), want %q", query.from, query.until, owner, ok, query.uid)
		}
	}
}

func TestKubernetesWorkloadProjectionIntersectsOriginalControllerWindows(t *testing.T) {
	const (
		tenant     = "11111111-1111-4111-8111-111111111111"
		contextID  = "22222222-2222-4222-8222-222222222222"
		sourceID   = "33333333-3333-4333-8333-333333333333"
		generation = "44444444-4444-4444-8444-444444444444"
		next       = "55555555-5555-4555-8555-555555555555"
		replicaSet = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_REPLICA_SET
		deployment = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_DEPLOYMENT
		job        = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_JOB
	)
	tick := func(second int64) time.Time { return time.Unix(1_700_000_000+second, 0).UTC() }
	snapshot := KubernetesInventorySnapshot{
		Scope: entity.Scope{TenantID: tenant, ContextID: contextID},
		Sources: []KubernetesInventorySource{{ID: sourceID, ContextID: contextID,
			ClusterID: "66666666-6666-4666-8666-666666666666", Namespace: "blue", AssignedAt: tick(0)}},
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	object := func(gen string, index, from, until int64, kind agentv1.KubernetesInventoryKind, uid string, unowned bool) KubernetesInventoryFact {
		fact := KubernetesInventoryFact{SourceID: sourceID, GenerationID: gen, Serial: "a", WindowIndex: index,
			From: tick(from), Until: tick(until), WitnessKind: kind, WitnessUID: uid, Name: uid, ControllerUnowned: unowned}
		snapshot.Facts = append(snapshot.Facts, fact)
		return fact
	}
	address := func(pod KubernetesInventoryFact, ip string) {
		pod.Name, pod.Address = "", ip
		snapshot.Facts = append(snapshot.Facts, pod)
	}
	controller := func(child KubernetesInventoryFact, kind agentv1.KubernetesInventoryKind, uid string) {
		child.Name, child.Relationship = "", kubernetesController
		child.FromKind, child.FromUID, child.ToKind, child.ToUID = child.WitnessKind, child.WitnessUID, kind, uid
		snapshot.Facts = append(snapshot.Facts, child)
	}
	old := object(generation, 0, 1, 12, kubernetesPod, "old-pod", false)
	address(old, "10.244.0.5")
	controller(old, replicaSet, "web-replica")
	rs := object(generation, 1, 2, 10, replicaSet, "web-replica", false)
	controller(rs, deployment, "web-deploy")
	object(generation, 2, 3, 8, deployment, "web-deploy", true)
	overlap := object(next, 0, 7, 12, kubernetesPod, "old-pod", false)
	address(overlap, "10.244.0.5")
	controller(overlap, replicaSet, "web-replica") // Same UID, but no retained ReplicaSet in this generation.
	standalone := object(next, 0, 7, 12, kubernetesPod, "job-pod", false)
	address(standalone, "10.244.0.6")
	controller(standalone, job, "standalone")
	object(next, 1, 8, 11, job, "standalone", true)

	projection, err := snapshot.AddressProjection(ctx, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip          string
		from, until int64
		pod, owner  string
	}{
		{"10.244.0.5", 1, 3, "old-pod", ""},
		{"10.244.0.5", 3, 7, "old-pod", "web-deploy"},
		{"10.244.0.5", 6, 8, "old-pod", ""},
		{"10.244.0.5", 8, 12, "old-pod", ""},
		{"10.244.0.6", 8, 11, "job-pod", "standalone"},
		{"10.244.0.6", 7, 11, "job-pod", ""},
	} {
		addr := netip.MustParseAddr(tc.ip)
		pod, _ := projection.Resolve(addr, tick(tc.from), tick(tc.until))
		owner, present := projection.ResolveWorkload(addr, tick(tc.from), tick(tc.until))
		if pod.UID != tc.pod || owner.UID != tc.owner || present != (tc.owner != "") {
			t.Fatalf("%s [%d,%d) gives Pod %q and workload %q (%t), want %q and %q",
				tc.ip, tc.from, tc.until, pod.UID, owner.UID, present, tc.pod, tc.owner)
		}
	}
}
