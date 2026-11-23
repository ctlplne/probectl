// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"context"
	"net/netip"
	"sync"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

type kubernetesInventorySnapshot struct {
	pods        kubernetesPodSnapshot
	supplements []kubernetesSupplementSnapshot
}

func (c *KubernetesInventoryCollector) readInventorySnapshot(ctx context.Context, perResource int64) (*kubernetesInventorySnapshot, error) {
	resources := kubernetesSupplementResources
	snapshot := &kubernetesInventorySnapshot{supplements: make([]kubernetesSupplementSnapshot, len(resources))}
	var group sync.WaitGroup
	for index, resource := range resources {
		group.Go(func() {
			snapshot.supplements[index], _ = c.reader.supplementSnapshot(ctx, resource, perResource)
		})
	}
	var err error
	snapshot.pods, err = c.reader.snapshot(ctx, kubernetesInventoryBudget)
	group.Wait()
	if err != nil {
		return nil, err
	}
	return snapshot, nil
}

func (c *KubernetesInventoryCollector) captureInventory(ctx context.Context, before *kubernetesInventorySnapshot) (*kubernetesPreparedUpload, *kubernetesInventorySnapshot, error) {
	resources := kubernetesSupplementResources
	perResource := int64(kubernetesInventoryBudget / len(resources))
	if before == nil {
		var err error
		before, err = c.readInventorySnapshot(ctx, perResource)
		if err != nil {
			return nil, nil, err
		}
	}
	if !waitKubernetesInventory(ctx, c.interval) {
		return nil, nil, ctx.Err()
	}
	after, err := c.readInventorySnapshot(ctx, perResource)
	if err != nil {
		return nil, nil, err
	}
	// Replay the same pair of collection rounds concurrently. A quiet
	// resource may wait for a bookmark, so its proof must not delay the
	// other resource watches or the start of the next ownership window.
	closed := make([]kubernetesSupplementWindow, len(resources))
	var group sync.WaitGroup
	for index, resource := range resources {
		first, last := before.supplements[index], after.supplements[index]
		if first.ResourceVersion == "" || last.ResourceVersion == "" {
			continue
		}
		group.Go(func() {
			closed[index], _ = c.reader.closeSupplementWindow(ctx, resource, first, last, perResource)
		})
	}
	podWindow, podRows, err := c.closePodWindow(ctx, before.pods, after.pods)
	group.Wait()
	if err != nil {
		return nil, after, err
	}
	if err = ctx.Err(); err != nil {
		return nil, nil, err
	}
	windows, rows := assembleKubernetesInventory(podWindow, podRows, closed)
	if len(windows) != len(resources)+1 {
		c.log.Warn("Kubernetes inventory has uncovered resource types", "binding_id", c.bindingID,
			"covered_resource_types", len(windows), "configured_resource_types", len(resources)+1)
	}
	upload, err := prepareKubernetesInventoryUpload(c.bindingID, windows, rows)
	return upload, after, err
}

func assembleKubernetesInventory(podWindow *agentv1.KubernetesInventoryWindow, podRows []*agentv1.KubernetesInventoryRow,
	closed []kubernetesSupplementWindow) ([]*agentv1.KubernetesInventoryWindow, []*agentv1.KubernetesInventoryRow) {
	windows := []*agentv1.KubernetesInventoryWindow{podWindow}
	rows := append([]*agentv1.KubernetesInventoryRow(nil), podRows...)
	pods := make(map[string]kubernetesPodMetadata)
	for _, row := range podRows {
		if object := row.GetObject(); object != nil {
			pods[object.Uid] = kubernetesPodMetadata{UID: object.Uid, Name: object.Name}
		} else if address := row.GetAddress(); address != nil {
			if value, err := netip.ParseAddr(address.Address); err == nil {
				pod := pods[address.Uid]
				pod.Addresses = append(pod.Addresses, value)
				pods[address.Uid] = pod
			}
		}
	}
	byService := make(map[string]kubernetesServiceMetadata)
	for _, captured := range closed {
		if captured.window != nil && captured.window.Kind == kubernetesServiceKind {
			for _, object := range captured.objects {
				if object.Service != nil {
					byService[object.Name] = *object.Service
				}
			}
		}
	}
	index := uint32(1)
	for _, captured := range closed {
		if captured.window == nil {
			continue
		}
		windows = append(windows, captured.window)
		for _, item := range captured.objects {
			rows = appendSupplementInventoryRows(rows, captured, item, index, byService, pods)
		}
		index++
	}
	return windows, rows
}

func appendSupplementInventoryRows(rows []*agentv1.KubernetesInventoryRow, captured kubernetesSupplementWindow,
	item kubernetesSupplementObject, index uint32, services map[string]kubernetesServiceMetadata, pods map[string]kubernetesPodMetadata) []*agentv1.KubernetesInventoryRow {
	kind := captured.window.Kind
	rows = append(rows, &agentv1.KubernetesInventoryRow{WindowIndex: index, Record: &agentv1.KubernetesInventoryRow_Object{
		Object: &agentv1.KubernetesInventoryObject{Kind: kind, Uid: item.UID, Name: item.Name, ControllerUnowned: kind > kubernetesSliceKind && item.Owner == nil},
	}})
	switch {
	case item.Service != nil:
		for _, address := range item.Service.Addresses {
			if !captured.disputedAddresses[address] {
				rows = append(rows, &agentv1.KubernetesInventoryRow{WindowIndex: index, Record: &agentv1.KubernetesInventoryRow_Address{
					Address: &agentv1.KubernetesInventoryAddress{Kind: kind, Uid: item.UID, Address: address.String()},
				}})
			}
		}
	case item.EndpointSlice != nil:
		service := services[item.EndpointSlice.Metadata.Labels["kubernetes.io/service-name"]]
		seenPod := make(map[string]bool)
		for _, backend := range item.EndpointSlice.serviceBackends(service, pods) {
			if !seenPod[backend.PodUID] {
				seenPod[backend.PodUID] = true
				rows = append(rows, &agentv1.KubernetesInventoryRow{WindowIndex: index, Record: &agentv1.KubernetesInventoryRow_Relationship{
					Relationship: &agentv1.KubernetesInventoryRelationship{
						Relation: agentv1.KubernetesInventoryRelationshipKind_KUBERNETES_INVENTORY_RELATIONSHIP_KIND_SERVICE_BACKEND,
						FromKind: kubernetesServiceKind, FromUid: backend.ServiceUID, ToKind: kubernetesPodKind,
						ToUid: backend.PodUID, EndpointSliceUid: backend.SliceUID,
					},
				}})
			}
		}
	case item.Owner != nil:
		if edge := kubernetesControllerInventoryRow(kind, item.UID, item.Owner, index); edge != nil {
			rows = append(rows, edge)
		}
	}
	return rows
}

func kubernetesControllerInventoryRow(kind kubernetesKind, uid string, owner *kubernetesOwnerReference, index uint32) *agentv1.KubernetesInventoryRow {
	for _, resource := range kubernetesSupplementResources {
		if resource.wireKind > kubernetesSliceKind && owner.APIVersion == resource.apiVersion && owner.Kind == resource.kind {
			return &agentv1.KubernetesInventoryRow{WindowIndex: index, Record: &agentv1.KubernetesInventoryRow_Relationship{
				Relationship: &agentv1.KubernetesInventoryRelationship{
					Relation: agentv1.KubernetesInventoryRelationshipKind_KUBERNETES_INVENTORY_RELATIONSHIP_KIND_CONTROLLER_OWNER,
					FromKind: kind, FromUid: uid, ToKind: resource.wireKind, ToUid: owner.UID,
				},
			}}
		}
	}
	return nil
}
