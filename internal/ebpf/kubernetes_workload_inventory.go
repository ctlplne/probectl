// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

type kubernetesKind = agentv1.KubernetesInventoryKind

const (
	kubernetesPodKind     = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_POD
	kubernetesServiceKind = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_SERVICE
	kubernetesSliceKind   = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_ENDPOINT_SLICE
)

type kubernetesSupplementResource struct {
	kubernetesResource
	wireKind kubernetesKind
}

var kubernetesSupplementResources = []kubernetesSupplementResource{
	{kubernetesResource{"v1", "Service", "/api/v1", "services"}, kubernetesServiceKind},
	{kubernetesResource{"discovery.k8s.io/v1", "EndpointSlice", "/apis/discovery.k8s.io/v1", "endpointslices"}, kubernetesSliceKind},
	{kubernetesResource{"apps/v1", "Deployment", "/apis/apps/v1", "deployments"}, agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_DEPLOYMENT},
	{kubernetesResource{"apps/v1", "ReplicaSet", "/apis/apps/v1", "replicasets"}, agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_REPLICA_SET},
	{kubernetesResource{"apps/v1", "DaemonSet", "/apis/apps/v1", "daemonsets"}, agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_DAEMON_SET},
	{kubernetesResource{"apps/v1", "StatefulSet", "/apis/apps/v1", "statefulsets"}, agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_STATEFUL_SET},
	{kubernetesResource{"batch/v1", "Job", "/apis/batch/v1", "jobs"}, agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_JOB},
	{kubernetesResource{"batch/v1", "CronJob", "/apis/batch/v1", "cronjobs"}, agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_CRON_JOB},
	{kubernetesResource{"v1", "ReplicationController", "/api/v1", "replicationcontrollers"}, agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_REPLICATION_CONTROLLER},
}

type kubernetesSupplementObject struct {
	UID, Name, ResourceVersion string
	Owner                      *kubernetesOwnerReference
	Service                    *kubernetesServiceMetadata
	EndpointSlice              *kubernetesEndpointSliceObject
}

type kubernetesSupplementSnapshot struct {
	kubernetesCollectionClock
	objects map[string]kubernetesSupplementObject
}

type kubernetesSupplementWindow struct {
	window            *agentv1.KubernetesInventoryWindow
	objects           []kubernetesSupplementObject
	disputedAddresses map[netip.Addr]bool
}

func (r *kubernetesPodReader) supplementSnapshot(ctx context.Context, resource kubernetesSupplementResource, maxBytes int64) (kubernetesSupplementSnapshot, error) {
	objects := make(map[string]kubernetesSupplementObject)
	clock, err := r.list(ctx, resource.kubernetesResource, maxBytes, func(raw json.RawMessage) (string, string, error) {
		object, err := readKubernetesSupplementObject(raw, r.namespace, resource, false)
		if err != nil {
			return "", "", err
		}
		objects[object.UID] = object
		return object.UID, object.Name, nil
	})
	if err != nil {
		return kubernetesSupplementSnapshot{}, err
	}
	return kubernetesSupplementSnapshot{kubernetesCollectionClock: clock, objects: objects}, nil
}

func readKubernetesSupplementObject(raw []byte, namespace string, resource kubernetesSupplementResource, watch bool) (kubernetesSupplementObject, error) {
	var header kubernetesPodObject
	if err := json.Unmarshal(raw, &header); err != nil || (watch || header.Kind != "") && header.Kind != resource.kind ||
		(watch || header.APIVersion != "") && header.APIVersion != resource.apiVersion || header.Metadata.Namespace != namespace ||
		!validKubernetesMetadataString(header.Metadata.UID) || !validKubernetesMetadataString(header.Metadata.Name) ||
		!entity.ValidKubernetesResourceVersion(header.Metadata.ResourceVersion) {
		return kubernetesSupplementObject{}, errKubernetesPodList
	}
	object := kubernetesSupplementObject{UID: header.Metadata.UID, Name: header.Metadata.Name, ResourceVersion: header.Metadata.ResourceVersion}
	for _, ref := range header.Metadata.Owners {
		if !ref.Controller {
			continue
		}
		if object.Owner != nil || !validKubernetesMetadataString(ref.UID) || !validKubernetesMetadataString(ref.Name) || ref.UID == object.UID {
			return kubernetesSupplementObject{}, errKubernetesPodList
		}
		object.Owner = &ref
	}
	switch resource.wireKind {
	case kubernetesServiceKind:
		var service kubernetesServiceObject
		if err := json.Unmarshal(raw, &service); err != nil {
			return kubernetesSupplementObject{}, errKubernetesPodList
		}
		observed, err := service.observation(namespace)
		if err != nil {
			return kubernetesSupplementObject{}, err
		}
		object.Service = &observed
	case kubernetesSliceKind:
		var slice kubernetesEndpointSliceObject
		if err := json.Unmarshal(raw, &slice); err != nil {
			return kubernetesSupplementObject{}, errKubernetesPodList
		}
		object.EndpointSlice = &slice
	}
	return object, nil
}

func (r *kubernetesPodReader) closeSupplementWindow(ctx context.Context, resource kubernetesSupplementResource,
	before, after kubernetesSupplementSnapshot, maxBytes int64) (kubernetesSupplementWindow, error) {
	if before.ResourceVersion == "" || after.ResourceVersion == "" || !after.ReadStartedAt.After(before.ReadCompletedAt) {
		return kubernetesSupplementWindow{}, errKubernetesCoverageGap
	}
	if order, known := entity.CompareKubernetesResourceVersions(before.ResourceVersion, after.ResourceVersion); known && order > 0 {
		return kubernetesSupplementWindow{}, errKubernetesCoverageGap
	}
	changed := make(map[string]bool)
	disputed := make(map[netip.Addr]bool)
	if resource.wireKind == kubernetesServiceKind {
		markDuplicateKubernetesServiceAddresses(before.objects, disputed)
		markDuplicateKubernetesServiceAddresses(after.objects, disputed)
	}
	var progress string
	if before.ResourceVersion != after.ResourceVersion {
		var err error
		progress, err = r.replaySupplementInventory(ctx, resource, before, after, maxBytes, changed, disputed)
		if err != nil {
			return kubernetesSupplementWindow{}, err
		}
	}
	out := kubernetesSupplementWindow{window: &agentv1.KubernetesInventoryWindow{Kind: resource.wireKind,
		FirstListVersion: before.ResourceVersion, LastListVersion: after.ResourceVersion, WatchProgressVersion: progress,
		FirstReadCompleteUnixNano: before.ReadCompletedAt.UnixNano(), LastReadStartUnixNano: after.ReadStartedAt.UnixNano()}, disputedAddresses: disputed}
	for id, object := range after.objects {
		prior, existed := before.objects[id]
		if existed && object.Name == prior.Name && object.ResourceVersion == prior.ResourceVersion && !changed[id] {
			out.objects = append(out.objects, object)
		}
	}
	slices.SortFunc(out.objects, func(left, right kubernetesSupplementObject) int { return strings.Compare(left.UID, right.UID) })
	return out, nil
}

func markDuplicateKubernetesServiceAddresses(objects map[string]kubernetesSupplementObject, disputed map[netip.Addr]bool) {
	seen := make(map[netip.Addr]bool)
	for _, object := range objects {
		for _, address := range object.Service.Addresses {
			if seen[address] {
				disputed[address] = true
			}
			seen[address] = true
		}
	}
}

func (r *kubernetesPodReader) replaySupplementInventory(ctx context.Context, resource kubernetesSupplementResource,
	before, after kubernetesSupplementSnapshot, maxBytes int64, changed map[string]bool, disputed map[netip.Addr]bool) (string, error) {
	reader := r.scopedResource(resource.kubernetesResource)
	var progress string
	lastVersion := before.ResourceVersion
	mark := func(object kubernetesSupplementObject) {
		if object.Service != nil {
			for _, address := range object.Service.Addresses {
				disputed[address] = true
			}
		}
	}
	observe := func(kind string, raw []byte) error {
		var header kubernetesPodObject
		if err := json.Unmarshal(raw, &header); err != nil || header.APIVersion != resource.apiVersion || header.Kind != resource.kind ||
			!entity.ValidKubernetesResourceVersion(header.Metadata.ResourceVersion) {
			return errKubernetesPodWatch
		}
		if order, known := entity.CompareKubernetesResourceVersions(header.Metadata.ResourceVersion, lastVersion); known && order < 0 {
			return errKubernetesPodWatch
		}
		lastVersion = header.Metadata.ResourceVersion
		if kind == "BOOKMARK" {
			if header.Metadata.Namespace != "" && header.Metadata.Namespace != r.namespace {
				return errKubernetesPodWatch
			}
		} else {
			if kind != "ADDED" && kind != "MODIFIED" && kind != "DELETED" {
				return errKubernetesPodWatch
			}
			if header.Metadata.Namespace != r.namespace {
				return errKubernetesPodWatch
			}
		}
		if kubernetesWatchCoversVersion(kubernetesPodChange{Type: kind, ResourceVersion: lastVersion}, after.ResourceVersion) {
			progress = lastVersion
			return errKubernetesWatchCovered
		}
		if kind != "BOOKMARK" {
			object, err := readKubernetesSupplementObject(raw, r.namespace, resource, true)
			if err != nil {
				return err
			}
			changed[object.UID] = true
			mark(before.objects[object.UID])
			mark(object)
		}
		return nil
	}
	err := tryKubernetesWatch(ctx, func(lease time.Duration) error {
		// Retry the original revision. Changes seen in either attempt can
		// only invalidate a candidate, so retain those omissions.
		lastVersion = before.ResourceVersion
		return reader.watchInventory(ctx, before.ResourceVersion, lease, maxBytes, observe)
	})
	if !errors.Is(err, errKubernetesWatchCovered) {
		return "", errKubernetesCoverageGap
	}
	return progress, nil
}
