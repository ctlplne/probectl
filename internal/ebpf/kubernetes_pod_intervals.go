// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
)

type kubernetesPodReplay struct {
	Namespace string
	// StartVersion is the exact starting point of the contiguous watch.
	StartVersion string
	Changes      []kubernetesPodChange
}

type kubernetesPodAddressClaim struct {
	UID   string
	Name  string
	Node  string
	Owner kubernetesOwnerReference
}

type kubernetesPodAddressInterval struct {
	Namespace   string
	Address     netip.Addr
	From, Until time.Time
	Claim       kubernetesPodAddressClaim
}

// stableKubernetesPodAddresses works on two complete most-recent lists from
// one authorized namespace. The replay belongs to that same authenticated
// cluster and namespace. Its exact start and continuity are held by the
// reader. Version ordering is only used for resources served by kube-apiserver.
func stableKubernetesPodAddresses(before, after kubernetesPodSnapshot,
	replay kubernetesPodReplay) ([]kubernetesPodAddressInterval, bool) {
	if before.Namespace == "" || before.Namespace != after.Namespace || before.ReadStartedAt.IsZero() ||
		before.ReadCompletedAt.Before(before.ReadStartedAt) || after.ReadCompletedAt.Before(after.ReadStartedAt) ||
		!after.ReadStartedAt.After(before.ReadCompletedAt) || before.Pods == nil || after.Pods == nil ||
		!entity.ValidKubernetesResourceVersion(before.ResourceVersion) || !entity.ValidKubernetesResourceVersion(after.ResourceVersion) {
		return nil, false
	}
	first, last := kubernetesPodClaimIndex(before.Pods), kubernetesPodClaimIndex(after.Pods)
	var changed map[netip.Addr]bool
	if before.ResourceVersion == after.ResourceVersion {
		if !maps.Equal(first, last) {
			return nil, false
		}
	} else {
		var covered bool
		changed, covered = replay.changedAddresses(before, after.ResourceVersion)
		if !covered {
			return nil, false
		}
	}
	result := make([]kubernetesPodAddressInterval, 0, len(first))
	for address, claim := range first {
		// A zero claim marks multiple owners in the same complete list.
		if claim.UID != "" && last[address] == claim && !changed[address] {
			result = append(result, kubernetesPodAddressInterval{Namespace: before.Namespace, Address: address,
				From: before.ReadCompletedAt, Until: after.ReadStartedAt, Claim: claim})
		}
	}
	slices.SortFunc(result, func(a, b kubernetesPodAddressInterval) int { return a.Address.Compare(b.Address) })
	return result, true
}

func (replay kubernetesPodReplay) changedAddresses(before kubernetesPodSnapshot, targetVersion string) (map[netip.Addr]bool, bool) {
	if replay.Namespace != before.Namespace || replay.StartVersion != before.ResourceVersion {
		return nil, false
	}
	if order, known := entity.CompareKubernetesResourceVersions(replay.StartVersion, targetVersion); known && order >= 0 {
		return nil, false
	}
	pods := make(map[string]kubernetesPodMetadata, len(before.Pods))
	for _, pod := range before.Pods {
		pods[pod.UID] = pod
	}
	changed := make(map[netip.Addr]bool)
	last := replay.StartVersion
	for _, change := range replay.Changes {
		if !entity.ValidKubernetesResourceVersion(change.ResourceVersion) {
			return nil, false
		}
		if order, known := entity.CompareKubernetesResourceVersions(change.ResourceVersion, last); known && order < 0 {
			return nil, false
		}
		last = change.ResourceVersion
		// An object at the target may be one of several updates at that
		// storage revision. A bookmark covers the whole target revision.
		if kubernetesWatchCoversVersion(change, targetVersion) {
			return changed, true
		}
		if !applyKubernetesPodChange(change, pods, changed) {
			return nil, false
		}
	}
	return nil, false
}

func kubernetesWatchCoversVersion(change kubernetesPodChange, targetVersion string) bool {
	order, known := entity.CompareKubernetesResourceVersions(change.ResourceVersion, targetVersion)
	return known && (order > 0 || order == 0 && change.Type == "BOOKMARK")
}

func applyKubernetesPodChange(change kubernetesPodChange, pods map[string]kubernetesPodMetadata, touched map[netip.Addr]bool) bool {
	if change.Type == "BOOKMARK" {
		return true
	}
	pod := change.Pod
	previous, exists := pods[pod.UID]
	if pod.UID == "" || (change.Type == "ADDED") == exists {
		return false
	}
	var next kubernetesPodMetadata
	switch change.Type {
	case "ADDED", "MODIFIED":
		next = pod
		pods[pod.UID] = pod
	case "DELETED":
		delete(pods, pod.UID)
	default:
		return false
	}
	// Preserve unchanged addresses even if other Pod fields or its other
	// address family changed. Include both sides of an ownership transition.
	markKubernetesAddressChanges(previous, next, touched)
	markKubernetesAddressChanges(next, previous, touched)
	return true
}

func markKubernetesAddressChanges(pod, other kubernetesPodMetadata, touched map[netip.Addr]bool) {
	if pod.HostNetwork {
		return
	}
	claimChanged := other.HostNetwork || kubernetesAddressClaim(pod) != kubernetesAddressClaim(other)
	for _, address := range pod.Addresses {
		if claimChanged || !slices.Contains(other.Addresses, address) {
			touched[address] = true
		}
	}
}

func kubernetesPodClaimIndex(pods []kubernetesPodMetadata) map[netip.Addr]kubernetesPodAddressClaim {
	claims := make(map[netip.Addr]kubernetesPodAddressClaim)
	for _, pod := range pods {
		if pod.HostNetwork {
			continue
		}
		claim := kubernetesAddressClaim(pod)
		for _, address := range pod.Addresses {
			if _, exists := claims[address]; exists {
				claims[address] = kubernetesPodAddressClaim{}
			} else {
				claims[address] = claim
			}
		}
	}
	return claims
}

func kubernetesAddressClaim(pod kubernetesPodMetadata) kubernetesPodAddressClaim {
	claim := kubernetesPodAddressClaim{UID: pod.UID, Name: pod.Name, Node: pod.Node}
	if pod.Owner != nil {
		claim.Owner = *pod.Owner
	}
	return claim
}
