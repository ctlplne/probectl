// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"errors"
	"net/netip"
	"slices"
)

var errKubernetesServiceInventory = errors.New("kubernetes: invalid Service inventory object")

type kubernetesServiceMetadata struct {
	UID, Namespace, Name string
	Addresses            []netip.Addr
}

type kubernetesServiceObject struct {
	Metadata struct {
		UID       string `json:"uid"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		Type       string   `json:"type"`
		ClusterIP  string   `json:"clusterIP"`
		ClusterIPs []string `json:"clusterIPs"`
	} `json:"spec"`
}

func (object kubernetesServiceObject) observation(namespace string) (kubernetesServiceMetadata, error) {
	meta := object.Metadata
	if namespace == "" || meta.Namespace != namespace || !validKubernetesMetadataString(meta.UID) ||
		!validKubernetesMetadataString(meta.Name) {
		return kubernetesServiceMetadata{}, errKubernetesServiceInventory
	}
	service := kubernetesServiceMetadata{UID: meta.UID, Namespace: namespace, Name: meta.Name}
	primary, addresses := object.Spec.ClusterIP, object.Spec.ClusterIPs
	if object.Spec.Type == "ExternalName" || primary == "" {
		if primary != "" || len(addresses) != 0 {
			return kubernetesServiceMetadata{}, errKubernetesServiceInventory
		}
		return service, nil
	}
	if primary == "None" {
		if len(addresses) > 1 || len(addresses) == 1 && addresses[0] != primary {
			return kubernetesServiceMetadata{}, errKubernetesServiceInventory
		}
		return service, nil
	}
	var ok bool
	service.Addresses, ok = parseKubernetesDualStack(primary, addresses)
	if !ok {
		return kubernetesServiceMetadata{}, errKubernetesServiceInventory
	}
	return service, nil
}

type kubernetesEndpointSliceObject struct {
	Metadata struct {
		UID       string                     `json:"uid"`
		Namespace string                     `json:"namespace"`
		Labels    map[string]string          `json:"labels"`
		Owners    []kubernetesOwnerReference `json:"ownerReferences"`
	} `json:"metadata"`
	AddressType string `json:"addressType"`
	Endpoints   []struct {
		Addresses []string `json:"addresses"`
		TargetRef struct {
			Kind       string `json:"kind"`
			APIVersion string `json:"apiVersion"`
			UID        string `json:"uid"`
			Namespace  string `json:"namespace"`
			Name       string `json:"name"`
		} `json:"targetRef"`
	} `json:"endpoints"`
}

type kubernetesServiceBackend struct {
	ServiceUID string
	SliceUID   string
	PodUID     string
	Address    netip.Addr
}

// serviceBackends joins scoped originals at the same established time. A
// Service name label is a lookup hint. The owner reference is checked against
// the current Service UID and the endpoint address against its target Pod.
func (slice kubernetesEndpointSliceObject) serviceBackends(service kubernetesServiceMetadata,
	pods map[string]kubernetesPodMetadata) []kubernetesServiceBackend {
	meta := slice.Metadata
	if service.Namespace == "" || service.Namespace != meta.Namespace || service.Name != meta.Labels["kubernetes.io/service-name"] ||
		service.UID == "" || !validKubernetesMetadataString(meta.UID) ||
		slice.AddressType != "IPv4" && slice.AddressType != "IPv6" {
		return nil
	}
	var ownerCount int
	for _, owner := range meta.Owners {
		if owner.APIVersion != "v1" || owner.Kind != "Service" {
			continue
		}
		if owner.Name != service.Name || owner.UID != service.UID {
			return nil
		}
		ownerCount++
	}
	if ownerCount != 1 {
		return nil
	}
	var backends []kubernetesServiceBackend
	seen := make(map[kubernetesServiceBackend]bool)
	for _, entry := range slice.Endpoints {
		target := entry.TargetRef
		pod, exists := pods[target.UID]
		if target.Kind != "Pod" || target.APIVersion != "v1" && target.APIVersion != "" || target.Namespace != service.Namespace ||
			!exists || pod.UID != target.UID || pod.Name != target.Name || len(entry.Addresses) == 0 {
			continue
		}
		// Kubernetes gives forwarding semantics only to the first address.
		address, err := netip.ParseAddr(entry.Addresses[0])
		if err != nil || address.Zone() != "" || address.Is4In6() || address.Is4() != (slice.AddressType == "IPv4") ||
			!slices.Contains(pod.Addresses, address) {
			continue
		}
		backend := kubernetesServiceBackend{ServiceUID: service.UID, SliceUID: meta.UID, PodUID: pod.UID, Address: address}
		if !seen[backend] {
			backends = append(backends, backend)
			seen[backend] = true
		}
	}
	return backends
}
