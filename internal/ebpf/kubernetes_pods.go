// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode"
)

var errKubernetesPodList = errors.New("kubernetes: incomplete or invalid Pod list")

type kubernetesOwnerReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller bool   `json:"controller"`
}

type kubernetesPodMetadata struct {
	UID             string
	Name            string
	ResourceVersion string
	Node            string
	HostNetwork     bool
	Terminating     bool
	Addresses       []netip.Addr
	Owner           *kubernetesOwnerReference
}

type kubernetesPodObject struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		UID               string                     `json:"uid"`
		ResourceVersion   string                     `json:"resourceVersion"`
		Namespace         string                     `json:"namespace"`
		Name              string                     `json:"name"`
		DeletionTimestamp *time.Time                 `json:"deletionTimestamp"`
		Owners            []kubernetesOwnerReference `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		Node        string `json:"nodeName"`
		HostNetwork bool   `json:"hostNetwork"`
	} `json:"spec"`
	Status struct {
		PrimaryIP string `json:"podIP"`
		IPs       []struct {
			IP string `json:"ip"`
		} `json:"podIPs"`
		Phase string `json:"phase"`
	} `json:"status"`
}

func (object kubernetesPodObject) observation(namespace string) (kubernetesPodMetadata, error) {
	meta := object.Metadata
	if meta.Namespace != namespace || !validKubernetesMetadataString(meta.UID) || !validKubernetesMetadataString(meta.Name) ||
		object.Spec.Node != "" && !validKubernetesMetadataString(object.Spec.Node) {
		return kubernetesPodMetadata{}, errKubernetesPodList
	}
	pod := kubernetesPodMetadata{UID: meta.UID, Name: meta.Name, ResourceVersion: meta.ResourceVersion, Node: object.Spec.Node, HostNetwork: object.Spec.HostNetwork,
		Terminating: meta.DeletionTimestamp != nil}
	for _, owner := range meta.Owners {
		if !owner.Controller {
			continue
		}
		if pod.Owner != nil || !validKubernetesMetadataString(owner.APIVersion) || !validKubernetesMetadataString(owner.Kind) ||
			!validKubernetesMetadataString(owner.Name) || !validKubernetesMetadataString(owner.UID) || owner.UID == meta.UID {
			return kubernetesPodMetadata{}, errKubernetesPodList
		}
		pod.Owner = &owner
	}
	addresses, err := object.podAddresses()
	if err != nil {
		return kubernetesPodMetadata{}, err
	}
	// An inactive or unknown object can retain a historical status IP.
	// Publish assignments only for active or allocating objects.
	if object.Status.Phase == "Running" || object.Status.Phase == "Pending" {
		pod.Addresses = addresses
	}
	return pod, nil
}

func (object kubernetesPodObject) podAddresses() ([]netip.Addr, error) {
	if len(object.Status.IPs) > 2 {
		return nil, errKubernetesPodList
	}
	var values [2]string
	for index, address := range object.Status.IPs {
		values[index] = address.IP
	}
	addresses, ok := parseKubernetesDualStack(object.Status.PrimaryIP, values[:len(object.Status.IPs)])
	if !ok {
		return nil, errKubernetesPodList
	}
	return addresses, nil
}

func parseKubernetesDualStack(primary string, addresses []string) ([]netip.Addr, bool) {
	if primary == "" && len(addresses) == 0 {
		return nil, true
	}
	first, ok := parseKubernetesAddress(primary)
	if !ok || len(addresses) > 2 {
		return nil, false
	}
	if len(addresses) == 0 {
		return []netip.Addr{first}, true
	}
	result := make([]netip.Addr, 0, len(addresses))
	for index, value := range addresses {
		address, ok := parseKubernetesAddress(value)
		if !ok || index == 0 && address != first || index != 0 && address.Is4() == first.Is4() {
			return nil, false
		}
		result = append(result, address)
	}
	return result, true
}

func parseKubernetesAddress(input string) (netip.Addr, bool) {
	address, err := netip.ParseAddr(input)
	address = address.Unmap()
	return address, err == nil && address.Zone() == "" && address.IsGlobalUnicast()
}

func validKubernetesMetadataString(s string) bool {
	return s != "" && strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) < 0
}
