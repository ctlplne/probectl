// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"net/netip"
	"regexp"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

const (
	kubernetesPod        = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_POD
	kubernetesService    = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_SERVICE
	kubernetesSlice      = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_ENDPOINT_SLICE
	kubernetesController = agentv1.KubernetesInventoryRelationshipKind_KUBERNETES_INVENTORY_RELATIONSHIP_KIND_CONTROLLER_OWNER
	kubernetesBackend    = agentv1.KubernetesInventoryRelationshipKind_KUBERNETES_INVENTORY_RELATIONSHIP_KIND_SERVICE_BACKEND
)

var (
	kubernetesObjectName = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)
	kubernetesObjectUID  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,255}$`)
)

func knownKubernetesInventoryKind(kind agentv1.KubernetesInventoryKind) bool {
	return kind >= kubernetesPod && kind <= agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_REPLICATION_CONTROLLER
}

func completeKubernetesMessage(message proto.Message) bool {
	if message == nil {
		return false
	}
	reflected := message.ProtoReflect()
	return reflected.IsValid() && len(reflected.GetUnknown()) == 0
}

type kubernetesInventoryWindow struct {
	Kind        agentv1.KubernetesInventoryKind
	From, Until time.Time
}

func inventoryWindow(raw *agentv1.KubernetesInventoryWindow, scope kubernetesUploadScope) (kubernetesInventoryWindow, error) {
	if !completeKubernetesMessage(raw) || !knownKubernetesInventoryKind(raw.Kind) || raw.FirstReadCompleteUnixNano <= 0 ||
		raw.LastReadStartUnixNano <= raw.FirstReadCompleteUnixNano || !validKubernetesInventoryVersions(raw) {
		return kubernetesInventoryWindow{}, ErrKubernetesInventoryInput
	}
	from := time.Unix(0, raw.FirstReadCompleteUnixNano).UTC()
	until := time.Unix(0, raw.LastReadStartUnixNano).UTC()
	if from.Before(scope.From) || until.After(scope.Until) || until.After(scope.CheckedAt) {
		return kubernetesInventoryWindow{}, ErrKubernetesInventoryAuthority
	}
	// PostgreSQL stores microseconds. Round inward before encoding so the
	// retained interval never extends beyond the original observations.
	if floor := from.Truncate(time.Microsecond); !floor.Equal(from) {
		from = floor.Add(time.Microsecond)
	}
	until = until.Truncate(time.Microsecond)
	if !until.After(from) {
		return kubernetesInventoryWindow{}, ErrKubernetesInventoryInput
	}
	return kubernetesInventoryWindow{Kind: raw.Kind, From: from, Until: until}, nil
}

func validKubernetesInventoryVersions(raw *agentv1.KubernetesInventoryWindow) bool {
	first, last := raw.FirstListVersion, raw.LastListVersion
	if !entity.ValidKubernetesResourceVersion(first) || !entity.ValidKubernetesResourceVersion(last) {
		return false
	}
	if first == last && raw.WatchProgressVersion == "" {
		return true
	}
	if order, known := entity.CompareKubernetesResourceVersions(first, last); known && order > 0 {
		return false
	}
	if !entity.ValidKubernetesResourceVersion(raw.WatchProgressVersion) {
		return false
	}
	order, known := entity.CompareKubernetesResourceVersions(raw.WatchProgressVersion, last)
	return known && order >= 0
}

func validKubernetesInventoryRow(raw *agentv1.KubernetesInventoryRow) bool {
	if !completeKubernetesMessage(raw) {
		return false
	}
	switch record := raw.Record.(type) {
	case *agentv1.KubernetesInventoryRow_Object:
		object := record.Object
		return completeKubernetesMessage(object) && knownKubernetesInventoryKind(object.Kind) &&
			(!object.ControllerUnowned || object.Kind > kubernetesSlice) &&
			kubernetesObjectUID.MatchString(object.Uid) && len(object.Name) <= 253 && kubernetesObjectName.MatchString(object.Name)
	case *agentv1.KubernetesInventoryRow_Address:
		address := record.Address
		if !completeKubernetesMessage(address) || address.Kind != kubernetesPod && address.Kind != kubernetesService ||
			!kubernetesObjectUID.MatchString(address.Uid) {
			return false
		}
		value, err := netip.ParseAddr(address.Address)
		return err == nil && value.Zone() == "" && value.Unmap().String() == address.Address && value.IsGlobalUnicast()
	case *agentv1.KubernetesInventoryRow_Relationship:
		return validKubernetesInventoryRelationship(record.Relationship)
	default:
		return false
	}
}

func validKubernetesInventoryRelationship(edge *agentv1.KubernetesInventoryRelationship) bool {
	if !completeKubernetesMessage(edge) || !knownKubernetesInventoryKind(edge.FromKind) || !knownKubernetesInventoryKind(edge.ToKind) ||
		!kubernetesObjectUID.MatchString(edge.FromUid) || !kubernetesObjectUID.MatchString(edge.ToUid) || edge.FromUid == edge.ToUid {
		return false
	}
	switch edge.Relation {
	case kubernetesController:
		return edge.EndpointSliceUid == "" && edge.FromKind != kubernetesService && edge.FromKind != kubernetesSlice &&
			edge.ToKind > kubernetesSlice
	case kubernetesBackend:
		return edge.FromKind == kubernetesService && edge.ToKind == kubernetesPod && kubernetesObjectUID.MatchString(edge.EndpointSliceUid)
	default:
		return false
	}
}
