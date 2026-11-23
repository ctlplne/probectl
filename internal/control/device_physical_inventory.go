// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"

	gouuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	physicalInventoryPageSize        = 16
	physicalInventoryReferenceMaxAge = 30 * 24 * time.Hour
)

type devicePhysicalInventorySelection struct {
	contextID     string
	deviceID      string
	source        entity.SourceKey
	observationID string
	afterIndex    uint32
}

type devicePhysicalInventoryItem struct {
	entity.SNMPPhysicalComponent
	References device.DeviceInventoryReferenceFlags `json:"references"`
}

type devicePhysicalInventoryPage struct {
	ObservationID string                        `json:"observation_id"`
	ObservedAt    time.Time                     `json:"observed_at"`
	Available     bool                          `json:"available"`
	Methodology   string                        `json:"methodology"`
	Items         []devicePhysicalInventoryItem `json:"items"`
	NextIndex     uint32                        `json:"next_index,omitempty"`
}

func parseDevicePhysicalInventorySelection(query url.Values) (devicePhysicalInventorySelection, error) {
	selected := devicePhysicalInventorySelection{
		contextID: query.Get("context_id"), deviceID: query.Get("device_entity_id"),
		observationID: query.Get("observation_id"),
	}
	for _, value := range []string{selected.contextID, selected.deviceID} {
		if id, err := gouuid.Parse(value); err != nil || id == gouuid.Nil || id.String() != value {
			return selected, apierror.Validation("canonical context_id and device_entity_id are required")
		}
	}
	source := entity.SourceKey{AgentID: query.Get("agent_id"), Kind: entity.DeviceTarget, SourceRef: query.Get("source_ref")}
	normalized, err := source.Normalize()
	if err != nil || normalized != source {
		return selected, apierror.Validation("canonical agent_id and source_ref are required")
	}
	selected.source = normalized
	if after := query.Get("after_index"); after != "" || selected.observationID != "" {
		index, parseErr := strconv.ParseUint(after, 10, 31)
		id, idErr := gouuid.Parse(selected.observationID)
		if parseErr != nil || index == 0 || index > math.MaxInt32 || idErr != nil || id == gouuid.Nil || id.String() != selected.observationID {
			return selected, apierror.Validation("pagination requires after_index and its original observation_id")
		}
		selected.afterIndex = uint32(index)
	}
	return selected, nil
}

func (s *Server) handleDevicePhysicalInventory(w http.ResponseWriter, r *http.Request) error {
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.TenantID == "" || actor.UserID == "" {
		return apierror.Forbidden("a current tenant user is required for physical inventory")
	}
	selected, err := parseDevicePhysicalInventorySelection(r.URL.Query())
	if err != nil {
		return err
	}
	page, err := s.readDevicePhysicalInventory(r.Context(), actor, selected)
	if err != nil {
		return err
	}
	credential := s.resolvePrincipal(r)
	if credential == nil {
		return unauthenticated(r)
	}
	if !auth.SamePrincipalAuthority(actor, credential) {
		return apierror.Forbidden("physical inventory credential authority changed")
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, page)
	return nil
}

func (s *Server) readDevicePhysicalInventory(ctx context.Context, actor *auth.Principal,
	selected devicePhysicalInventorySelection) (devicePhysicalInventoryPage, error) {
	var page devicePhysicalInventoryPage
	if s.pool == nil {
		return page, apierror.Unavailable("physical inventory is temporarily unavailable")
	}
	ctx, err := bindCanonicalDeviceTenant(ctx, actor)
	if err != nil {
		return page, apierror.Forbidden("physical inventory tenant scope mismatch")
	}
	registry := store.NewEntityRegistry(s.pool)
	scope := entity.Scope{TenantID: actor.TenantID, ContextID: selected.contextID}
	var evidence store.DevicePhysicalInventoryEvidence
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := s.authorizeCanonicalDeviceSourceInScope(ctx, sc, actor, scope.ContextID, selected.deviceID, selected.source, ai.PermMetricsRead); err != nil {
			return err
		}
		var readErr error
		evidence, readErr = registry.CurrentDevicePhysicalInventoryInScope(ctx, sc, scope, selected.deviceID, selected.source)
		return readErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return page, apierror.NotFound("no current physical inventory for this device source")
	}
	if err != nil {
		return page, entityAPIError(err)
	}
	if selected.observationID != "" && evidence.EvidenceID != selected.observationID {
		return page, apierror.Conflict("physical inventory changed, reload its first page")
	}
	page = devicePhysicalInventoryPage{ObservationID: evidence.EvidenceID, ObservedAt: evidence.ObservedAt,
		Available: evidence.Snapshot.Available, Methodology: entity.SNMPPhysicalInventorySource,
		Items: make([]devicePhysicalInventoryItem, 0, physicalInventoryPageSize)}
	now := time.Now().UTC()
	for _, row := range evidence.Snapshot.Components {
		if row.Index <= selected.afterIndex {
			continue
		}
		if len(page.Items) == physicalInventoryPageSize {
			page.NextIndex = page.Items[len(page.Items)-1].Index
			break
		}
		if err := ctx.Err(); err != nil {
			return devicePhysicalInventoryPage{}, err
		}
		page.Items = append(page.Items, devicePhysicalInventoryItem{
			SNMPPhysicalComponent: row,
			References:            s.deviceInventoryReferences.Lookup(row, now, physicalInventoryReferenceMaxAge),
		})
	}
	return page, ctx.Err()
}
