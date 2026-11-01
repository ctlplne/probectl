// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"io"
	"math"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type libreNMSCaptureList struct {
	resource string
	raw      io.Reader
	stream   func(io.Reader, func(Snapshot) error) error
}

// LibreNMSMembershipList is one complete response for a group ID taken from
// the operator-selected source's group inventory. The caller, not the source
// body, chooses this ID; capture rejects missing, duplicate and foreign IDs.
type LibreNMSMembershipList struct {
	GroupID string
	Raw     io.Reader
}

// CaptureLibreNMSDevices consumes the documented unpaged device-list response
// into bounded tenant transactions, then seals only a complete, valid response.
// This device-only seam is useful for a focused capture proof. A full inventory
// also needs its locations, groups and rules before review can publish a plan.
func (s CaptureStore) CaptureLibreNMSDevices(ctx context.Context,
	contextID, planID string, raw io.Reader) (string, error) {
	return s.captureLibreNMSLists(ctx, contextID, planID,
		nil,
		libreNMSCaptureList{"devices", raw, streamLibreNMSDevices})
}

// CaptureLibreNMSDevicesAndLocations captures both unpaged lists in one
// tenant/source-bound plan. A missing or invalid second response leaves all
// committed pages inert; only a complete two-list snapshot can seal. Sites
// remain unassigned candidates and cannot select a routing context.
func (s CaptureStore) CaptureLibreNMSDevicesAndLocations(ctx context.Context,
	contextID, planID string, devices, locations io.Reader) (string, error) {
	return s.captureLibreNMSLists(ctx, contextID, planID,
		nil,
		libreNMSCaptureList{"devices", devices, streamLibreNMSDevices},
		libreNMSCaptureList{"locations", locations, streamLibreNMSLocations})
}

// CaptureLibreNMSInventory captures each supported inventory plane and every
// group's separate device membership list before sealing. This list is a
// manifest from the trusted source client, not a way for vendor JSON to name
// a tenant, context, credential, group or destination. Missing membership
// responses leave the partial plan inert and fail closed.
func (s CaptureStore) CaptureLibreNMSInventory(ctx context.Context, contextID, planID string,
	devices, locations, groups, rules io.Reader, memberships []LibreNMSMembershipList) (string, error) {
	groupIDs := make(map[string]bool)
	lists := []libreNMSCaptureList{
		{"devices", devices, streamLibreNMSDevices},
		{"locations", locations, streamLibreNMSLocations},
		{"groups", groups, func(raw io.Reader, emit func(Snapshot) error) error {
			return streamLibreNMSGroups(raw, func(snapshot Snapshot) error {
				for i, row := range snapshot.Rows {
					if _, duplicate := groupIDs[row.ExternalID]; duplicate {
						return ErrInvalidPage
					}
					groupIDs[row.ExternalID] = false
					for j, code := range snapshot.Rows[i].UnmappedCodes {
						if code == "membership_not_captured" {
							snapshot.Rows[i].UnmappedCodes[j] = "group_unmapped"
						}
					}
				}
				return emit(snapshot)
			})
		}},
		{"rules", rules, streamLibreNMSRules},
	}
	for _, member := range memberships {
		member := member
		lists = append(lists, libreNMSCaptureList{"memberships", member.Raw,
			func(raw io.Reader, emit func(Snapshot) error) error {
				seen, known := groupIDs[member.GroupID]
				if !known || seen {
					return ErrInvalidPage
				}
				if err := streamLibreNMSGroupMembers(raw, member.GroupID, emit); err != nil {
					return err
				}
				groupIDs[member.GroupID] = true
				return nil
			}})
	}
	complete := func() error {
		if len(groupIDs) != len(memberships) {
			return ErrInvalidPage
		}
		for _, seen := range groupIDs {
			if !seen {
				return ErrInvalidPage
			}
		}
		return nil
	}
	return s.captureLibreNMSLists(ctx, contextID, planID, complete, lists...)
}

// The plan must have been started by an authorized caller for this LibreNMS
// instance and routing context. Neither source JSON nor a reader may choose a
// tenant, context, credential or destination. A retry replays every previous
// chunk and rejects any changed prefix before appending new rows.
func (s CaptureStore) captureLibreNMSLists(ctx context.Context,
	contextID, planID string, complete func() error, lists ...libreNMSCaptureList) (string, error) {
	if s.pool == nil || s.audit == nil {
		return "", ErrCaptureAuditUnavailable
	}
	contextUUID, err := uuid.Parse(contextID)
	if err != nil || contextUUID == uuid.Nil {
		return "", ErrPlanUnavailable
	}
	planUUID, err := uuid.Parse(planID)
	if err != nil || planUUID == uuid.Nil || len(lists) == 0 {
		return "", ErrInvalidPage
	}
	for _, list := range lists {
		if list.raw == nil || list.stream == nil || !knownResource(LibreNMS, list.resource) {
			return "", ErrInvalidPage
		}
	}
	contextID, planID = contextUUID.String(), planUUID.String()
	// Resolve the caller's tenant and plan before consuming an untrusted
	// source stream. Each emitted chunk rechecks the plan under FORCE RLS so
	// a concurrent seal or expiry still stops subsequent writes.
	var initial captureMeta
	if err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var readErr error
		initial, readErr = loadCaptureMeta(ctx, sc, contextID, planID, false)
		return readErr
	}); err != nil {
		return "", err
	}
	if initial.source != LibreNMS || initial.state != "capturing" {
		return "", ErrPlanUnavailable
	}
	var pageNumber, firstRow int64
	for _, list := range lists {
		err = list.stream(list.raw, func(snapshot Snapshot) error {
			if pageNumber == math.MaxInt64 || firstRow > math.MaxInt64-int64(len(snapshot.Rows)) {
				return ErrInvalidPage
			}
			var tenantID string
			var meta captureMeta
			if err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
				tenantID = sc.Tenant.String()
				var readErr error
				meta, readErr = loadCaptureMeta(ctx, sc, contextID, planID, false)
				return readErr
			}); err != nil {
				return err
			}
			tenantUUID, err := uuid.Parse(tenantID)
			if err != nil || tenantUUID == uuid.Nil || meta.source != LibreNMS || meta.state != "capturing" {
				return ErrPlanUnavailable
			}
			if _, err := s.appendSnapshot(ctx, contextID, planID, pageNumber,
				list.resource, firstRow, tenantUUID.String(), meta, snapshot); err != nil {
				return err
			}
			pageNumber++
			firstRow += int64(len(snapshot.Rows))
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	if complete != nil {
		if err := complete(); err != nil {
			return "", err
		}
	}
	return s.Seal(ctx, contextID, planID, pageNumber, firstRow)
}
