// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"encoding/hex"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// DiscoveryDevice is the field set a deployment-configured discovery source
// can contribute. Tenant, context, target and review choices come from local
// authority. Sources may not contribute arbitrary vendor properties.
type DiscoveryDevice struct {
	ExternalID string
	Hostname   string
	Address    string
}

type DiscoveryPlan struct {
	PlanID       string `json:"plan_id"`
	ContextID    string `json:"context_id"`
	SnapshotHash string `json:"snapshot_hash"`
	RowCount     int    `json:"row_count"`
}

// PublishDiscovery atomically records a complete candidate inventory. The
// caller must authorize the selected context and finish source I/O first.
// The sealed plan has no review choices and changes no entity or poll target.
func (s CaptureStore) PublishDiscovery(ctx context.Context, contextID, instanceRef string,
	devices []DiscoveryDevice) (DiscoveryPlan, error) {
	if s.pool == nil || s.audit == nil {
		return DiscoveryPlan{}, ErrCaptureAuditUnavailable
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return DiscoveryPlan{}, tenancy.ErrNoTenant
	}
	tenantUUID, err := uuid.Parse(tenant.String())
	if err != nil || tenantUUID == uuid.Nil {
		return DiscoveryPlan{}, ErrPlanUnavailable
	}
	contextUUID, err := uuid.Parse(contextID)
	if err != nil || contextUUID == uuid.Nil || !safeInstanceRef(instanceRef) || len(devices) > maxCaptureRowsPerPage {
		return DiscoveryPlan{}, ErrInvalidPage
	}
	tenantID, contextID := tenantUUID.String(), contextUUID.String()
	nonce, err := crypto.Random(32)
	if err != nil {
		return DiscoveryPlan{}, err
	}
	gen := hex.EncodeToString(nonce)
	snapshot, err := discoverySnapshot(devices)
	if err != nil {
		return DiscoveryPlan{}, err
	}
	rows, err := normalizePlanPage(tenantID, contextID, instanceRef, gen, DeviceDiscovery, snapshot, 0)
	if err != nil {
		return DiscoveryPlan{}, err
	}
	pageHash, err := normalizedPageHash(tenantID, contextID, instanceRef, gen,
		DeviceDiscovery, capturePolicyVersion, "devices", 0, 0, rows)
	if err != nil {
		return DiscoveryPlan{}, err
	}
	digest, err := newPlanDigest(tenantID, contextID, instanceRef, gen, DeviceDiscovery, capturePolicyVersion)
	if err != nil {
		return DiscoveryPlan{}, err
	}
	if err := digest.appendPage(rows); err != nil {
		return DiscoveryPlan{}, err
	}
	sealedHash, err := digest.hexSum()
	if err != nil {
		return DiscoveryPlan{}, err
	}
	planID, err := captureUUID()
	if err != nil {
		return DiscoveryPlan{}, err
	}
	sourceID, err := captureUUID()
	if err != nil {
		return DiscoveryPlan{}, err
	}
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, scope tenancy.Scope) error {
		if err := s.insertCapturePlan(ctx, scope, contextID, planID, sourceID, DeviceDiscovery, instanceRef, gen, false); err != nil {
			return err
		}
		if err := s.insertCapturePage(ctx, scope, tenantID, contextID, planID, 0, 0, "devices", pageHash, rows); err != nil {
			return err
		}
		return s.sealCapturePlan(ctx, scope, tenantID, contextID, planID, sealedHash, 1, int64(len(rows)))
	})
	if err != nil {
		return DiscoveryPlan{}, err
	}
	return DiscoveryPlan{PlanID: planID, ContextID: contextID, SnapshotHash: sealedHash, RowCount: len(rows)}, nil
}

func discoverySnapshot(devices []DiscoveryDevice) (Snapshot, error) {
	snapshot := Snapshot{Source: DeviceDiscovery}
	for _, device := range devices {
		if device.ExternalID == "" || safeLabel(device.ExternalID) != device.ExternalID {
			return Snapshot{}, ErrInvalidPage
		}
		row := Row{Kind: "device", ExternalID: device.ExternalID,
			Hostname: safeDNSHost(device.Hostname), Address: safeAddress(device.Address)}
		if row.Hostname == "" && row.Address == "" {
			row.UnmappedCodes = []string{"host_unmapped"}
		}
		row.Label = row.Hostname
		if row.Label == "" {
			row.Label = row.Address
		}
		snapshot.Rows = append(snapshot.Rows, row)
	}
	return snapshot, nil
}
