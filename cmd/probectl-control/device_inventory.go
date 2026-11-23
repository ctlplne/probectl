// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/device"
)

func buildDeviceInventoryReferences(ctx context.Context, cfg *config.Config, log *slog.Logger) *device.InventoryReferences {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	references, issues := device.LoadDeviceInventoryReferences(ctx, device.InventoryReferenceFiles{
		Lifecycle: cfg.DeviceInventoryLifecycleFile, KEV: cfg.DeviceInventoryKEVFile,
		NVD: cfg.DeviceInventoryNVDFile, NVDMetadata: cfg.DeviceInventoryNVDMetadataFile,
		CPEBindings: cfg.DeviceInventoryCPEBindingsFile,
	})
	for source, err := range issues {
		reason := "invalid_or_unreadable"
		switch {
		case errors.Is(err, fs.ErrNotExist):
			reason = "missing"
		case ctx.Err() != nil:
			reason = "deadline_or_shutdown"
		}
		log.Warn("device inventory reference unavailable", "source", source, "reason", reason)
	}
	return references
}
