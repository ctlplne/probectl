// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"log/slog"
	"time"

	"github.com/ctlplne/probectl/internal/license"
)

// License lifecycle audit (DPR-102). The license manager evaluates its state
// on every read, so a deployment slides from active into grace and then into
// read-only without any event being recorded; the lab's license ladder left
// no trace in either audit stream. RunLicenseAudit records the license that
// was loaded and every state transition in the provider stream — the
// deployment-level, separately-audited stream an MSP owns — with the
// identity of the license but never its contents.

const (
	licenseLoadedAuditAction       = "license.loaded"
	licenseStateChangedAuditAction = "license.state_changed"
	licenseAuditTarget             = "license"
	licenseAuditInterval           = time.Minute
)

// licenseInfoSource is what the audit watches: the manager's editions view.
type licenseInfoSource interface {
	Info() license.Info
}

// licenseAuditAppender appends one event to the provider audit stream.
type licenseAuditAppender func(ctx context.Context, action, target string, data map[string]any) error

// RunLicenseAudit records the loaded license once, then every state
// transition it observes at interval until ctx ends. A failed append is
// logged and retried on the next transition; the state itself is never
// affected.
func RunLicenseAudit(ctx context.Context, src licenseInfoSource, appendEvent licenseAuditAppender, interval time.Duration, log *slog.Logger) {
	if src == nil || appendEvent == nil {
		return
	}
	if interval <= 0 {
		interval = licenseAuditInterval
	}
	last := src.Info()
	if err := appendEvent(ctx, licenseLoadedAuditAction, licenseAuditTarget, licenseAuditData(last, "")); err != nil && log != nil {
		log.Warn("failed to audit the loaded license", "error", err.Error())
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cur := src.Info()
		if cur.State == last.State && cur.LicenseID == last.LicenseID && cur.Tier == last.Tier {
			continue
		}
		if err := appendEvent(ctx, licenseStateChangedAuditAction, licenseAuditTarget, licenseAuditData(cur, string(last.State))); err != nil {
			if log != nil {
				log.Warn("failed to audit the license state change", "from", last.State, "to", cur.State, "error", err.Error())
			}
			continue // keep last: retry the transition on the next tick
		}
		if log != nil {
			log.Info("license state changed", "from", last.State, "to", cur.State, "tier", cur.Tier)
		}
		last = cur
	}
}

// licenseAuditData is the event payload: identity and lifecycle, no contents.
func licenseAuditData(info license.Info, from string) map[string]any {
	data := map[string]any{
		"tier":          string(info.Tier),
		"state":         string(info.State),
		"license_id":    info.LicenseID,
		"customer":      info.Customer,
		"trust_anchors": info.TrustAnchors,
	}
	if info.ExpiresAt != nil {
		data["expires_at"] = info.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if info.ReadOnlyAt != nil {
		data["read_only_at"] = info.ReadOnlyAt.UTC().Format(time.RFC3339)
	}
	if from != "" {
		data["from"] = from
	}
	return data
}
