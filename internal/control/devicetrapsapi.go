// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/device"
)

// deviceTrapsContract versions the GET /v1/device/traps response shape.
const deviceTrapsContract = "probectl.device-traps/v1"

type deviceTrapRetention struct {
	MaxPerTenant  int `json:"max_per_tenant"`
	RetentionDays int `json:"retention_days"`
	MaxVarBinds   int `json:"max_varbinds"`
}

type deviceTrapResponse struct {
	ContractVersion   string              `json:"contract_version"`
	Items             []device.TrapRecord `json:"items"`
	CollectionRunning bool                `json:"collection_running"`
	EffectiveLimit    int                 `json:"effective_limit"`
	Truncated         bool                `json:"truncated"`
	AsOf              time.Time           `json:"as_of"`
	LatestAt          *time.Time          `json:"latest_at,omitempty"`
	Retention         deviceTrapRetention `json:"retention"`
}

// handleDeviceTraps serves GET /v1/device/traps (D-60): the caller tenant's
// stored, authenticated SNMP traps, newest first. The tenant comes from the
// session principal; the store reads through a tenant-scoped transaction
// under forced row security, so no query parameter can reach another tenant.
func (s *Server) handleDeviceTraps(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	filter, err := deviceTrapFilter(r)
	if err != nil {
		return err
	}
	resp := deviceTrapResponse{
		ContractVersion: deviceTrapsContract, Items: []device.TrapRecord{},
		CollectionRunning: s.deviceTraps != nil, EffectiveLimit: filter.Limit,
		AsOf: time.Now().UTC(),
		Retention: deviceTrapRetention{
			MaxPerTenant:  device.MaxTrapsPerTenant,
			RetentionDays: int(device.TrapRetention / (24 * time.Hour)),
			MaxVarBinds:   device.MaxTrapVarBinds,
		},
	}
	if s.deviceTraps == nil {
		writeJSON(w, http.StatusOK, resp)
		return nil
	}
	rows, truncated, err := s.deviceTraps.ListTrapEvents(r.Context(), tid, filter)
	if err != nil {
		return err
	}
	if len(rows) > 0 {
		latest := rows[0].ReceivedAt
		resp.LatestAt = &latest
		resp.Items = rows
	}
	resp.Truncated = truncated
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// deviceTrapFilter parses device, since, until (RFC 3339, on the received-at
// clock) and limit (default 100, clamped to the 500-row hard cap).
func deviceTrapFilter(r *http.Request) (device.TrapFilter, error) {
	limit, err := intParam(r, "limit", device.DefaultTrapRead)
	if err != nil {
		return device.TrapFilter{}, err
	}
	q := r.URL.Query()
	f := device.TrapFilter{Device: strings.TrimSpace(q.Get("device")), Limit: min(limit, device.MaxTrapRead)}
	if len(f.Device) > 255 {
		return device.TrapFilter{}, apierror.BadRequest("device must be at most 255 characters")
	}
	for name, dst := range map[string]*time.Time{"since": &f.Since, "until": &f.Until} {
		raw := strings.TrimSpace(q.Get(name))
		if raw == "" {
			continue
		}
		at, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return device.TrapFilter{}, apierror.BadRequest(name + " must be RFC3339")
		}
		*dst = at
	}
	if !f.Since.IsZero() && !f.Until.IsZero() && !f.Since.Before(f.Until) {
		return device.TrapFilter{}, apierror.BadRequest("since must be before until")
	}
	return f, nil
}
