// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"strings"

	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/siem"
)

// deviceSyslogSink adapts the authenticated TLS syslog receiver (internal/siem)
// onto the tenant-scoped device syslog store the control plane serves at
// GET /v1/device/syslog. The receiver stamps the tenant from the authenticated
// source (never the payload); this sink only translates the normalized event
// and persists it through the SAME OpsStore the API reads, so an accepted line
// surfaces on the read path (RTP-09). Tenant isolation stays a storage-layer
// property: the row carries the receiver's resolved tenant_id (docs/guardrails.md
// G7-1).
type deviceSyslogSink struct {
	ops device.OpsStore
}

// NewDeviceSyslogSink wires the authenticated TLS syslog receiver's store onto
// the control plane's device syslog read path (RTP-09). ops is the same
// tenant-scoped store GET /v1/device/syslog reads (Server.DeviceOps()).
func NewDeviceSyslogSink(ops device.OpsStore) siem.SyslogStore {
	return &deviceSyslogSink{ops: ops}
}

// RecordSyslog implements siem.SyslogStore: it maps the normalized, authenticated
// siem event onto a device.SyslogEvent and persists it tenant-scoped.
func (s *deviceSyslogSink) RecordSyslog(ctx context.Context, ev siem.SyslogEvent) (siem.SyslogEvent, error) {
	deviceName := strings.TrimSpace(ev.Hostname)
	if deviceName == "" {
		deviceName = strings.TrimSpace(ev.SourceName)
	}
	message := ev.Message
	if strings.TrimSpace(message) == "" {
		// The device store requires a non-empty message; a NILVALUE RFC 5424 MSG
		// still produces a record (severity/host/app are the signal) rather than
		// being dropped.
		message = "-"
	}
	version := 0
	if ev.Format == "rfc5424" {
		version = 1
	}
	stored, err := s.ops.RecordSyslog(ctx, device.SyslogEvent{
		TenantID:      ev.TenantID,
		Device:        deviceName,
		SourceAddress: ev.SourceAddress,
		Facility:      ev.Facility,
		Severity:      ev.Severity,
		SeverityText:  device.SyslogSeverityText(ev.Severity),
		Version:       version,
		Hostname:      ev.Hostname,
		AppName:       ev.AppName,
		Message:       message,
		Labels:        deviceSyslogLabels(ev),
		ObservedAt:    ev.ReceivedAt,
	})
	if err != nil {
		return siem.SyslogEvent{}, err
	}
	ev.ID = stored.ID
	return ev, nil
}

// deviceSyslogLabels carries a few non-sensitive provenance keys from the
// authenticated receiver onto the stored row for operator traceability.
func deviceSyslogLabels(ev siem.SyslogEvent) map[string]string {
	labels := map[string]string{
		"source_name": ev.SourceName,
		"auth_method": ev.AuthMethod,
		"format":      ev.Format,
	}
	if ev.ProcID != "" {
		labels["proc_id"] = ev.ProcID
	}
	if ev.MsgID != "" {
		labels["msg_id"] = ev.MsgID
	}
	return labels
}
