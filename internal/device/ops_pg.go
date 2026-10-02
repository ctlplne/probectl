// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// PostgresOpsStore is the durable device OpsStore (PLAT-06/RTP-08/WEB-26):
// device syslog and config-archive rows survive a control-plane restart and are
// shared across replicas, unlike MemoryOpsStore. Every read and write runs
// inside a tenant-scoped transaction, so FORCE ROW LEVEL SECURITY (migration
// 0104) is the enforced boundary — the handler can never read another tenant's
// rows. MemoryOpsStore remains for tests and the pool-less lightweight mode.
type PostgresOpsStore struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// NewPostgresOpsStore binds the store to the writer pool.
func NewPostgresOpsStore(pool *pgxpool.Pool) *PostgresOpsStore {
	return &PostgresOpsStore{pool: pool, now: time.Now}
}

func (s *PostgresOpsStore) inTenant(ctx context.Context, tenant string, fn func(context.Context, tenancy.Scope) error) error {
	return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), s.pool, fn)
}

func (s *PostgresOpsStore) RecordSyslog(ctx context.Context, ev SyslogEvent) (SyslogEvent, error) {
	if ev.TenantID == "" {
		return SyslogEvent{}, errors.New("device ops: tenant_id is required")
	}
	if strings.TrimSpace(ev.Device) == "" {
		return SyslogEvent{}, errors.New("device ops: device is required")
	}
	if strings.TrimSpace(ev.Message) == "" {
		return SyslogEvent{}, errors.New("device ops: message is required")
	}
	if ev.ObservedAt.IsZero() {
		ev.ObservedAt = s.now()
	}
	ev.ObservedAt = ev.ObservedAt.UTC()
	if ev.SeverityText == "" {
		ev.SeverityText = SyslogSeverityText(ev.Severity)
	}
	labels, err := json.Marshal(ev.Labels)
	if err != nil {
		return SyslogEvent{}, fmt.Errorf("device ops: encode labels: %w", err)
	}
	err = s.inTenant(ctx, ev.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `
INSERT INTO device_syslog
    (tenant_id, device, source_address, facility, severity, severity_text, hostname, app_name, message, raw, labels, observed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12)
RETURNING id::text`,
			ev.TenantID, ev.Device, ev.SourceAddress, ev.Facility, ev.Severity, ev.SeverityText,
			ev.Hostname, ev.AppName, ev.Message, ev.Raw, string(labels), ev.ObservedAt).Scan(&ev.ID)
	})
	if err != nil {
		return SyslogEvent{}, fmt.Errorf("device ops: record syslog: %w", err)
	}
	return ev, nil
}

func (s *PostgresOpsStore) ListSyslog(ctx context.Context, tenant string, f OpsFilter) ([]SyslogEvent, error) {
	if tenant == "" {
		return nil, errors.New("device ops: tenant_id is required")
	}
	limit := normalizeOpsLimit(f.Limit)
	var out []SyslogEvent
	err := s.inTenant(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		// RLS scopes the read to the caller tenant; the device filter is optional.
		rows, err := sc.Q.Query(ctx, `
SELECT id::text, tenant_id::text, device, source_address, facility, severity, severity_text,
       hostname, app_name, message, raw, labels, observed_at
  FROM device_syslog
 WHERE ($1 = '' OR device = $1)
 ORDER BY observed_at DESC
 LIMIT $2`, f.Device, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ev SyslogEvent
			var labels []byte
			if err := rows.Scan(&ev.ID, &ev.TenantID, &ev.Device, &ev.SourceAddress, &ev.Facility,
				&ev.Severity, &ev.SeverityText, &ev.Hostname, &ev.AppName, &ev.Message, &ev.Raw,
				&labels, &ev.ObservedAt); err != nil {
				return err
			}
			if len(labels) > 0 {
				_ = json.Unmarshal(labels, &ev.Labels)
			}
			ev.ObservedAt = ev.ObservedAt.UTC()
			out = append(out, ev)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("device ops: list syslog: %w", err)
	}
	return out, nil
}

func (s *PostgresOpsStore) ArchiveConfig(ctx context.Context, cfg ConfigVersion) (ConfigVersion, error) {
	if cfg.TenantID == "" {
		return ConfigVersion{}, errors.New("device ops: tenant_id is required")
	}
	if strings.TrimSpace(cfg.Device) == "" {
		return ConfigVersion{}, errors.New("device ops: device is required")
	}
	cfg.Device = strings.TrimSpace(cfg.Device)
	cfg.Content = RedactConfig(cfg.Content)
	cfg.ContentHash = hashConfig(cfg.Content)
	if cfg.ObservedAt.IsZero() {
		cfg.ObservedAt = s.now()
	}
	cfg.ObservedAt = cfg.ObservedAt.UTC()
	cfg.ArchivedAt = s.now().UTC()
	cfg.PreviousHash = ""
	cfg.Drifted = false
	cfg.Version = 1
	err := s.inTenant(ctx, cfg.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
		var prevHash string
		var prevVer int
		err := sc.Q.QueryRow(ctx,
			`SELECT content_hash, version FROM device_configs WHERE device = $1 ORDER BY version DESC LIMIT 1`,
			cfg.Device).Scan(&prevHash, &prevVer)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			// first version for this device
		case err != nil:
			return err
		default:
			cfg.PreviousHash = prevHash
			cfg.Version = prevVer + 1
			cfg.Drifted = prevHash != cfg.ContentHash
		}
		return sc.Q.QueryRow(ctx, `
INSERT INTO device_configs
    (tenant_id, device, source, version, content, content_hash, previous_hash, drifted, observed_at, archived_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING id::text`,
			cfg.TenantID, cfg.Device, cfg.Source, cfg.Version, cfg.Content, cfg.ContentHash,
			cfg.PreviousHash, cfg.Drifted, cfg.ObservedAt, cfg.ArchivedAt).Scan(&cfg.ID)
	})
	if err != nil {
		return ConfigVersion{}, fmt.Errorf("device ops: archive config: %w", err)
	}
	return cfg, nil
}

func (s *PostgresOpsStore) ListConfigs(ctx context.Context, tenant string, f OpsFilter) ([]ConfigVersion, error) {
	if tenant == "" {
		return nil, errors.New("device ops: tenant_id is required")
	}
	limit := normalizeOpsLimit(f.Limit)
	var out []ConfigVersion
	err := s.inTenant(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `
SELECT id::text, tenant_id::text, device, source, version, content, content_hash, previous_hash, drifted, observed_at, archived_at
  FROM device_configs
 WHERE ($1 = '' OR device = $1)
 ORDER BY archived_at DESC
 LIMIT $2`, f.Device, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var cfg ConfigVersion
			if err := rows.Scan(&cfg.ID, &cfg.TenantID, &cfg.Device, &cfg.Source, &cfg.Version,
				&cfg.Content, &cfg.ContentHash, &cfg.PreviousHash, &cfg.Drifted,
				&cfg.ObservedAt, &cfg.ArchivedAt); err != nil {
				return err
			}
			cfg.ObservedAt = cfg.ObservedAt.UTC()
			cfg.ArchivedAt = cfg.ArchivedAt.UTC()
			out = append(out, cfg)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("device ops: list configs: %w", err)
	}
	return out, nil
}
