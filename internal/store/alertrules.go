// SPDX-License-Identifier: LicenseRef-probectl-TBD

package store

import (
	"context"
	"encoding/json"

	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
)

// AlertRules is the tenant-scoped alert-rule repository. RLS confines every row
// to the caller's tenant (F50).
type AlertRules struct{}

const alertRuleCols = `id::text, tenant_id::text, name, enabled, metric, match_labels,
	type, comparison, threshold, window_n, sensitivity, for_n, renotify_seconds,
	severity, channels, created_at, updated_at`

// channelSecretAAD binds sealed channel secrets to their column (the tenant
// binding rides tenantcrypto.BindAAD inside the sealer).
var channelSecretAAD = []byte("alert-channel-secret")

// sealChannelSecrets seals each channel's HMAC secret at rest (S-T6 — the
// follow-up noted in migration 0011): per-tenant keys when licensed, the
// deployment envelope otherwise, passthrough only in keyless dev. The store
// value is self-describing, so legacy plaintext rows keep working
// (decrypt-on-read).
func sealChannelSecrets(ctx context.Context, tenantID string, channels []alert.ChannelSpec) ([]alert.ChannelSpec, error) {
	if len(channels) == 0 {
		return channels, nil
	}
	out := make([]alert.ChannelSpec, len(channels))
	copy(out, channels)
	for i := range out {
		if out[i].Secret == "" {
			continue
		}
		sealed, err := tenantcrypto.Seal(ctx, tenantID, []byte(out[i].Secret), channelSecretAAD)
		if err != nil {
			return nil, err
		}
		out[i].Secret = sealed
	}
	return out, nil
}

// openChannelSecrets reverses sealChannelSecrets. A missing/destroyed key is
// an ERROR for that rule (fail safe — never a silent fallback).
func openChannelSecrets(ctx context.Context, tenantID string, channels []alert.ChannelSpec) error {
	for i := range channels {
		if channels[i].Secret == "" {
			continue
		}
		plain, err := tenantcrypto.Open(ctx, tenantID, channels[i].Secret, channelSecretAAD)
		if err != nil {
			return err
		}
		channels[i].Secret = string(plain)
	}
	return nil
}

func scanAlertRule(row interface{ Scan(...any) error }, r *alert.Rule) error {
	var match, channels []byte
	var typ, cmp, sev string
	if err := row.Scan(&r.ID, &r.TenantID, &r.Name, &r.Enabled, &r.Metric, &match,
		&typ, &cmp, &r.Threshold, &r.Window, &r.Sensitivity, &r.ForN, &r.RenotifySeconds,
		&sev, &channels, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return err
	}
	r.Type = alert.RuleType(typ)
	r.Comparison = alert.Comparison(cmp)
	r.Severity = alert.Severity(sev)
	r.Match = map[string]string{}
	if len(match) > 0 {
		if err := json.Unmarshal(match, &r.Match); err != nil {
			return err
		}
	}
	r.Channels = nil
	if len(channels) > 0 {
		if err := json.Unmarshal(channels, &r.Channels); err != nil {
			return err
		}
	}
	return nil
}

func marshalMatch(m map[string]string) string {
	if m == nil {
		return "{}"
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func marshalChannels(c []alert.ChannelSpec) string {
	if c == nil {
		return "[]"
	}
	b, _ := json.Marshal(c)
	return string(b)
}

// Create inserts an alert rule in the caller's tenant.
func (AlertRules) Create(ctx context.Context, s tenancy.Scope, in alert.Rule) (*alert.Rule, error) {
	sealed, err := sealChannelSecrets(ctx, s.Tenant.String(), in.Channels)
	if err != nil {
		return nil, err
	}
	in.Channels = sealed
	var r alert.Rule
	err = scanAlertRule(s.Q.QueryRow(ctx,
		`INSERT INTO alert_rules
		   (tenant_id, name, enabled, metric, match_labels, type, comparison, threshold,
		    window_n, sensitivity, for_n, renotify_seconds, severity, channels)
		 VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb)
		 RETURNING `+alertRuleCols,
		s.Tenant.String(), in.Name, in.Enabled, in.Metric, marshalMatch(in.Match),
		string(in.Type), string(in.Comparison), in.Threshold, in.Window, in.Sensitivity,
		in.ForN, in.RenotifySeconds, string(in.Severity), marshalChannels(in.Channels)), &r)
	if err != nil {
		return nil, mapWriteErr("alert rule", err)
	}
	if err := openChannelSecrets(ctx, s.Tenant.String(), r.Channels); err != nil {
		return nil, err
	}
	return &r, nil
}

// Get returns an alert rule by id (RLS guarantees tenant ownership).
func (AlertRules) Get(ctx context.Context, s tenancy.Scope, id string) (*alert.Rule, error) {
	var r alert.Rule
	if err := scanAlertRule(s.Q.QueryRow(ctx,
		`SELECT `+alertRuleCols+` FROM alert_rules WHERE id = $1`, id), &r); err != nil {
		return nil, notFound("alert rule", err)
	}
	if err := openChannelSecrets(ctx, s.Tenant.String(), r.Channels); err != nil {
		return nil, err
	}
	return &r, nil
}

// List returns the tenant's alert rules, newest first.
func (AlertRules) List(ctx context.Context, s tenancy.Scope) ([]alert.Rule, error) {
	rows, err := s.Q.Query(ctx, `SELECT `+alertRuleCols+` FROM alert_rules ORDER BY created_at DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []alert.Rule{}
	for rows.Next() {
		var r alert.Rule
		if err := scanAlertRule(rows, &r); err != nil {
			return nil, err
		}
		if err := openChannelSecrets(ctx, s.Tenant.String(), r.Channels); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListEnabled returns the tenant's enabled rules (the evaluator's working set).
func (AlertRules) ListEnabled(ctx context.Context, s tenancy.Scope) ([]alert.Rule, error) {
	rows, err := s.Q.Query(ctx, `SELECT `+alertRuleCols+` FROM alert_rules WHERE enabled ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []alert.Rule{}
	for rows.Next() {
		var r alert.Rule
		if err := scanAlertRule(rows, &r); err != nil {
			return nil, err
		}
		if err := openChannelSecrets(ctx, s.Tenant.String(), r.Channels); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Update replaces an alert rule's mutable fields.
func (AlertRules) Update(ctx context.Context, s tenancy.Scope, id string, in alert.Rule) (*alert.Rule, error) {
	sealed, err := sealChannelSecrets(ctx, s.Tenant.String(), in.Channels)
	if err != nil {
		return nil, err
	}
	in.Channels = sealed
	var r alert.Rule
	err = scanAlertRule(s.Q.QueryRow(ctx,
		`UPDATE alert_rules SET name=$2, enabled=$3, metric=$4, match_labels=$5::jsonb,
		   type=$6, comparison=$7, threshold=$8, window_n=$9, sensitivity=$10, for_n=$11,
		   renotify_seconds=$12, severity=$13, channels=$14::jsonb, updated_at=now()
		 WHERE id = $1
		 RETURNING `+alertRuleCols,
		id, in.Name, in.Enabled, in.Metric, marshalMatch(in.Match), string(in.Type),
		string(in.Comparison), in.Threshold, in.Window, in.Sensitivity, in.ForN,
		in.RenotifySeconds, string(in.Severity), marshalChannels(in.Channels)), &r)
	if err != nil {
		return nil, mapWriteErr("alert rule", err)
	}
	if err := openChannelSecrets(ctx, s.Tenant.String(), r.Channels); err != nil {
		return nil, err
	}
	return &r, nil
}

// Delete removes an alert rule by id.
func (AlertRules) Delete(ctx context.Context, s tenancy.Scope, id string) error {
	tag, err := s.Q.Exec(ctx, `DELETE FROM alert_rules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return apierror.NotFound("alert rule not found")
	}
	return nil
}
