// SPDX-License-Identifier: LicenseRef-probectl-TBD

package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
)

// EnvelopeRewrapStats is a no-secret receipt for a deployment-envelope rewrap
// pass. Counts are value-level for encrypted fields and row-level for rows.
type EnvelopeRewrapStats struct {
	Store         string `json:"store"`
	RowsScanned   int    `json:"rows_scanned"`
	ValuesScanned int    `json:"values_scanned"`
	Active        int    `json:"active"`
	Matched       int    `json:"matched"`
	Rewrapped     int    `json:"rewrapped"`
	Verified      int    `json:"verified"`
}

// Add folds another store's stats into this receipt.
func (s *EnvelopeRewrapStats) Add(other EnvelopeRewrapStats) {
	s.RowsScanned += other.RowsScanned
	s.ValuesScanned += other.ValuesScanned
	s.Active += other.Active
	s.Matched += other.Matched
	s.Rewrapped += other.Rewrapped
	s.Verified += other.Verified
}

// RewrapEnvelopeSecrets re-seals webhook channel secrets from a retired
// deployment KEK to the active one. It runs inside a tenant scope so RLS remains
// the outer boundary even though this is an operator maintenance job.
func (AlertRules) RewrapEnvelopeSecrets(ctx context.Context, s tenancy.Scope, activeKeyID, fromKeyID string, dryRun bool, verifyOpen bool) (EnvelopeRewrapStats, error) {
	stats := EnvelopeRewrapStats{Store: "alert_rules.channels"}
	rows, err := s.Q.Query(ctx, `SELECT id::text, channels FROM alert_rules WHERE channels::text LIKE '%dv1:%' ORDER BY id`)
	if err != nil {
		return stats, err
	}
	defer rows.Close()

	type row struct {
		id       string
		channels []alert.ChannelSpec
	}
	var candidates []row
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return stats, err
		}
		var channels []alert.ChannelSpec
		if err := json.Unmarshal(raw, &channels); err != nil {
			return stats, err
		}
		candidates = append(candidates, row{id: id, channels: channels})
	}
	if err := rows.Err(); err != nil {
		return stats, err
	}

	for _, candidate := range candidates {
		stats.RowsScanned++
		changed := false
		for i := range candidate.channels {
			secret := candidate.channels[i].Secret
			keyID, ok := tenantcrypto.DeploymentEnvelopeKeyID(secret)
			if !ok {
				continue
			}
			stats.ValuesScanned++
			if keyID == activeKeyID {
				stats.Active++
				if verifyOpen {
					if _, err := tenantcrypto.Open(ctx, s.Tenant.String(), secret, channelSecretAAD); err != nil {
						return stats, err
					}
					stats.Verified++
				}
				continue
			}
			if fromKeyID != "" && keyID != fromKeyID {
				continue
			}
			stats.Matched++
			if dryRun {
				continue
			}
			rewrapped, err := tenantcrypto.RewrapDeploymentEnvelope(ctx, s.Tenant.String(), secret, channelSecretAAD)
			if err != nil {
				return stats, err
			}
			newKeyID, ok := tenantcrypto.DeploymentEnvelopeKeyID(rewrapped)
			if !ok || newKeyID != activeKeyID {
				return stats, fmt.Errorf("alert_rules: rewrap produced key id %q (want active %q)", newKeyID, activeKeyID)
			}
			candidate.channels[i].Secret = rewrapped
			stats.Rewrapped++
			changed = true
		}
		if changed {
			raw, err := json.Marshal(candidate.channels)
			if err != nil {
				return stats, err
			}
			if _, err := s.Q.Exec(ctx, `UPDATE alert_rules SET channels = $2::jsonb, updated_at = now() WHERE id = $1`, candidate.id, string(raw)); err != nil {
				return stats, err
			}
		}
	}
	return stats, nil
}
