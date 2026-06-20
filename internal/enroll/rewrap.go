// SPDX-License-Identifier: LicenseRef-probectl-TBD

package enroll

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
)

// RewrapAgentCA re-seals the deployment-global issuing intermediate key from a
// retired deployment KEK to the active one. The root key is never stored, so the
// intermediate key is the only enrollment CA secret this workflow touches.
func RewrapAgentCA(ctx context.Context, pool *pgxpool.Pool, activeKeyID, fromKeyID string, dryRun bool, verifyOpen bool) (store.EnvelopeRewrapStats, error) {
	stats := store.EnvelopeRewrapStats{Store: "agent_ca.key_sealed"}
	cas := store.NewAgentCA(pool)
	certPEM, sealedKey, err := cas.Load(ctx, "intermediate")
	if errors.Is(err, store.ErrAgentCANotInitialized) {
		return stats, nil
	}
	if err != nil {
		return stats, err
	}
	if sealedKey == "" {
		return stats, nil
	}
	stats.RowsScanned = 1
	keyID, ok := tenantcrypto.DeploymentEnvelopeKeyID(sealedKey)
	if !ok {
		return stats, nil
	}
	stats.ValuesScanned = 1
	if keyID == activeKeyID {
		stats.Active = 1
		if verifyOpen {
			if _, err := tenantcrypto.Open(ctx, caSealScope, sealedKey, []byte(caSealAAD)); err != nil {
				return stats, err
			}
			stats.Verified = 1
		}
		return stats, nil
	}
	if fromKeyID != "" && keyID != fromKeyID {
		return stats, nil
	}
	stats.Matched = 1
	if dryRun {
		return stats, nil
	}
	rewrapped, err := tenantcrypto.RewrapDeploymentEnvelope(ctx, caSealScope, sealedKey, []byte(caSealAAD))
	if err != nil {
		return stats, err
	}
	newKeyID, ok := tenantcrypto.DeploymentEnvelopeKeyID(rewrapped)
	if !ok || newKeyID != activeKeyID {
		return stats, fmt.Errorf("enroll: rewrap produced key id %q (want active %q)", newKeyID, activeKeyID)
	}
	if err := cas.Save(ctx, "intermediate", certPEM, rewrapped); err != nil {
		return stats, err
	}
	stats.Rewrapped = 1
	return stats, nil
}
