// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

// See ee/doc.go for the boundary rules every ee/ file observes.

package provider

import (
	"context"
	"fmt"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
)

// RewrapOperatorTOTP re-seals every provider operator's TOTP secret from a
// retired deployment-envelope key to the active one (PLAT-04). provider-operator
// TOTP is sealed with the SAME deployment envelope as alert_rules / tenant_idp /
// agent_ca, so without it a deployment-envelope rotation left every operator's
// MFA on the retired key: envelope-rewrap --verify-retired reported success
// (it never scanned provider_operators) and removing the retired opener locked
// every provider operator out of the console (break-glass / cross-tenant ops).
//
// env must carry the retired key as an opener (the keyring built from
// PROBECTL_ENVELOPE_OPENER_KEYS) so a matched value can be opened and re-sealed
// under the active key. It mirrors the alert_rules / tenant_idp rewrap, using
// the per-operator AAD "provider-totp:<id>".
func RewrapOperatorTOTP(ctx context.Context, env *crypto.Envelope, st *PGStore, activeKeyID, fromKeyID string, dryRun, verifyOpen bool) (store.EnvelopeRewrapStats, error) {
	stats := store.EnvelopeRewrapStats{Store: "provider_operators.totp"}
	if env == nil || st == nil {
		return stats, nil
	}
	ops, err := st.ListOperatorTOTPs(ctx)
	if err != nil {
		return stats, err
	}
	for _, op := range ops {
		stats.RowsScanned++
		keyID := op.Sealed.KeyID
		if keyID == "" {
			continue
		}
		stats.ValuesScanned++
		aad := []byte("provider-totp:" + op.ID)
		if keyID == activeKeyID {
			stats.Active++
			if verifyOpen {
				raw, err := env.Open(ctx, op.Sealed, aad)
				if err != nil {
					return stats, err
				}
				crypto.Zeroize(raw)
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
		raw, err := env.Open(ctx, op.Sealed, aad)
		if err != nil {
			return stats, err
		}
		resealed, err := env.Seal(ctx, raw, aad)
		crypto.Zeroize(raw)
		if err != nil {
			return stats, err
		}
		if resealed.KeyID != activeKeyID {
			return stats, fmt.Errorf("provider_operators: rewrap produced key id %q (want active %q)", resealed.KeyID, activeKeyID)
		}
		if err := st.SetOperatorTOTP(ctx, op.ID, resealed); err != nil {
			return stats, err
		}
		stats.Rewrapped++
	}
	return stats, nil
}
