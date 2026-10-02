// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package tenantkeys

import (
	"context"
	"fmt"
	"strconv"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
)

// RewrapManagedKEKs re-seals every managed tenant KEK from a retired
// deployment-envelope key to the active one (CRY-02). Without it, the documented
// PROBECTL_ENVELOPE_KEY rotation leaves managed tenant_keys.wrapped_kek rows
// sealed under the retired key — openable only while the retired key stays in
// PROBECTL_ENVELOPE_OPENER_KEYS — so this is what lets the operator fully retire
// the old key. master MUST carry the retired key as an opener (built by
// byokMaster in the attach seam); otherwise the unwrap fails closed.
//
// In dry-run it only inventories. In verify mode (dryRun + verifyOpen) it opens
// every active-key value to prove it decrypts and counts any value still under
// fromKeyID as Matched, so the caller's --verify-retired-key-id can assert zero.
func RewrapManagedKEKs(ctx context.Context, master *crypto.Envelope, st Store, activeKeyID, fromKeyID string, dryRun, verifyOpen bool) (store.EnvelopeRewrapStats, error) {
	stats := store.EnvelopeRewrapStats{Store: "tenant_keys.wrapped_kek"}
	if master == nil {
		return stats, fmt.Errorf("tenantkeys: rewrap requires the deployment master envelope")
	}
	rows, err := st.AllManaged(ctx)
	if err != nil {
		return stats, err
	}
	for _, kv := range rows {
		stats.RowsScanned++
		sealed, err := decodeSealed(kv.WrappedKEK)
		if err != nil {
			return stats, fmt.Errorf("tenantkeys: tenant %s v%d: %w", kv.TenantID, kv.Version, err)
		}
		stats.ValuesScanned++
		aad := []byte("tenant-kek:" + kv.TenantID + ":" + strconv.Itoa(kv.Version))

		if sealed.KeyID == activeKeyID {
			stats.Active++
			if verifyOpen {
				kek, err := master.Open(ctx, sealed, aad)
				if err != nil {
					return stats, fmt.Errorf("tenantkeys: verify tenant %s v%d under active key: %w", kv.TenantID, kv.Version, err)
				}
				zeroize(kek)
				stats.Verified++
			}
			continue
		}
		if fromKeyID != "" && sealed.KeyID != fromKeyID {
			continue
		}
		stats.Matched++
		if dryRun {
			continue
		}
		kek, err := master.Open(ctx, sealed, aad)
		if err != nil {
			return stats, fmt.Errorf("tenantkeys: unwrap tenant %s v%d (retired key %q — is it in PROBECTL_ENVELOPE_OPENER_KEYS?): %w",
				kv.TenantID, kv.Version, sealed.KeyID, err)
		}
		resealed, err := master.Seal(ctx, kek, aad)
		zeroize(kek)
		if err != nil {
			return stats, fmt.Errorf("tenantkeys: reseal tenant %s v%d: %w", kv.TenantID, kv.Version, err)
		}
		if resealed.KeyID != activeKeyID {
			return stats, fmt.Errorf("tenantkeys: reseal produced key id %q (want active %q)", resealed.KeyID, activeKeyID)
		}
		if err := st.UpdateWrappedKEK(ctx, kv.TenantID, kv.Version, encodeSealed(resealed)); err != nil {
			return stats, err
		}
		stats.Rewrapped++
	}
	return stats, nil
}
