// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package tenantkeys

import (
	"context"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
)

// Manager adapts the Keyring to the core tenantcrypto.KeyManager contract —
// the /v1/security/keys surface speaks core DTOs (key chain STATE only; the
// material never leaves this package).
type Manager struct{ ring *Keyring }

// NewManager wraps a keyring.
func NewManager(ring *Keyring) *Manager { return &Manager{ring: ring} }

// KeyStatus implements tenantcrypto.KeyManager.
func (m *Manager) KeyStatus(ctx context.Context, tenantID string) ([]tenantcrypto.KeyInfo, error) {
	chain, err := m.ring.Status(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]tenantcrypto.KeyInfo, 0, len(chain))
	for _, kv := range chain {
		out = append(out, toInfo(kv))
	}
	return out, nil
}

// RotateKey implements tenantcrypto.KeyManager.
func (m *Manager) RotateKey(ctx context.Context, tenantID, mode, byokRef string) (tenantcrypto.KeyInfo, error) {
	kv, err := m.ring.Rotate(ctx, tenantID, mode, byokRef)
	if err != nil {
		return tenantcrypto.KeyInfo{}, err
	}
	return toInfo(*kv), nil
}

func toInfo(kv KeyVersion) tenantcrypto.KeyInfo {
	info := tenantcrypto.KeyInfo{
		Version:   kv.Version,
		Mode:      kv.Mode,
		State:     kv.State,
		CreatedAt: kv.CreatedAt.UTC().Format(time.RFC3339),
	}
	if kv.RetiredAt != nil {
		info.RetiredAt = kv.RetiredAt.UTC().Format(time.RFC3339)
	}
	if kv.DestroyedAt != nil {
		info.DestroyedAt = kv.DestroyedAt.UTC().Format(time.RFC3339)
	}
	return info
}
