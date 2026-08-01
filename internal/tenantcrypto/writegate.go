// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tenantcrypto

import (
	"context"

	"github.com/ctlplne/probectl/internal/license"
)

// GateKeyManagerWrites preserves the key-status read surface while denying
// rotations before they reach the ee delegate whenever the shared license
// write capability is disabled. The tenantcrypto Sealer/Open path is separate
// and deliberately remains untouched so existing ciphertext keeps decrypting.
func GateKeyManagerWrites(delegate KeyManager, writes license.WriteCapability) KeyManager {
	if delegate == nil {
		return nil
	}
	return writeGatedKeyManager{delegate: delegate, writes: writes}
}

type writeGatedKeyManager struct {
	delegate KeyManager
	writes   license.WriteCapability
}

func (g writeGatedKeyManager) KeyStatus(ctx context.Context, tenantID string) ([]KeyInfo, error) {
	return g.delegate.KeyStatus(ctx, tenantID)
}

func (g writeGatedKeyManager) RotateKey(ctx context.Context, tenantID, actor, mode, byokRef string) (KeyInfo, error) {
	if !g.writes.Enabled() {
		return KeyInfo{}, license.ErrReadOnly
	}
	return g.delegate.RotateKey(ctx, tenantID, actor, mode, byokRef)
}
