// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package auth

import (
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// WorkerCredentialPolicyMatches is only one private worker-admission predicate.
// It cannot replace current-row, authority, lifecycle or publication checks. A
// live row alone is insufficient after changing the authenticating Manager key.
func (m *Manager) WorkerCredentialPolicyMatches(ref WorkerCredentialRef) bool {
	if m == nil || m.store == nil || ref.binding == nil || ref.binding.kind != WorkerCredentialSession {
		return false
	}
	if _, _, err := ref.ScopedID(ref.binding.tenant, ref.binding.owner); err != nil {
		return false
	}
	policy := m.workerCredentialPolicy()
	return crypto.ConstantTimeEqual(ref.binding.authPolicy[:], policy[:])
}

// Fingerprint the authenticating configuration privately. The keyed path keeps
// the key in the existing crypto helper, never in an appended temporary buffer.
// Equivalent replicas produce the same policy, never a reusable credential.
func (m *Manager) workerCredentialPolicy() [32]byte {
	source := []byte("probectl.worker.session.policy.v1\x00")
	if m.keyedHashing() {
		source = append(source, 1)
	} else {
		source = append(source, 0)
	}
	source = append(source, 0)
	source = append(source, m.ttl.String()...)
	source = append(source, 0)
	source = append(source, m.idle.String()...)
	if m.secure {
		source = append(source, 1)
	} else {
		source = append(source, 0)
	}
	var digest []byte
	if m.keyedHashing() {
		digest = crypto.Sign(m.hmacKey, source)
	} else {
		digest = crypto.Hash(source)
	}
	var policy [32]byte
	copy(policy[:], digest)
	clear(digest)
	clear(source)
	return policy
}

// WorkerCredentialIdleTimeout returns the current policy's idle window only
// after exact authenticating-policy verification; it grants no data access.
func (m *Manager) WorkerCredentialIdleTimeout(ref WorkerCredentialRef) (time.Duration, error) {
	if !m.WorkerCredentialPolicyMatches(ref) || m.idle <= 0 {
		return 0, ErrWorkerCredentialInvalid
	}
	return m.idle, nil
}
