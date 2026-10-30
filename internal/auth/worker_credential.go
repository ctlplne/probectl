// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package auth

import (
	"errors"
	"fmt"
	"io"

	"github.com/ctlplne/probectl/internal/crypto"
)

type WorkerCredentialKind uint8

const (
	WorkerCredentialSession WorkerCredentialKind = 1
	WorkerCredentialMCP     WorkerCredentialKind = 2
	workerCredentialBytes                        = 4 + 1 + 36*3 + 32 + 32
)

var (
	ErrWorkerCredentialInvalid = errors.New("auth: invalid originating worker credential")
	errWorkerCredentialPrivate = errors.New("auth: worker credential references require private encrypted storage")
)

// WorkerCredentialRef identifies one exact accepted credential, not a principal
// or grant. Capture only after real authentication; store only in an envelope
// bound to the immutable tenant/owner/message/revision. It cannot authenticate
// a public request. Every worker use must reload the live credential and current
// user/grants/policies/lifecycle before sensitive reads and publication.
type WorkerCredentialRef struct {
	binding *workerCredentialBinding
}

// A private pointer also prevents fmt from recursively exposing an unexported
// reference value inside another struct. The binding is immutable after capture.
type workerCredentialBinding struct {
	kind        WorkerCredentialKind
	tenant      string
	owner       string
	id          string
	authPolicy  [32]byte
	fingerprint [32]byte
}

// WithWorkerCredential copies an already authenticated principal and attaches
// private provenance only. It neither reloads nor grants permissions. MCP origin
// remains bearer origin, and a session reference cannot downgrade that marker.
func WithWorkerCredential(p *Principal, ref WorkerCredentialRef) (*Principal, error) {
	if p == nil {
		return nil, ErrWorkerCredentialInvalid
	}
	kind, _, err := ref.ScopedID(p.TenantID, p.UserID)
	if err != nil || kind == WorkerCredentialSession && p.ViaBearerToken {
		return nil, ErrWorkerCredentialInvalid
	}
	snapshot := *p
	snapshot.workerCredential = ref
	snapshot.ViaBearerToken = kind == WorkerCredentialMCP
	return &snapshot, nil
}

// WorkerCredentialFromPrincipal is private worker-admission metadata, not
// authorization. Every execution/publication must revalidate the live credential
// and all current authority through the tenant-scoped store/policy boundaries.
func WorkerCredentialFromPrincipal(p *Principal) (WorkerCredentialRef, error) {
	if p == nil {
		return WorkerCredentialRef{}, ErrWorkerCredentialInvalid
	}
	kind, _, err := p.workerCredential.ScopedID(p.TenantID, p.UserID)
	if err != nil || p.ViaBearerToken != (kind == WorkerCredentialMCP) {
		return WorkerCredentialRef{}, ErrWorkerCredentialInvalid
	}
	return p.workerCredential, nil
}

// CaptureWorkerCredential fingerprints the accepted stored hash, never a raw
// bearer or cookie. A later credential on the same row cannot satisfy it.
func CaptureWorkerCredential(kind WorkerCredentialKind, tenant, owner, id string, storedHash []byte) (WorkerCredentialRef, error) {
	return captureWorkerCredential(kind, tenant, owner, id, storedHash, [32]byte{})
}

func captureWorkerCredential(kind WorkerCredentialKind, tenant, owner, id string, storedHash []byte, policy [32]byte) (WorkerCredentialRef, error) {
	if !workerCredentialScopeValid(kind, tenant, owner, id) || len(storedHash) != 32 {
		return WorkerCredentialRef{}, ErrWorkerCredentialInvalid
	}
	binding := &workerCredentialBinding{kind: kind, tenant: tenant, owner: owner, id: id, authPolicy: policy}
	binding.fingerprint = workerCredentialFingerprint(kind, tenant, owner, id, storedHash, policy)
	return WorkerCredentialRef{binding: binding}, nil
}

// ScopedID returns only metadata for an already tenant/owner-bound worker. No
// unscoped ID lookup or access to a raw token/hash/fingerprint is available.
func (r WorkerCredentialRef) ScopedID(tenant, owner string) (WorkerCredentialKind, string, error) {
	binding := r.binding
	if binding == nil || !workerCredentialScopeValid(binding.kind, binding.tenant, binding.owner, binding.id) || binding.tenant != tenant || binding.owner != owner {
		return 0, "", ErrWorkerCredentialInvalid
	}
	return binding.kind, binding.id, nil
}

// MatchesStored verifies the authoritative current row identity and hash. It
// deliberately checks every scope component even when SQL already scoped it.
func (r WorkerCredentialRef) MatchesStored(kind WorkerCredentialKind, tenant, owner, id string, storedHash []byte) bool {
	binding := r.binding
	if binding == nil || binding.kind != kind || binding.tenant != tenant || binding.owner != owner || binding.id != id || len(storedHash) != 32 {
		return false
	}
	if !workerCredentialScopeValid(kind, tenant, owner, id) {
		return false
	}
	actual := workerCredentialFingerprint(kind, tenant, owner, id, storedHash, binding.authPolicy)
	return crypto.ConstantTimeEqual(binding.fingerprint[:], actual[:])
}

func workerCredentialFingerprint(kind WorkerCredentialKind, tenant, owner, id string, hash []byte, policy [32]byte) [32]byte {
	source := append([]byte("probectl.worker.credential.v2\x00"), byte(kind))
	source = append(source, tenant...)
	source = append(source, owner...)
	source = append(source, id...)
	source = append(source, policy[:]...)
	source = append(source, hash...)
	var fingerprint [32]byte
	copy(fingerprint[:], crypto.Hash(source))
	clear(source)
	return fingerprint
}

func workerCredentialScopeValid(kind WorkerCredentialKind, tenant, owner, id string) bool {
	return (kind == WorkerCredentialSession || kind == WorkerCredentialMCP) && workerCredentialUUID(tenant) && workerCredentialUUID(owner) && workerCredentialUUID(id)
}

func workerCredentialUUID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for index, value := range []byte(id) {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if value != '-' {
				return false
			}
			continue
		}
		isHex := value >= '0' && value <= '9' || value >= 'a' && value <= 'f'
		if !isHex {
			return false
		}
	}
	return true
}

// MarshalBinary is an explicit PRIVATE storage codec for later envelope
// sealing. Its output is never a public capability or authentication token.
func (r WorkerCredentialRef) MarshalBinary() ([]byte, error) {
	binding := r.binding
	if binding == nil {
		return nil, ErrWorkerCredentialInvalid
	}
	if _, _, err := r.ScopedID(binding.tenant, binding.owner); err != nil {
		return nil, err
	}
	out := make([]byte, 0, workerCredentialBytes)
	out = append(out, "PWC2"...)
	out = append(out, byte(binding.kind))
	out = append(out, binding.tenant...)
	out = append(out, binding.owner...)
	out = append(out, binding.id...)
	out = append(out, binding.authPolicy[:]...)
	out = append(out, binding.fingerprint[:]...)
	return out, nil
}

// DecodeWorkerCredentialRef decodes syntax only. A valid encoding still needs
// authoritative current-row verification and current authorization on every use.
func DecodeWorkerCredentialRef(encoded []byte) (WorkerCredentialRef, error) {
	if len(encoded) != workerCredentialBytes || string(encoded[:4]) != "PWC2" {
		return WorkerCredentialRef{}, ErrWorkerCredentialInvalid
	}
	binding := &workerCredentialBinding{
		kind: WorkerCredentialKind(encoded[4]), tenant: string(encoded[5:41]),
		owner: string(encoded[41:77]), id: string(encoded[77:113]),
	}
	if !workerCredentialScopeValid(binding.kind, binding.tenant, binding.owner, binding.id) {
		return WorkerCredentialRef{}, ErrWorkerCredentialInvalid
	}
	copy(binding.authPolicy[:], encoded[113:145])
	copy(binding.fingerprint[:], encoded[145:])
	return WorkerCredentialRef{binding: binding}, nil
}

func (WorkerCredentialRef) MarshalJSON() ([]byte, error) { return nil, errWorkerCredentialPrivate }
func (*WorkerCredentialRef) UnmarshalJSON([]byte) error  { return errWorkerCredentialPrivate }

func (WorkerCredentialRef) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "auth.WorkerCredentialRef[private]")
}
