// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package audit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

const (
	irPrivateArtifactDomain   = "probectl-ir-private-artifact-v1"
	maxIRPrivateArtifactBytes = 64 << 10
)

// IROpenKeyResolver is the investigation-only half of the IR key domain.
// Routine provider operation receives only IRWrapKeyResolver and therefore
// cannot obtain this capability.
type IROpenKeyResolver interface {
	OpenProviderForTenant(
		context.Context,
		string,
		string,
	) (crypto.KeyProvider, func(), error)
}

// LocalIRPrivateKeyResolver opens operator-owned, envelope-encrypted private
// key artifacts from a local directory. It performs no network operations,
// reads an artifact only after authorization, and never caches plaintext key
// material. Versioned files are named
// <tenant-uuid>.<sha256-of-key-id>.pem.enc and must be mode 0600.
type LocalIRPrivateKeyResolver struct {
	directory string
	unlock    crypto.KeyProvider
}

// NewLocalIRPrivateKeyResolver validates the investigation-only local mount.
func NewLocalIRPrivateKeyResolver(
	directory string,
	unlock crypto.KeyProvider,
) (*LocalIRPrivateKeyResolver, error) {
	if unlock == nil {
		return nil, errors.New("audit: IR private-artifact unlock provider is required")
	}
	directory = filepath.Clean(strings.TrimSpace(directory))
	if directory == "." || !filepath.IsAbs(directory) {
		return nil, errors.New("audit: IR private-key directory must be an absolute path")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("audit: inspect IR private-key directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("audit: IR private-key path must be a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf(
			"audit: IR private-key directory permissions are %04o, want owner-only",
			info.Mode().Perm(),
		)
	}
	return &LocalIRPrivateKeyResolver{directory: directory, unlock: unlock}, nil
}

// OpenProviderForTenant authenticates and opens exactly one encrypted private
// artifact. The artifact's AEAD binds it to both tenant and public-key ID, so a
// copied file cannot open another tenant's sidecar. cleanup must be called.
func (r *LocalIRPrivateKeyResolver) OpenProviderForTenant(
	ctx context.Context,
	tenantID, keyID string,
) (crypto.KeyProvider, func(), error) {
	if r == nil || r.unlock == nil || r.directory == "" {
		return nil, nil, ErrIRKeyUnavailable
	}
	if !canonicalIRTenantID.MatchString(tenantID) || strings.TrimSpace(keyID) == "" {
		return nil, nil, ErrIRAttributionNotFound
	}
	filename, err := IRPrivateKeyArtifactFilename(tenantID, keyID)
	if err != nil {
		return nil, nil, ErrIRAttributionNotFound
	}
	artifact, err := readIRPrivateArtifact(filepath.Join(r.directory, filename))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Compatibility for the first single-key artifact format. A legacy
			// file is accepted only when its decrypted public fingerprint still
			// matches the exact requested key ID below.
			artifact, err = readIRPrivateArtifact(
				filepath.Join(r.directory, tenantID+".pem.enc"),
			)
		}
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, nil, ErrIRKeyUnavailable
			}
			return nil, nil, err
		}
	}
	defer crypto.Zeroize(artifact)
	sealed, err := crypto.DecodeSealed(artifact)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: decode encrypted IR private-key artifact: %w", err)
	}
	privatePEM, err := crypto.NewEnvelope(r.unlock).Open(
		ctx,
		sealed,
		irPrivateArtifactAAD(tenantID, keyID),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: open encrypted IR private-key artifact: %w", err)
	}
	defer crypto.Zeroize(privatePEM)
	provider, err := crypto.NewRSAOAEPKeyProviderPEM(privatePEM)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: parse IR private-key artifact: %w", err)
	}
	if provider.KeyID() != keyID {
		provider.Destroy()
		return nil, nil, errors.New(
			"audit: IR private-key artifact does not match the sealed key id",
		)
	}
	return provider, provider.Destroy, nil
}

// IRPrivateKeyArtifactFilename returns the traversal-safe, versioned filename
// for one tenant/key pair. Retaining old versions preserves historical reveal
// after a wrapping-key rotation.
func IRPrivateKeyArtifactFilename(tenantID, keyID string) (string, error) {
	if !canonicalIRTenantID.MatchString(tenantID) ||
		strings.TrimSpace(keyID) == "" {
		return "", errors.New("audit: invalid IR private-key artifact identity")
	}
	keyHash := hex.EncodeToString(crypto.Hash([]byte(keyID)))
	return tenantID + "." + keyHash + ".pem.enc", nil
}

// SealIRPrivateKeyArtifact returns an at-rest-safe artifact for the local
// investigation mount. The plaintext private PEM exists only in caller memory.
func SealIRPrivateKeyArtifact(
	ctx context.Context,
	unlock crypto.KeyProvider,
	tenantID string,
	privatePEM []byte,
) ([]byte, string, error) {
	if unlock == nil {
		return nil, "", errors.New("audit: IR private-artifact unlock provider is required")
	}
	if !canonicalIRTenantID.MatchString(tenantID) {
		return nil, "", errors.New("audit: IR tenant id is not a canonical UUID")
	}
	provider, err := crypto.NewRSAOAEPKeyProviderPEM(privatePEM)
	if err != nil {
		return nil, "", err
	}
	keyID := provider.KeyID()
	provider.Destroy()
	sealed, err := crypto.NewEnvelope(unlock).Seal(
		ctx,
		privatePEM,
		irPrivateArtifactAAD(tenantID, keyID),
	)
	if err != nil {
		return nil, "", fmt.Errorf("audit: seal IR private-key artifact: %w", err)
	}
	encoded, err := sealed.Encode()
	if err != nil {
		return nil, "", fmt.Errorf("audit: encode IR private-key artifact: %w", err)
	}
	return encoded, keyID, nil
}

func irPrivateArtifactAAD(tenantID, keyID string) []byte {
	raw, _ := json.Marshal(struct {
		Domain   string `json:"domain"`
		TenantID string `json:"tenant_id"`
		KeyID    string `json:"key_id"`
	}{
		Domain: irPrivateArtifactDomain, TenantID: tenantID, KeyID: keyID,
	})
	return raw
}

func readIRPrivateArtifact(path string) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return nil, errors.New("audit: IR private-key artifact is not a real regular file")
	}
	if pathInfo.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf(
			"audit: IR private-key artifact permissions are %04o, want 0600",
			pathInfo.Mode().Perm(),
		)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(pathInfo, info) || !info.Mode().IsRegular() {
		return nil, errors.New("audit: IR private-key artifact changed while opening")
	}
	if info.Size() < 1 || info.Size() > maxIRPrivateArtifactBytes {
		return nil, errors.New("audit: IR private-key artifact has invalid size")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxIRPrivateArtifactBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) < 1 || len(raw) > maxIRPrivateArtifactBytes {
		crypto.Zeroize(raw)
		return nil, errors.New("audit: IR private-key artifact changed size while reading")
	}
	return raw, nil
}
