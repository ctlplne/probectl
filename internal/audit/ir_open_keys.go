// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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
	"reflect"
	"sort"
	"strings"

	"github.com/ctlplne/probectl/internal/crypto"
)

const (
	irPrivateArtifactDomain     = "probectl-ir-private-artifact-v1"
	irKeyArtifactDestroyDomain  = "probectl-ir-key-artifact-destruction-v1"
	irPublicArtifactIDPrefix    = "public:"
	irPrivateArtifactIDPrefix   = "private:"
	irDestroyingArtifactInfix   = ".destroying-"
	maxIRPrivateArtifactBytes   = 64 << 10
	maxIRArtifactKeyIDs         = 4096
	maxIRArtifactKeyIDBytes     = 256
	irArtifactInventoryPageSize = 256
	// The private key directory is deployment-wide. Inventory permits up to
	// 65,536 aggregate entries before failing closed so unrelated local files
	// cannot force unbounded work or allocation.
	maxIRArtifactInventoryEntries = 65_536
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

// LocalIRKeyArtifactDestroyer inventories and crypto-shreds the exact local
// public/private artifacts for one tenant. It is a separate capability from
// KeyProvider so routine seal/open paths cannot destroy operator-owned keys.
// It performs no network operations.
type LocalIRKeyArtifactDestroyer struct {
	publicDirectory  string
	privateDirectory string
	publicRoot       *os.Root
	privateRoot      *os.Root
}

var _ crypto.KeyArtifactDestroyer = (*LocalIRKeyArtifactDestroyer)(nil)

// NewLocalIRKeyArtifactDestroyer validates the two local key-domain mounts.
// The private mount must be owner-only because it contains encrypted private
// key artifacts that can be opened by the separately held unlock provider.
func NewLocalIRKeyArtifactDestroyer(
	publicDirectory, privateDirectory string,
) (*LocalIRKeyArtifactDestroyer, error) {
	publicDirectory, publicRoot, err := openIRKeyArtifactRoot(
		publicDirectory,
		false,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: invalid IR public-key directory: %w", err)
	}
	privateDirectory, privateRoot, err := openIRKeyArtifactRoot(
		privateDirectory,
		true,
	)
	if err != nil {
		_ = publicRoot.Close()
		return nil, fmt.Errorf("audit: invalid IR private-key directory: %w", err)
	}
	return &LocalIRKeyArtifactDestroyer{
		publicDirectory:  publicDirectory,
		privateDirectory: privateDirectory,
		publicRoot:       publicRoot,
		privateRoot:      privateRoot,
	}, nil
}

// Close releases the two directory handles anchoring this destroyer's key
// domains. The destroyer must not be used after Close.
func (d *LocalIRKeyArtifactDestroyer) Close() error {
	if d == nil {
		return nil
	}
	var first error
	if d.publicRoot != nil {
		first = d.publicRoot.Close()
		d.publicRoot = nil
	}
	if d.privateRoot != nil {
		if err := d.privateRoot.Close(); first == nil {
			first = err
		}
		d.privateRoot = nil
	}
	return first
}

// Inventory returns a canonical, path-free commitment to every exact public,
// legacy-private, and requested versioned-private artifact currently present.
// A tenant-shaped private artifact outside keyIDs fails closed instead of
// silently surviving the destruction plan.
func (d *LocalIRKeyArtifactDestroyer) Inventory(
	ctx context.Context,
	subject string,
	keyIDs []string,
) (crypto.KeyArtifactManifest, error) {
	keyIDs, err := canonicalIRArtifactKeyIDs(keyIDs)
	if err != nil {
		return crypto.KeyArtifactManifest{}, err
	}
	result, err := d.inventory(ctx, subject, keyIDs, nil)
	if err != nil {
		return crypto.KeyArtifactManifest{}, err
	}
	return result.manifest, nil
}

// Destroy removes only the artifacts committed by manifest. Private artifacts
// are first renamed to a deterministic, manifest-specific in-progress name,
// overwritten with internal/crypto randomness, synced, unlinked, and followed
// by a directory sync. The in-progress name makes interruption retryable
// without accepting a changed live artifact.
func (d *LocalIRKeyArtifactDestroyer) Destroy(
	ctx context.Context,
	manifest crypto.KeyArtifactManifest,
) (crypto.KeyArtifactReceipt, error) {
	specs, err := d.validateManifest(manifest)
	if err != nil {
		return crypto.KeyArtifactReceipt{}, err
	}
	manifestHash, err := crypto.HashKeyArtifactManifest(manifest)
	if err != nil {
		return crypto.KeyArtifactReceipt{}, err
	}
	tombstones := make(map[string]localIRKeyArtifactSpec)
	for _, artifact := range manifest.Artifacts {
		spec := specs[artifact.ID]
		if !spec.private {
			continue
		}
		tombstones[irPrivateDestroyTombstoneName(spec.name, manifestHash)] = spec
	}
	current, err := d.inventory(
		ctx,
		manifest.Subject,
		manifest.KeyIDs,
		tombstones,
	)
	if err != nil {
		return crypto.KeyArtifactReceipt{}, err
	}
	planned := make(map[string]string, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		planned[artifact.ID] = artifact.Commitment
	}
	for _, artifact := range current.manifest.Artifacts {
		commitment, ok := planned[artifact.ID]
		if !ok || commitment != artifact.Commitment {
			return crypto.KeyArtifactReceipt{}, fmt.Errorf(
				"%w: live artifact %q differs from the authorized plan",
				crypto.ErrKeyArtifactManifestChanged,
				artifact.ID,
			)
		}
	}

	// Remove the public wrapping key first. A crash can leave private
	// ciphertext for a retry, but routine operation cannot create new records.
	for _, artifact := range manifest.Artifacts {
		spec := specs[artifact.ID]
		if spec.private {
			continue
		}
		if err := removeIRPublicArtifact(
			ctx,
			d.publicRoot,
			spec.name,
			artifact.Commitment,
		); err != nil {
			return crypto.KeyArtifactReceipt{}, err
		}
	}
	for _, artifact := range manifest.Artifacts {
		spec := specs[artifact.ID]
		if !spec.private {
			continue
		}
		tombstone := irPrivateDestroyTombstoneName(spec.name, manifestHash)
		if err := destroyIRPrivateArtifact(
			ctx,
			d.privateRoot,
			spec.name,
			tombstone,
			artifact.Commitment,
		); err != nil {
			return crypto.KeyArtifactReceipt{}, err
		}
	}
	if err := d.VerifyDestroyed(ctx, manifest); err != nil {
		return crypto.KeyArtifactReceipt{}, err
	}
	return crypto.KeyArtifactReceipt{
		ManifestHash: manifestHash,
		Destroyed:    len(manifest.Artifacts),
	}, nil
}

// VerifyDestroyed proves that neither a live artifact nor an interrupted
// private-artifact tombstone from this exact manifest remains.
func (d *LocalIRKeyArtifactDestroyer) VerifyDestroyed(
	ctx context.Context,
	manifest crypto.KeyArtifactManifest,
) error {
	specs, err := d.validateManifest(manifest)
	if err != nil {
		return err
	}
	manifestHash, err := crypto.HashKeyArtifactManifest(manifest)
	if err != nil {
		return err
	}
	tombstones := make(map[string]localIRKeyArtifactSpec)
	for _, artifact := range manifest.Artifacts {
		spec := specs[artifact.ID]
		if spec.private {
			tombstones[irPrivateDestroyTombstoneName(spec.name, manifestHash)] = spec
		}
	}
	current, err := d.inventory(
		ctx,
		manifest.Subject,
		manifest.KeyIDs,
		tombstones,
	)
	if err != nil {
		return err
	}
	if len(current.manifest.Artifacts) != 0 || len(current.tombstones) != 0 {
		return fmt.Errorf(
			"%w: %d live and %d in-progress IR key artifacts remain",
			crypto.ErrKeyArtifactManifestChanged,
			len(current.manifest.Artifacts),
			len(current.tombstones),
		)
	}
	return nil
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

type localIRKeyArtifactSpec struct {
	id      string
	name    string
	private bool
}

type localIRKeyArtifactInventory struct {
	manifest   crypto.KeyArtifactManifest
	tombstones map[string]struct{}
}

func readBoundedIRPrivateDirectory(
	ctx context.Context,
	readDir func(int) ([]os.DirEntry, error),
) ([]os.DirEntry, error) {
	entriesToVisit := make([]os.DirEntry, 0, irArtifactInventoryPageSize)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries, readErr := readDir(irArtifactInventoryPageSize)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return nil, fmt.Errorf(
				"audit: read IR private-key directory: %w",
				readErr,
			)
		}
		if len(entries) == 0 {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return nil, fmt.Errorf(
				"audit: read IR private-key directory: %w",
				io.ErrNoProgress,
			)
		}
		if len(entries) > maxIRArtifactInventoryEntries-len(entriesToVisit) {
			return nil, fmt.Errorf(
				"audit: IR private-key directory exceeds %d entries",
				maxIRArtifactInventoryEntries,
			)
		}
		entriesToVisit = append(entriesToVisit, entries...)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	return entriesToVisit, nil
}

func validateIRKeyArtifactDirectory(
	directory string,
	ownerOnly bool,
) (string, error) {
	directory = filepath.Clean(strings.TrimSpace(directory))
	if directory == "." || !filepath.IsAbs(directory) {
		return "", errors.New("directory must be an absolute path")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return "", err
	}
	if err := validateIRKeyArtifactDirectoryInfo(info, ownerOnly); err != nil {
		return "", err
	}
	return directory, nil
}

func openIRKeyArtifactRoot(
	directory string,
	ownerOnly bool,
) (string, *os.Root, error) {
	directory, err := validateIRKeyArtifactDirectory(directory, ownerOnly)
	if err != nil {
		return "", nil, err
	}
	pathInfo, err := os.Lstat(directory)
	if err != nil {
		return "", nil, err
	}
	if err := validateIRKeyArtifactDirectoryInfo(pathInfo, ownerOnly); err != nil {
		return "", nil, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return "", nil, err
	}
	rootInfo, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return "", nil, err
	}
	if !os.SameFile(pathInfo, rootInfo) {
		_ = root.Close()
		return "", nil, errors.New("directory changed while anchoring it")
	}
	if err := validateIRKeyArtifactDirectoryInfo(rootInfo, ownerOnly); err != nil {
		_ = root.Close()
		return "", nil, err
	}
	return directory, root, nil
}

func validateIRKeyArtifactDirectoryInfo(
	info os.FileInfo,
	ownerOnly bool,
) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("path must be a real directory")
	}
	if ownerOnly && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf(
			"permissions are %04o, want owner-only",
			info.Mode().Perm(),
		)
	}
	if !ownerOnly && info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf(
			"permissions are %04o, want no group/world write access",
			info.Mode().Perm(),
		)
	}
	return nil
}

func validateIRKeyArtifactRootIdentity(
	directory string,
	root *os.Root,
	ownerOnly bool,
) error {
	if root == nil || directory == "" {
		return errors.New("anchored directory is unavailable")
	}
	pathInfo, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if err := validateIRKeyArtifactDirectoryInfo(pathInfo, ownerOnly); err != nil {
		return err
	}
	rootInfo, err := root.Stat(".")
	if err != nil {
		return err
	}
	if err := validateIRKeyArtifactDirectoryInfo(rootInfo, ownerOnly); err != nil {
		return err
	}
	if !os.SameFile(pathInfo, rootInfo) {
		return fmt.Errorf(
			"%w: configured key directory no longer matches its anchored mount",
			crypto.ErrKeyArtifactManifestChanged,
		)
	}
	return nil
}

func canonicalIRArtifactKeyIDs(keyIDs []string) ([]string, error) {
	if len(keyIDs) > maxIRArtifactKeyIDs {
		return nil, errors.New("audit: too many IR key artifact ids")
	}
	for _, keyID := range keyIDs {
		if keyID == "" ||
			len(keyID) > maxIRArtifactKeyIDBytes ||
			strings.TrimSpace(keyID) != keyID {
			return nil, errors.New("audit: IR key artifact id is not canonical")
		}
	}
	canonical := append([]string(nil), keyIDs...)
	sort.Strings(canonical)
	write := 0
	for _, keyID := range canonical {
		if write > 0 && canonical[write-1] == keyID {
			continue
		}
		canonical[write] = keyID
		write++
	}
	return canonical[:write], nil
}

func (d *LocalIRKeyArtifactDestroyer) validateManifest(
	manifest crypto.KeyArtifactManifest,
) (map[string]localIRKeyArtifactSpec, error) {
	if d == nil || d.publicRoot == nil || d.privateRoot == nil {
		return nil, errors.New("audit: IR key artifact destroyer is unavailable")
	}
	if manifest.Domain != irKeyArtifactDestroyDomain ||
		!canonicalIRTenantID.MatchString(manifest.Subject) {
		return nil, fmt.Errorf(
			"%w: IR key artifact domain or subject is invalid",
			crypto.ErrKeyArtifactManifestChanged,
		)
	}
	if err := crypto.ValidateKeyArtifactManifest(manifest); err != nil {
		return nil, err
	}
	specs, _, err := d.irArtifactSpecs(manifest.Subject, manifest.KeyIDs)
	if err != nil {
		return nil, err
	}
	for _, artifact := range manifest.Artifacts {
		if _, ok := specs[artifact.ID]; !ok {
			return nil, fmt.Errorf(
				"%w: artifact %q is outside the exact IR key plan",
				crypto.ErrKeyArtifactManifestChanged,
				artifact.ID,
			)
		}
	}
	return specs, nil
}

func (d *LocalIRKeyArtifactDestroyer) inventory(
	ctx context.Context,
	subject string,
	keyIDs []string,
	allowedTombstones map[string]localIRKeyArtifactSpec,
) (localIRKeyArtifactInventory, error) {
	if ctx == nil {
		return localIRKeyArtifactInventory{}, errors.New("audit: context is required")
	}
	if err := ctx.Err(); err != nil {
		return localIRKeyArtifactInventory{}, err
	}
	if d == nil || d.publicRoot == nil || d.privateRoot == nil {
		return localIRKeyArtifactInventory{}, errors.New(
			"audit: IR key artifact destroyer is unavailable",
		)
	}
	if !canonicalIRTenantID.MatchString(subject) {
		return localIRKeyArtifactInventory{}, errors.New(
			"audit: IR key artifact subject is not a canonical tenant UUID",
		)
	}
	if err := validateIRKeyArtifactRootIdentity(
		d.publicDirectory,
		d.publicRoot,
		false,
	); err != nil {
		return localIRKeyArtifactInventory{}, fmt.Errorf(
			"audit: inspect IR public-key directory: %w",
			err,
		)
	}
	if err := validateIRKeyArtifactRootIdentity(
		d.privateDirectory,
		d.privateRoot,
		true,
	); err != nil {
		return localIRKeyArtifactInventory{}, fmt.Errorf(
			"audit: inspect IR private-key directory: %w",
			err,
		)
	}
	specs, privateNames, err := d.irArtifactSpecs(subject, keyIDs)
	if err != nil {
		return localIRKeyArtifactInventory{}, err
	}
	artifacts := make([]crypto.KeyArtifact, 0, len(specs))
	publicSpec := specs[irPublicArtifactIDPrefix+subject+".pem"]
	publicCommitment, present, err := commitIRArtifactIfPresent(
		d.publicRoot,
		publicSpec.name,
		false,
	)
	if err != nil {
		return localIRKeyArtifactInventory{}, err
	}
	if present {
		artifacts = append(artifacts, crypto.KeyArtifact{
			ID:         publicSpec.id,
			Commitment: publicCommitment,
		})
	}

	privateDirectory, err := d.privateRoot.Open(".")
	if err != nil {
		return localIRKeyArtifactInventory{}, fmt.Errorf(
			"audit: open anchored IR private-key directory: %w",
			err,
		)
	}
	entries, readErr := readBoundedIRPrivateDirectory(
		ctx,
		privateDirectory.ReadDir,
	)
	closeErr := privateDirectory.Close()
	if readErr != nil {
		return localIRKeyArtifactInventory{}, readErr
	}
	if closeErr != nil {
		return localIRKeyArtifactInventory{}, closeErr
	}
	seenTombstones := make(map[string]struct{})
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return localIRKeyArtifactInventory{}, err
		}
		name := entry.Name()
		if spec, ok := privateNames[name]; ok {
			commitment, present, err := commitIRArtifactIfPresent(
				d.privateRoot,
				spec.name,
				true,
			)
			if err != nil {
				return localIRKeyArtifactInventory{}, err
			}
			if present {
				artifacts = append(artifacts, crypto.KeyArtifact{
					ID:         spec.id,
					Commitment: commitment,
				})
			}
			continue
		}
		if _, ok := allowedTombstones[name]; ok {
			file, _, _, err := openCommittedIRArtifact(
				d.privateRoot,
				name,
				true,
				os.O_RDONLY,
			)
			if err != nil {
				return localIRKeyArtifactInventory{}, err
			}
			if err := file.Close(); err != nil {
				return localIRKeyArtifactInventory{}, err
			}
			seenTombstones[name] = struct{}{}
			continue
		}
		if isTenantIRPrivateArtifactName(subject, name) {
			return localIRKeyArtifactInventory{}, fmt.Errorf(
				"%w: unexpected tenant private artifact %q",
				crypto.ErrKeyArtifactManifestChanged,
				name,
			)
		}
	}
	sort.Slice(artifacts, func(i, j int) bool {
		return artifacts[i].ID < artifacts[j].ID
	})
	manifest := crypto.KeyArtifactManifest{
		Domain:    irKeyArtifactDestroyDomain,
		Subject:   subject,
		KeyIDs:    append([]string(nil), keyIDs...),
		Artifacts: artifacts,
	}
	if err := crypto.ValidateKeyArtifactManifest(manifest); err != nil {
		return localIRKeyArtifactInventory{}, err
	}
	if err := validateIRKeyArtifactRootIdentity(
		d.publicDirectory,
		d.publicRoot,
		false,
	); err != nil {
		return localIRKeyArtifactInventory{}, err
	}
	if err := validateIRKeyArtifactRootIdentity(
		d.privateDirectory,
		d.privateRoot,
		true,
	); err != nil {
		return localIRKeyArtifactInventory{}, err
	}
	return localIRKeyArtifactInventory{
		manifest:   manifest,
		tombstones: seenTombstones,
	}, nil
}

func (d *LocalIRKeyArtifactDestroyer) irArtifactSpecs(
	subject string,
	keyIDs []string,
) (
	map[string]localIRKeyArtifactSpec,
	map[string]localIRKeyArtifactSpec,
	error,
) {
	specs := make(map[string]localIRKeyArtifactSpec, len(keyIDs)+2)
	privateNames := make(map[string]localIRKeyArtifactSpec, len(keyIDs)+1)
	add := func(name string, private bool) error {
		prefix := irPublicArtifactIDPrefix
		if private {
			prefix = irPrivateArtifactIDPrefix
		}
		spec := localIRKeyArtifactSpec{
			id:      prefix + name,
			name:    name,
			private: private,
		}
		if _, exists := specs[spec.id]; exists {
			return fmt.Errorf(
				"%w: duplicate exact IR key artifact %q",
				crypto.ErrKeyArtifactManifestChanged,
				spec.id,
			)
		}
		specs[spec.id] = spec
		if private {
			privateNames[name] = spec
		}
		return nil
	}
	if err := add(subject+".pem", false); err != nil {
		return nil, nil, err
	}
	if err := add(subject+".pem.enc", true); err != nil {
		return nil, nil, err
	}
	for _, keyID := range keyIDs {
		name, err := IRPrivateKeyArtifactFilename(subject, keyID)
		if err != nil {
			return nil, nil, err
		}
		if _, exists := privateNames[name]; exists {
			return nil, nil, fmt.Errorf(
				"%w: colliding exact IR private artifact %q",
				crypto.ErrKeyArtifactManifestChanged,
				name,
			)
		}
		if err := add(name, true); err != nil {
			return nil, nil, err
		}
	}
	return specs, privateNames, nil
}

func isTenantIRPrivateArtifactName(subject, name string) bool {
	if name == subject+".pem.enc" {
		return true
	}
	return strings.HasPrefix(name, subject+".") &&
		strings.Contains(name, ".pem.enc")
}

func irPrivateDestroyTombstoneName(name, manifestHash string) string {
	return name + irDestroyingArtifactInfix + manifestHash
}

func commitIRArtifactIfPresent(
	root *os.Root,
	name string,
	private bool,
) (string, bool, error) {
	file, _, commitment, err := openCommittedIRArtifact(
		root,
		name,
		private,
		os.O_RDONLY,
	)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	if err := file.Close(); err != nil {
		return "", false, err
	}
	return commitment, true, nil
}

func openCommittedIRArtifact(
	root *os.Root,
	name string,
	private bool,
	flag int,
) (*os.File, os.FileInfo, string, error) {
	pathInfo, err := root.Lstat(name)
	if err != nil {
		return nil, nil, "", err
	}
	if err := validateIRArtifactInfo(pathInfo, private); err != nil {
		return nil, nil, "", err
	}
	file, err := root.OpenFile(name, flag, 0)
	if err != nil {
		return nil, nil, "", err
	}
	fail := func(cause error) (*os.File, os.FileInfo, string, error) {
		_ = file.Close()
		return nil, nil, "", cause
	}
	info, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	if !os.SameFile(pathInfo, info) {
		return fail(errors.New("audit: IR key artifact changed while opening"))
	}
	if err := validateIRArtifactInfo(info, private); err != nil {
		return fail(err)
	}
	maxBytes := int64(maxIRPublicKeyBytes)
	if private {
		maxBytes = maxIRPrivateArtifactBytes
	}
	if info.Size() < 1 || info.Size() > maxBytes {
		return fail(errors.New("audit: IR key artifact has invalid size"))
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return fail(err)
	}
	if int64(len(raw)) != info.Size() {
		crypto.Zeroize(raw)
		return fail(errors.New("audit: IR key artifact changed size while reading"))
	}
	commitment := hex.EncodeToString(crypto.Hash(raw))
	crypto.Zeroize(raw)
	endInfo, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	if !os.SameFile(info, endInfo) || endInfo.Size() != info.Size() {
		return fail(errors.New("audit: IR key artifact changed while reading"))
	}
	return file, info, commitment, nil
}

func validateIRArtifactInfo(info os.FileInfo, private bool) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("audit: IR key artifact is not a real regular file")
	}
	if private && info.Mode().Perm() != 0o600 {
		return fmt.Errorf(
			"audit: IR private-key artifact permissions are %04o, want 0600",
			info.Mode().Perm(),
		)
	}
	links, ok := irArtifactLinkCount(info)
	if !ok {
		return errors.New("audit: cannot verify IR key artifact link count")
	}
	if links != 1 {
		return fmt.Errorf(
			"audit: IR key artifact has %d hard links, want exactly one",
			links,
		)
	}
	return nil
}

func irArtifactLinkCount(info os.FileInfo) (uint64, bool) {
	if info == nil || info.Sys() == nil {
		return 0, false
	}
	value := reflect.ValueOf(info.Sys())
	for value.IsValid() && value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return 0, false
		}
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return 0, false
	}
	field := value.FieldByName("Nlink")
	if !field.IsValid() {
		return 0, false
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return field.Uint(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if field.Int() < 0 {
			return 0, false
		}
		return uint64(field.Int()), true
	default:
		return 0, false
	}
}

func removeIRPublicArtifact(
	ctx context.Context,
	root *os.Root,
	name, expectedCommitment string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	file, info, commitment, err := openCommittedIRArtifact(
		root,
		name,
		false,
		os.O_RDONLY,
	)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return syncIRArtifactDirectory(root)
		}
		return err
	}
	if commitment != expectedCommitment {
		_ = file.Close()
		return fmt.Errorf(
			"%w: public IR key artifact changed",
			crypto.ErrKeyArtifactManifestChanged,
		)
	}
	if err := verifyCurrentIRArtifactPath(root, name, info, false); err != nil {
		_ = file.Close()
		return err
	}
	if err := root.Remove(name); err != nil {
		_ = file.Close()
		if errors.Is(err, os.ErrNotExist) {
			return syncIRArtifactDirectory(root)
		}
		return err
	}
	syncErr := syncIRArtifactDirectory(root)
	closeErr := file.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func destroyIRPrivateArtifact(
	ctx context.Context,
	root *os.Root,
	name, tombstone, expectedCommitment string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	pathInfo, pathErr := root.Lstat(name)
	_, tombstoneErr := root.Lstat(tombstone)
	pathPresent := pathErr == nil
	tombstonePresent := tombstoneErr == nil
	if pathErr != nil && !errors.Is(pathErr, os.ErrNotExist) {
		return pathErr
	}
	if tombstoneErr != nil && !errors.Is(tombstoneErr, os.ErrNotExist) {
		return tombstoneErr
	}
	if pathPresent && tombstonePresent {
		return fmt.Errorf(
			"%w: live and in-progress private IR key artifacts both exist",
			crypto.ErrKeyArtifactManifestChanged,
		)
	}
	var (
		file *os.File
		info os.FileInfo
		err  error
	)
	if pathPresent {
		if err := validateIRArtifactInfo(pathInfo, true); err != nil {
			return err
		}
		var commitment string
		file, info, commitment, err = openCommittedIRArtifact(
			root,
			name,
			true,
			os.O_RDWR,
		)
		if err != nil {
			return err
		}
		if commitment != expectedCommitment {
			_ = file.Close()
			return fmt.Errorf(
				"%w: private IR key artifact changed",
				crypto.ErrKeyArtifactManifestChanged,
			)
		}
		if err := verifyCurrentIRArtifactPath(root, name, info, true); err != nil {
			_ = file.Close()
			return err
		}
		if err := root.Rename(name, tombstone); err != nil {
			_ = file.Close()
			return err
		}
		if err := verifyCurrentIRArtifactPath(
			root,
			tombstone,
			info,
			true,
		); err != nil {
			_ = file.Close()
			return err
		}
		if err := syncIRArtifactDirectory(root); err != nil {
			_ = file.Close()
			return err
		}
		tombstonePresent = true
	}
	if !tombstonePresent {
		return syncIRArtifactDirectory(root)
	}

	if file == nil {
		file, info, _, err = openCommittedIRArtifact(
			root,
			tombstone,
			true,
			os.O_RDWR,
		)
		if err != nil {
			return err
		}
	}
	random, err := crypto.Random(int(info.Size()))
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("audit: randomize IR private-key artifact: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		crypto.Zeroize(random)
		_ = file.Close()
		return err
	}
	err = writeAllIRArtifact(file, random)
	crypto.Zeroize(random)
	if err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := verifyCurrentIRArtifactPath(
		root,
		tombstone,
		info,
		true,
	); err != nil {
		_ = file.Close()
		return err
	}
	if err := root.Remove(tombstone); err != nil {
		_ = file.Close()
		if errors.Is(err, os.ErrNotExist) {
			return syncIRArtifactDirectory(root)
		}
		return err
	}
	syncErr := syncIRArtifactDirectory(root)
	closeErr := file.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func writeAllIRArtifact(file *os.File, raw []byte) error {
	for len(raw) > 0 {
		written, err := file.Write(raw)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		raw = raw[written:]
	}
	return nil
}

func verifyCurrentIRArtifactPath(
	root *os.Root,
	name string,
	openedInfo os.FileInfo,
	private bool,
) error {
	current, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !os.SameFile(openedInfo, current) {
		return errors.New("audit: IR key artifact path changed during operation")
	}
	return validateIRArtifactInfo(current, private)
}

func syncIRArtifactDirectory(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
