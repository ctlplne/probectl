// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package deliveryaudit

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	probcrypto "github.com/ctlplne/probectl/internal/crypto"
)

const (
	maxArtifactCount = 128
	maxArtifactBytes = 128 << 20
	maxArtifactTotal = 512 << 20
)

func digestBytes(data []byte) string {
	return "sha256:" + hex.EncodeToString(probcrypto.Hash(data))
}

// bindArtifactSnapshot reads every artifact once. The exact byte slice used to
// calculate signed size/hash metadata is retained for every artifact whose
// contents participate in semantic promotion checks.
func bindArtifactSnapshot(receipt Receipt, root string) (Receipt, map[string]semanticArtifactResult, error) {
	if len(receipt.Artifacts) == 0 {
		return Receipt{}, nil, errors.New("delivery audit: at least one artifact is required")
	}
	if len(receipt.Artifacts) > maxArtifactCount {
		return Receipt{}, nil, fmt.Errorf("delivery audit: artifact count %d exceeds limit %d", len(receipt.Artifacts), maxArtifactCount)
	}
	bound := append([]Artifact(nil), receipt.Artifacts...)
	seen := make(map[string]bool, len(bound))
	snapshot := make(map[string]semanticArtifactResult, len(bound))
	var total int64
	for i := range bound {
		if !validArtifactKind(bound[i].Kind) {
			return Receipt{}, nil, fmt.Errorf("delivery audit: artifact %q has unsupported kind %q", bound[i].Path, bound[i].Kind)
		}
		clean, data, info, err := readBoundedWithinRoot(root, bound[i].Path, maxArtifactBytes)
		if err != nil {
			return Receipt{}, nil, fmt.Errorf("delivery audit: artifact %q: %w", bound[i].Path, err)
		}
		if seen[clean] {
			return Receipt{}, nil, fmt.Errorf("delivery audit: duplicate artifact path %q", clean)
		}
		seen[clean] = true
		total += info.Size()
		if total > maxArtifactTotal {
			return Receipt{}, nil, fmt.Errorf("delivery audit: artifact bytes exceed total limit %d", maxArtifactTotal)
		}
		retainSemanticArtifact(snapshot, clean, bound[i].Kind, data)
		bound[i].Path = clean
		bound[i].Bytes = info.Size()
		bound[i].SHA256 = digestBytes(data)
	}
	sort.Slice(bound, func(i, j int) bool { return bound[i].Path < bound[j].Path })
	receipt.Artifacts = bound
	return receipt, snapshot, nil
}

func verifyArtifacts(receipt Receipt, root string) (map[string]semanticArtifactResult, error) {
	if len(receipt.Artifacts) == 0 || len(receipt.Artifacts) > maxArtifactCount {
		return nil, errors.New("delivery audit: invalid artifact count")
	}
	seen := make(map[string]bool, len(receipt.Artifacts))
	snapshot := make(map[string]semanticArtifactResult, len(receipt.Artifacts))
	var total int64
	for _, artifact := range receipt.Artifacts {
		if !validArtifactKind(artifact.Kind) {
			return nil, fmt.Errorf("delivery audit: artifact %q has unsupported kind %q", artifact.Path, artifact.Kind)
		}
		clean, data, info, err := readBoundedWithinRoot(root, artifact.Path, maxArtifactBytes)
		if err != nil {
			return nil, fmt.Errorf("delivery audit: artifact %q: %w", artifact.Path, err)
		}
		if clean != artifact.Path {
			return nil, fmt.Errorf("delivery audit: artifact path %q is not canonical", artifact.Path)
		}
		if seen[clean] {
			return nil, fmt.Errorf("delivery audit: duplicate artifact path %q", clean)
		}
		seen[clean] = true
		total += info.Size()
		if total > maxArtifactTotal {
			return nil, fmt.Errorf("delivery audit: artifact bytes exceed total limit %d", maxArtifactTotal)
		}
		if artifact.Bytes != info.Size() {
			return nil, fmt.Errorf("delivery audit: artifact %q size mismatch", clean)
		}
		if artifact.SHA256 != digestBytes(data) {
			return nil, fmt.Errorf("delivery audit: artifact %q digest mismatch", clean)
		}
		retainSemanticArtifact(snapshot, clean, artifact.Kind, data)
	}
	return snapshot, nil
}

func retainSemanticArtifact(snapshot map[string]semanticArtifactResult, path string, kind ArtifactKind, data []byte) {
	limit := int64(maxSemanticArtifactBytes)
	if kind == ArtifactUIScreenshot {
		limit = maxScreenshotBytes
	}
	if int64(len(data)) > limit {
		snapshot[path] = semanticArtifactResult{err: fmt.Errorf("file exceeds semantic evidence limit %d", limit)}
		return
	}
	snapshot[path] = semanticArtifactResult{data: data}
}

func validArtifactKind(kind ArtifactKind) bool {
	switch kind {
	case ArtifactCLITranscript, ArtifactUIScreenshot, ArtifactBrowserNetwork,
		ArtifactStoreProbes, ArtifactTLSTrust, ArtifactStackInventory,
		ArtifactLinterOutput, ArtifactReachability, ArtifactActivation,
		ArtifactGovernedReview, ArtifactCertManifest, ArtifactPublicCert,
		ArtifactNegativeReceipt, ArtifactNegativeFixture, ArtifactCLIOutput,
		ArtifactAPIObservation, ArtifactProductPipeline, ArtifactOTLPRequest,
		ArtifactOTLPResponse, ArtifactKafkaKey, ArtifactKafkaPayload, ArtifactStoreObservation,
		ArtifactPipelineCounters, ArtifactKafkaGroupOffset, ArtifactKafkaGroupRaw, ArtifactOther:
		return true
	case ArtifactClickHouseIsolation, ArtifactClickHouseIsolationRaw:
		return true
	default:
		return false
	}
}

// readBoundedWithinRoot opens through a rooted directory handle, so a racing
// symlink cannot redirect the read outside root. Pre/post Lstat and descriptor
// identity checks preserve the stricter no-symlink artifact contract too.
func readBoundedWithinRoot(root, relative string, limit int64) (string, []byte, os.FileInfo, error) {
	if strings.TrimSpace(relative) == "" || filepath.IsAbs(relative) {
		return "", nil, nil, errors.New("path must be a non-empty relative path")
	}
	clean := filepath.Clean(relative)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", nil, nil, errors.New("path traversal is not allowed")
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", nil, nil, fmt.Errorf("resolve artifact root: %w", err)
	}
	rootBefore, err := os.Lstat(rootAbs)
	if err != nil || rootBefore.Mode()&os.ModeSymlink != 0 || !rootBefore.IsDir() {
		return "", nil, nil, errors.New("artifact root must be a real directory, not a symlink")
	}
	rooted, err := os.OpenRoot(rootAbs)
	if err != nil {
		return "", nil, nil, err
	}
	defer rooted.Close()
	rootHandle, err := rooted.Stat(".")
	if err != nil || !os.SameFile(rootBefore, rootHandle) {
		return "", nil, nil, errors.New("artifact root identity changed while opening")
	}
	current := ""
	for _, component := range strings.Split(clean, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, lerr := rooted.Lstat(current)
		if lerr != nil {
			return "", nil, nil, lerr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", nil, nil, fmt.Errorf("symlink component %q is not allowed", component)
		}
	}
	f, err := rooted.Open(clean)
	if err != nil {
		return "", nil, nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() {
		return "", nil, nil, errors.New("artifact must be a regular file")
	}
	linked, err := rooted.Lstat(clean)
	if err != nil || linked.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, linked) {
		return "", nil, nil, errors.New("artifact identity changed while opening")
	}
	if opened.Size() > limit {
		return "", nil, nil, fmt.Errorf("file is %d bytes; limit is %d", opened.Size(), limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return "", nil, nil, fmt.Errorf("file exceeds %d-byte limit", limit)
	}
	openedAfter, statErr := f.Stat()
	linkedAfter, lstatErr := rooted.Lstat(clean)
	rootAfter, rootErr := rooted.Stat(".")
	if statErr != nil || lstatErr != nil || rootErr != nil || linkedAfter.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(opened, openedAfter) || !os.SameFile(opened, linkedAfter) || !os.SameFile(rootBefore, rootAfter) ||
		openedAfter.Size() != int64(len(data)) {
		return "", nil, nil, errors.New("artifact or root identity changed during read")
	}
	return filepath.ToSlash(clean), data, openedAfter, nil
}

func readBoundedRegular(path string, limit int64) ([]byte, os.FileInfo, error) {
	linkedBefore, err := os.Lstat(path)
	if err != nil || linkedBefore.Mode()&os.ModeSymlink != 0 || !linkedBefore.Mode().IsRegular() {
		return nil, nil, errors.New("not a regular non-symlink file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, errors.New("not a regular file")
	}
	if !os.SameFile(linkedBefore, info) {
		return nil, nil, errors.New("file identity changed while opening")
	}
	if info.Size() > limit {
		return nil, nil, fmt.Errorf("file is %d bytes; limit is %d", info.Size(), limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > limit {
		return nil, nil, fmt.Errorf("file exceeds %d-byte limit", limit)
	}
	infoAfter, statErr := f.Stat()
	linkedAfter, lstatErr := os.Lstat(path)
	if statErr != nil || lstatErr != nil || linkedAfter.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(info, infoAfter) || !os.SameFile(info, linkedAfter) || infoAfter.Size() != int64(len(data)) {
		return nil, nil, errors.New("file identity changed during read")
	}
	return data, infoAfter, nil
}
