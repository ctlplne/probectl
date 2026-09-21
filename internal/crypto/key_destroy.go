// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

const (
	maxKeyArtifactIdentityBytes = 256
	maxKeyArtifactsPerManifest  = 1024
	maxKeyArtifactManifestBytes = 60 << 10
)

// ErrKeyArtifactManifestChanged means the operator-owned key domain differs
// from the exact durable plan. Destruction must stop rather than widen its
// target set after authorization.
var ErrKeyArtifactManifestChanged = errors.New("crypto: key artifact manifest changed")

// KeyArtifact is one opaque, exact artifact commitment. ID is a logical
// identifier, never a filesystem path or key value; Commitment is the
// lowercase SHA-256 of the artifact bytes.
type KeyArtifact struct {
	ID         string `json:"id"`
	Commitment string `json:"commitment"`
}

// KeyArtifactManifest is the canonical, key-material-free destruction plan
// passed through the crypto boundary. KeyIDs and Artifacts must be sorted and
// unique so the signed representation has exactly one encoding.
type KeyArtifactManifest struct {
	Domain    string        `json:"domain"`
	Subject   string        `json:"subject"`
	KeyIDs    []string      `json:"key_ids"`
	Artifacts []KeyArtifact `json:"artifacts"`
}

// KeyArtifactReceipt is the non-secret proof returned after the exact planned
// artifacts are absent.
type KeyArtifactReceipt struct {
	ManifestHash string `json:"manifest_hash"`
	Destroyed    int    `json:"destroyed"`
}

// KeyArtifactDestroyer is deliberately separate from KeyProvider. Routine
// wrapping/unwrapping code therefore never receives destructive authority.
type KeyArtifactDestroyer interface {
	Inventory(
		context.Context,
		string,
		[]string,
	) (KeyArtifactManifest, error)
	Destroy(context.Context, KeyArtifactManifest) (KeyArtifactReceipt, error)
	VerifyDestroyed(context.Context, KeyArtifactManifest) error
}

// ValidateKeyArtifactManifest validates the bounded canonical shape used by a
// signed destruction plan. It does not inspect or resolve the artifacts.
func ValidateKeyArtifactManifest(manifest KeyArtifactManifest) error {
	if strings.TrimSpace(manifest.Domain) == "" ||
		len(manifest.Domain) > maxKeyArtifactIdentityBytes ||
		strings.TrimSpace(manifest.Subject) == "" ||
		len(manifest.Subject) > maxKeyArtifactIdentityBytes {
		return errors.New("crypto: key artifact manifest identity is invalid")
	}
	if len(manifest.KeyIDs) > maxKeyArtifactsPerManifest ||
		len(manifest.Artifacts) > maxKeyArtifactsPerManifest {
		return errors.New("crypto: key artifact manifest exceeds bounded shape")
	}
	if !sort.StringsAreSorted(manifest.KeyIDs) {
		return errors.New("crypto: key artifact key ids are not canonical")
	}
	for index, keyID := range manifest.KeyIDs {
		if strings.TrimSpace(keyID) == "" ||
			len(keyID) > maxKeyArtifactIdentityBytes ||
			(index > 0 && keyID == manifest.KeyIDs[index-1]) {
			return errors.New("crypto: key artifact key id is invalid")
		}
	}
	previous := ""
	for _, artifact := range manifest.Artifacts {
		if strings.TrimSpace(artifact.ID) == "" ||
			len(artifact.ID) > maxKeyArtifactIdentityBytes ||
			artifact.ID <= previous ||
			!lowerHexDigest(artifact.Commitment) {
			return errors.New("crypto: key artifact entry is not canonical")
		}
		previous = artifact.ID
	}
	raw, err := json.Marshal(manifest)
	if err != nil || len(raw) > maxKeyArtifactManifestBytes {
		return errors.New("crypto: key artifact manifest exceeds bounded encoding")
	}
	return nil
}

// HashKeyArtifactManifest returns the canonical SHA-256 commitment used by
// signed plans and destruction receipts.
func HashKeyArtifactManifest(manifest KeyArtifactManifest) (string, error) {
	if err := ValidateKeyArtifactManifest(manifest); err != nil {
		return "", err
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(Hash(raw)), nil
}

func lowerHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}
