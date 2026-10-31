// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// ReaderHasher is the streaming extension of Provider. A replacement/FIPS
// provider without it refuses streaming digests; it never falls back to a
// different provider behind the deployment's back (docs/guardrails.md G7-3).
type ReaderHasher interface {
	HashReader(io.Reader) ([]byte, error)
}

var ErrStreamingHashUnavailable = errors.New("crypto: configured provider does not support streaming SHA-256")

func (stdProvider) HashReader(reader io.Reader) ([]byte, error) {
	hash := sha256.New()
	if _, err := io.Copy(hash, reader); err != nil {
		return nil, fmt.Errorf("crypto: read digest input: %w", err)
	}
	return hash.Sum(nil), nil
}

func HashReader(reader io.Reader) ([]byte, error) {
	provider, ok := Default.(ReaderHasher)
	if !ok {
		return nil, ErrStreamingHashUnavailable
	}
	return provider.HashReader(reader)
}
