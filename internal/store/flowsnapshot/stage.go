// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowsnapshot

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

type objectRef struct {
	Bytes int64
	Hash  string
}
type privateHeader struct {
	Version            int
	DataKey, CursorKey []byte
	Validity           json.RawMessage
	Objects            []objectRef
}

func (p *privateHeader) zeroize() {
	crypto.Zeroize(p.DataKey)
	crypto.Zeroize(p.CursorKey)
	crypto.Zeroize(p.Validity)
}

type commonHeader struct{ Query, Data json.RawMessage }
type stagedSnapshot struct {
	manifest manifest
	private  privateHeader
	dir      string
}

func (s *stagedSnapshot) close() { s.private.zeroize(); _ = os.RemoveAll(s.dir) }

func privateAAD(m manifest) []byte {
	m.CreatedAt = m.CreatedAt.UTC()
	m.ExpiresAt = m.ExpiresAt.UTC()
	body, _ := json.Marshal(m)
	return append([]byte("probectl.flow-snapshot.private.v1:"), body...)
}

func (s *Service) stage(ctx context.Context, scope Scope, generation int64, required []string, pageSize int, input Input) (*stagedSnapshot, error) {
	if len(input.Rows) > MaxRows || !input.ValidUntil.After(s.now()) || len(input.Validity) > 8192 || !json.Valid(input.Validity) {
		return nil, ErrBudget
	}
	// Bound before encoding or copying. Individual JSON values must be objects;
	// there is no float64 decode/re-encode anywhere in materialized row storage.
	inputBytes := int64(len(input.Query)) + int64(len(input.Header)) + int64(len(input.Validity))
	if !jsonObject(input.Query) || !jsonObject(input.Header) {
		return nil, ErrIntegrity
	}
	for _, row := range input.Rows {
		inputBytes += int64(len(row)) + 1
		if inputBytes > s.config.SnapshotBytes {
			return nil, ErrBudget
		}
		if !jsonObject(row) {
			return nil, ErrIntegrity
		}
	}
	if inputBytes > s.config.SnapshotBytes {
		return nil, ErrBudget
	}
	var query bytes.Buffer
	if err := json.Compact(&query, input.Query); err != nil {
		return nil, ErrIntegrity
	}
	id, err := crypto.UUIDv4()
	if err != nil {
		return nil, err
	}
	lane, err := s.objectLane(ctx, scope.TenantID)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	expires := minTime(now.Add(s.config.Lifetime), input.ValidUntil).UTC().Truncate(time.Microsecond)
	if !expires.After(now) {
		return nil, ErrNotFound
	}
	m := manifest{Scope: scope, ID: id, QueryHash: hex.EncodeToString(crypto.Hash(query.Bytes())), Lane: lane, Generation: generation, CreatedAt: now, ExpiresAt: expires, Rows: len(input.Rows), PageSize: pageSize, Permissions: slices.Clone(required)}
	dir, err := os.MkdirTemp(s.config.TempDir, "probectl-flow-snapshot-")
	if err != nil {
		return nil, err
	}
	staged := &stagedSnapshot{manifest: m, dir: dir, private: privateHeader{Version: 1, Validity: slices.Clone(input.Validity)}}
	success := false
	defer func() {
		if !success {
			staged.close()
		}
	}()
	staged.private.DataKey, err = crypto.Random(crypto.KeySize)
	if err != nil {
		return nil, err
	}
	staged.private.CursorKey, err = crypto.Random(crypto.KeySize)
	if err != nil {
		return nil, err
	}
	var charged int64
	stageObject := func(index int, value any) error {
		plaintext, err := json.Marshal(value)
		if err != nil {
			return err
		}
		defer crypto.Zeroize(plaintext)
		if int64(len(plaintext))+28 > s.config.ObjectBytes {
			return ErrBudget
		}
		ciphertext, err := crypto.Encrypt(staged.private.DataKey, plaintext, objectAAD(m, index))
		if err != nil {
			return err
		}
		defer crypto.Zeroize(ciphertext)
		charged += int64(len(ciphertext))
		if charged > s.config.SnapshotBytes {
			return ErrBudget
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprint(index)), ciphertext, 0600); err != nil {
			return err
		}
		staged.private.Objects = append(staged.private.Objects, objectRef{int64(len(ciphertext)), hex.EncodeToString(crypto.Hash(ciphertext))})
		return nil
	}
	if err := stageObject(0, commonHeader{Query: query.Bytes(), Data: input.Header}); err != nil {
		return nil, err
	}
	for start := 0; start < len(input.Rows); start += chunkRows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		end := min(start+chunkRows, len(input.Rows))
		if err := stageObject(start/chunkRows+1, input.Rows[start:end]); err != nil {
			return nil, err
		}
	}
	privateJSON, err := json.Marshal(staged.private)
	if err != nil {
		return nil, err
	}
	defer crypto.Zeroize(privateJSON)
	sealed, err := s.seal(ctx, scope.TenantID, privateJSON, privateAAD(m))
	if err != nil {
		return nil, err
	}
	if !s.hasScheme(sealed) {
		return nil, ErrEncryption
	}
	if len(sealed) > 65536 {
		return nil, ErrBudget
	}
	staged.manifest.Private = sealed
	// Charge ciphertext, encrypted metadata, public metadata, plus a conservative
	// allowance for the row and index headers; pending rows count identically.
	staged.manifest.ChargedBytes = charged + int64(len(sealed)+len(privateAAD(m))+4096)
	if staged.manifest.ChargedBytes > s.config.SnapshotBytes {
		return nil, ErrBudget
	}
	success = true
	return staged, nil
}

func jsonObject(body []byte) bool {
	body = bytes.TrimSpace(body)
	return len(body) > 1 && body[0] == '{' && json.Valid(body)
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s *Service) openPrivate(ctx context.Context, m manifest) (privateHeader, error) {
	if len(m.Private) > 65536 || !s.hasScheme(m.Private) {
		return privateHeader{}, ErrEncryption
	}
	plaintext, err := s.open(ctx, m.TenantID, m.Private, privateAAD(m))
	if err != nil {
		return privateHeader{}, errors.Join(ErrIntegrity, err)
	}
	defer crypto.Zeroize(plaintext)
	var private privateHeader
	if err := json.Unmarshal(plaintext, &private); err != nil {
		return privateHeader{}, ErrIntegrity
	}
	if private.Version != 1 || len(private.DataKey) != crypto.KeySize || len(private.CursorKey) != crypto.KeySize || len(private.Objects) != 1+(m.Rows+chunkRows-1)/chunkRows || !json.Valid(private.Validity) {
		private.zeroize()
		return privateHeader{}, ErrIntegrity
	}
	return private, nil
}
