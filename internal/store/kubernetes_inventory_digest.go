// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type kubernetesInventoryPartReader struct {
	rows           pgx.Rows
	expectedParts  int64
	remainingBytes int64
	next           int64
	current        io.Reader
}

// Read frames the retained byte stream while checking the exact stored part
// indexes and total bytes. Only one part is held while hashing a generation.
func (r *kubernetesInventoryPartReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if r.current != nil {
			n, err := r.current.Read(p)
			if !errors.Is(err, io.EOF) {
				return n, err
			}
			r.current = nil
			if n > 0 {
				return n, nil
			}
		}
		if !r.rows.Next() {
			if err := r.rows.Err(); err != nil {
				return 0, err
			}
			if r.next != r.expectedParts || r.remainingBytes != 0 {
				return 0, ErrKubernetesInventoryOrder
			}
			return 0, io.EOF
		}
		var index int64
		var wire []byte
		if err := r.rows.Scan(&index, &wire); err != nil {
			return 0, err
		}
		if index != r.next || r.next >= r.expectedParts || len(wire) == 0 || int64(len(wire)) > r.remainingBytes {
			return 0, ErrKubernetesInventoryOrder
		}
		r.next++
		r.remainingBytes -= int64(len(wire))
		r.current = entity.FrameKubernetesInventoryRecord(wire)
	}
}

// verifyKubernetesInventoryUpload reads the staging row under the caller's
// tenant and locks the complete stage while validating its retained originals.
// Publication must run in the same transaction before releasing this lock.
func verifyKubernetesInventoryUpload(ctx context.Context, sc tenancy.Scope, authority kubernetesUploadScope) ([]byte, []byte, error) {
	tenant, bound := tenancy.FromContext(ctx)
	if !bound || tenant != sc.Tenant || tenant.String() != authority.TenantID || sc.Q == nil {
		return nil, nil, ErrKubernetesInventoryAuthority
	}
	key := []any{authority.TenantID, authority.ContextID, authority.BindingID, authority.GenerationID}
	var manifest, digest []byte
	reader := kubernetesInventoryPartReader{}
	err := sc.Q.QueryRow(ctx, `
SELECT manifest,payload_digest,expected_parts,expected_bytes
FROM kubernetes_inventory_staging
WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3 AND generation_id=$4
  AND sender_serial=$5 AND expires_at>clock_timestamp()
  AND next_part=expected_parts AND appended_rows=expected_rows AND appended_bytes=expected_bytes
FOR UPDATE`, append(key, authority.Serial)...).
		Scan(&manifest, &digest, &reader.expectedParts, &reader.remainingBytes)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrKubernetesInventoryOrder
	}
	if err != nil {
		return nil, nil, err
	}
	rows, err := sc.Q.Query(ctx, `
SELECT part_index,original_wire FROM kubernetes_inventory_stage_parts
WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3 AND generation_id=$4 ORDER BY part_index`, key...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	reader.rows = rows
	calculated, err := entity.HashKubernetesInventory(manifest, &reader)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(calculated, digest) {
		return nil, nil, ErrKubernetesInventoryConflict
	}
	return manifest, calculated, nil
}
