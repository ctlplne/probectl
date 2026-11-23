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
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var (
	ErrKubernetesInventoryAuthority = errors.New("kubernetes inventory source authority is inactive")
	ErrKubernetesInventoryOrder     = errors.New("kubernetes inventory part is outside the current upload")
	ErrKubernetesInventoryConflict  = errors.New("kubernetes inventory upload conflicts with retained evidence")
	ErrKubernetesInventoryInput     = errors.New("invalid kubernetes inventory evidence")
	ErrKubernetesInventoryBudget    = errors.New("kubernetes inventory resource admission exceeded")
)

type kubernetesUploadScope struct {
	TenantID, ContextID, BindingID, GenerationID, Serial string
	Namespace                                            string
	From, Until, CheckedAt                               time.Time
}

// lockKubernetesUploadAuthority requires a writable tenant transaction. Hold
// the exact source epoch, routing assignment and issued identity until the
// upload operation commits so revocation is ordered with writes.
func lockKubernetesUploadAuthority(ctx context.Context, sc tenancy.Scope, agent, serial, binding, generation string) (kubernetesUploadScope, error) {
	tenant, bound := tenancy.FromContext(ctx)
	if !bound || tenant != sc.Tenant || sc.Q == nil || agent == "" || serial == "" ||
		!canonicalKubernetesUploadID(binding) || !canonicalKubernetesUploadID(generation) {
		return kubernetesUploadScope{}, ErrKubernetesInventoryAuthority
	}
	invalidating, cutoff, err := entityEvidenceLifecycleScope(ctx, sc)
	if err != nil {
		return kubernetesUploadScope{}, err
	}
	if invalidating {
		return kubernetesUploadScope{}, ErrKubernetesInventoryAuthority
	}
	authority := kubernetesUploadScope{TenantID: tenant.String(), BindingID: binding, GenerationID: generation, Serial: serial}
	err = sc.Q.QueryRow(ctx, `
SELECT b.context_id::text,b.namespace,greatest(b.assigned_at,a.assigned_at,k.issued_at),
       least(coalesce(a.expires_at,k.not_after),k.not_after),clock_timestamp()
FROM kubernetes_inventory_sources b
JOIN entity_agent_contexts a ON (a.tenant_id,a.agent_id,a.context_id)=(b.tenant_id,b.agent_id,b.context_id)
JOIN agents collector ON collector.tenant_id=b.tenant_id AND collector.id::text=b.agent_id AND collector.status<>'revoked'
JOIN agent_identities k ON (k.tenant_id,k.agent_id)=(b.tenant_id,b.agent_id)
WHERE b.tenant_id=$1 AND b.id=$2 AND b.agent_id=$3 AND k.serial=$4 AND k.spiffe_id=$5
  AND b.closed_at IS NULL AND b.assigned_at<=clock_timestamp() AND a.assigned_at<=clock_timestamp()
  AND (a.expires_at IS NULL OR a.expires_at>clock_timestamp())
  AND k.revoked_at IS NULL AND k.issued_at<=clock_timestamp() AND k.not_after>clock_timestamp()
FOR SHARE OF b,a,collector,k`, tenant.String(), binding, agent, serial, crypto.EntitySPIFFEID(tenant.String(), agent)).
		Scan(&authority.ContextID, &authority.Namespace, &authority.From, &authority.Until, &authority.CheckedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return kubernetesUploadScope{}, ErrKubernetesInventoryAuthority
	}
	if err != nil {
		return kubernetesUploadScope{}, err
	}
	if cutoff.After(authority.From) {
		authority.From = cutoff
	}
	if !authority.Until.After(authority.From) {
		return kubernetesUploadScope{}, ErrKubernetesInventoryAuthority
	}
	return authority, nil
}

func canonicalKubernetesUploadID(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && raw == id.String()
}

type kubernetesUploadPosition struct {
	Next, Rows, Bytes int64
	PartsLeft         int64
	RowsLeft          int64
	BytesLeft         int64
	Published         bool
}

type kubernetesUploadManifest struct {
	Body, Digest []byte
	Parts        uint32
	Rows, Bytes  uint64
}

// openKubernetesInventoryUpload requires the same authority and lifecycle
// locks as append and publish. expires is set by admission, not the sender.
func openKubernetesInventoryUpload(ctx context.Context, sc tenancy.Scope, authority kubernetesUploadScope,
	manifest kubernetesUploadManifest, expires time.Time) (kubernetesUploadPosition, error) {
	tenant, bound := tenancy.FromContext(ctx)
	if !bound || tenant != sc.Tenant || tenant.String() != authority.TenantID || sc.Q == nil {
		return kubernetesUploadPosition{}, ErrKubernetesInventoryAuthority
	}
	if len(manifest.Body) == 0 || len(manifest.Digest) != 32 || manifest.Rows > math.MaxInt64 || manifest.Bytes > math.MaxInt64 ||
		(manifest.Parts == 0 && (manifest.Rows != 0 || manifest.Bytes != 0)) ||
		(manifest.Rows < uint64(manifest.Parts) || manifest.Bytes < uint64(manifest.Parts)) {
		return kubernetesUploadPosition{}, ErrKubernetesInventoryOrder
	}
	key := []any{authority.TenantID, authority.ContextID, authority.BindingID, authority.GenerationID}
	var originalBody, originalDigest []byte
	var originalSerial string
	var position kubernetesUploadPosition
	err := sc.Q.QueryRow(ctx, `
SELECT manifest,payload_digest,sender_serial,part_count,row_count,body_bytes
FROM kubernetes_inventory_generations WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3 AND id=$4`, key...).
		Scan(&originalBody, &originalDigest, &originalSerial, &position.Next, &position.Rows, &position.Bytes)
	if err == nil {
		if originalSerial != authority.Serial || !bytes.Equal(originalBody, manifest.Body) || !bytes.Equal(originalDigest, manifest.Digest) {
			return kubernetesUploadPosition{}, ErrKubernetesInventoryConflict
		}
		position.Published = true
		return position, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return kubernetesUploadPosition{}, err
	}
	if authority.Until.Before(expires) {
		expires = authority.Until
	}
	if _, err := sc.Q.Exec(ctx, `DELETE FROM kubernetes_inventory_staging
WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3 AND expires_at<=clock_timestamp()`, key[:3]...); err != nil {
		return kubernetesUploadPosition{}, err
	}
	if _, err := sc.Q.Exec(ctx, `
INSERT INTO kubernetes_inventory_staging(tenant_id,context_id,source_id,generation_id,
       sender_serial,manifest,payload_digest,expected_parts,expected_rows,expected_bytes,opened_at,expires_at)
SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,instant.at,$11
FROM (SELECT clock_timestamp() AS at) instant WHERE $11::timestamptz>instant.at
ON CONFLICT DO NOTHING`, append(key, authority.Serial,
		manifest.Body, manifest.Digest, int64(manifest.Parts), int64(manifest.Rows), int64(manifest.Bytes), expires)...); err != nil {
		return kubernetesUploadPosition{}, err
	}
	err = sc.Q.QueryRow(ctx, `
SELECT manifest,payload_digest,sender_serial,next_part,appended_rows,appended_bytes,
       expected_parts-next_part,expected_rows-appended_rows,expected_bytes-appended_bytes
FROM kubernetes_inventory_staging
WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3 AND generation_id=$4 AND expires_at>clock_timestamp()`, key...).
		Scan(&originalBody, &originalDigest, &originalSerial, &position.Next, &position.Rows, &position.Bytes,
			&position.PartsLeft, &position.RowsLeft, &position.BytesLeft)
	if errors.Is(err, pgx.ErrNoRows) {
		return kubernetesUploadPosition{}, ErrKubernetesInventoryOrder
	}
	if err != nil {
		return kubernetesUploadPosition{}, err
	}
	if originalSerial != authority.Serial || !bytes.Equal(originalBody, manifest.Body) || !bytes.Equal(originalDigest, manifest.Digest) {
		return kubernetesUploadPosition{}, ErrKubernetesInventoryConflict
	}
	return position, nil
}

// appendKubernetesInventoryPart takes a validated deterministic part encoding
// and a positive count of actual decoded rows. The stage and next index are
// locked in the same tenant transaction as the immutable part insert.
func appendKubernetesInventoryPart(ctx context.Context, sc tenancy.Scope, authority kubernetesUploadScope,
	index uint32, count int, wire []byte) (kubernetesUploadPosition, error) {
	tenant, bound := tenancy.FromContext(ctx)
	if !bound || tenant != sc.Tenant || tenant.String() != authority.TenantID || sc.Q == nil || count <= 0 || len(wire) == 0 {
		return kubernetesUploadPosition{}, ErrKubernetesInventoryAuthority
	}
	key := []any{authority.TenantID, authority.ContextID, authority.BindingID, authority.GenerationID}
	var position kubernetesUploadPosition
	err := sc.Q.QueryRow(ctx, `
SELECT next_part,appended_rows,appended_bytes,expected_parts-next_part,
       expected_rows-appended_rows,expected_bytes-appended_bytes
FROM kubernetes_inventory_staging
WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3 AND generation_id=$4
  AND sender_serial=$5 AND expires_at>clock_timestamp()
FOR UPDATE`, append(key, authority.Serial)...).
		Scan(&position.Next, &position.Rows, &position.Bytes, &position.PartsLeft, &position.RowsLeft, &position.BytesLeft)
	if errors.Is(err, pgx.ErrNoRows) {
		return kubernetesUploadPosition{}, ErrKubernetesInventoryOrder
	}
	if err != nil {
		return kubernetesUploadPosition{}, err
	}
	part := int64(index)
	if part < position.Next {
		var original []byte
		if err := sc.Q.QueryRow(ctx, `
SELECT original_wire FROM kubernetes_inventory_stage_parts
WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3 AND generation_id=$4 AND part_index=$5`, append(key, part)...).Scan(&original); err != nil {
			return kubernetesUploadPosition{}, err
		}
		if !bytes.Equal(wire, original) {
			return kubernetesUploadPosition{}, ErrKubernetesInventoryConflict
		}
		return position, nil
	}
	rows, size := int64(count), int64(len(wire))
	if part != position.Next || position.PartsLeft <= 0 || rows > position.RowsLeft || size > position.BytesLeft {
		return kubernetesUploadPosition{}, ErrKubernetesInventoryOrder
	}
	if _, err := sc.Q.Exec(ctx, `
INSERT INTO kubernetes_inventory_stage_parts(tenant_id,context_id,source_id,generation_id,part_index,original_wire)
VALUES ($1,$2,$3,$4,$5,$6)`, append(key, part, wire)...); err != nil {
		return kubernetesUploadPosition{}, err
	}
	if _, err := sc.Q.Exec(ctx, `
UPDATE kubernetes_inventory_staging
SET next_part=next_part+1,appended_rows=appended_rows+$5,appended_bytes=appended_bytes+$6
WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3 AND generation_id=$4`, append(key, rows, size)...); err != nil {
		return kubernetesUploadPosition{}, err
	}
	position.Next++
	position.Rows += rows
	position.Bytes += size
	position.PartsLeft--
	position.RowsLeft -= rows
	position.BytesLeft -= size
	return position, nil
}
