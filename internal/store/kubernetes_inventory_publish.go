// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func publishKubernetesInventory(ctx context.Context, sc tenancy.Scope, scope kubernetesUploadScope) (kubernetesUploadPosition, []byte, error) {
	var position kubernetesUploadPosition
	key := []any{scope.TenantID, scope.ContextID, scope.BindingID, scope.GenerationID}
	var digest []byte
	var serial string
	err := sc.Q.QueryRow(ctx, `SELECT g.sender_serial,g.payload_digest,g.part_count,g.row_count,g.body_bytes
FROM kubernetes_inventory_generations g
WHERE g.tenant_id=$1 AND g.context_id=$2 AND g.source_id=$3 AND g.id=$4
  AND NOT EXISTS (
    SELECT 1 FROM kubernetes_inventory_windows w
    WHERE (w.tenant_id,w.context_id,w.source_id,w.generation_id)=(g.tenant_id,g.context_id,g.source_id,g.id)
      AND w.valid_from<$5)`, append(key, scope.From)...).
		Scan(&serial, &digest, &position.Next, &position.Rows, &position.Bytes)
	if err == nil {
		if serial != scope.Serial {
			return kubernetesUploadPosition{}, nil, ErrKubernetesInventoryConflict
		}
		position.Published = true
		return position, digest, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return kubernetesUploadPosition{}, nil, err
	}
	manifestWire, digest, err := verifyKubernetesInventoryUpload(ctx, sc, scope)
	if err != nil {
		return kubernetesUploadPosition{}, nil, err
	}
	var manifest agentv1.KubernetesInventoryManifest
	if err := proto.Unmarshal(manifestWire, &manifest); err != nil || !completeKubernetesMessage(&manifest) ||
		!validKubernetesInventoryWindows(manifest.Windows) || manifest.Rows > entity.KubernetesInventoryGenerationRows ||
		manifest.PayloadBytes > entity.KubernetesInventoryGenerationBytes {
		return kubernetesUploadPosition{}, nil, ErrKubernetesInventoryInput
	}
	position.Next, position.Rows, position.Bytes = int64(manifest.Parts), int64(manifest.Rows), int64(manifest.PayloadBytes)
	if _, err := sc.Q.Exec(ctx, `
INSERT INTO kubernetes_inventory_generations(tenant_id,context_id,source_id,id,sender_serial,manifest,payload_digest,part_count,row_count,body_bytes)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, append(key, scope.Serial, manifestWire, digest,
		position.Next, position.Rows, position.Bytes)...); err != nil {
		return kubernetesUploadPosition{}, nil, err
	}
	if err := retainKubernetesInventory(ctx, sc, scope, &manifest, key); err != nil {
		return kubernetesUploadPosition{}, nil, err
	}
	removed, err := sc.Q.Exec(ctx, `DELETE FROM kubernetes_inventory_staging
WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3 AND generation_id=$4 AND expires_at>clock_timestamp()`, key...)
	if err != nil {
		return kubernetesUploadPosition{}, nil, err
	}
	if removed.RowsAffected() != 1 {
		return kubernetesUploadPosition{}, nil, ErrKubernetesInventoryOrder
	}
	position.Published = true
	return position, digest, nil
}

func retainKubernetesInventory(ctx context.Context, sc tenancy.Scope, scope kubernetesUploadScope,
	manifest *agentv1.KubernetesInventoryManifest, key []any) error {
	var windows []kubernetesInventoryWindow
	for index, raw := range manifest.Windows {
		window, err := inventoryWindow(raw, scope)
		if err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `
INSERT INTO kubernetes_inventory_windows(tenant_id,context_id,source_id,generation_id,window_index,object_kind,valid_from,valid_until)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, append(key, int64(index), int32(window.Kind), window.From, window.Until)...); err != nil {
			return err
		}
		windows = append(windows, window)
	}
	var retained uint64
	for index := uint32(0); index < manifest.Parts; index++ {
		var wire []byte
		if err := sc.Q.QueryRow(ctx, `SELECT original_wire FROM kubernetes_inventory_stage_parts
WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3 AND generation_id=$4 AND part_index=$5`, append(key, int64(index))...).Scan(&wire); err != nil {
			return err
		}
		var part agentv1.KubernetesInventoryPart
		if err := proto.Unmarshal(wire, &part); err != nil || !completeKubernetesMessage(&part) || part.Index != index ||
			len(part.Rows) == 0 || len(part.Rows) > entity.KubernetesInventoryPartRows || uint64(len(part.Rows)) > manifest.Rows-retained {
			return ErrKubernetesInventoryInput
		}
		if err := retainKubernetesInventoryPart(ctx, sc, key, windows, part.Rows); err != nil {
			return err
		}
		retained += uint64(len(part.Rows))
	}
	if retained != manifest.Rows {
		return ErrKubernetesInventoryInput
	}
	return nil
}

type kubernetesInventoryCopyRow struct {
	Window   uint32 `json:"window_index"`
	Kind     int32  `json:"object_kind"`
	UID      string `json:"object_uid"`
	Name     string `json:"object_name,omitempty"`
	Unowned  bool   `json:"controller_unowned"`
	Address  string `json:"ip,omitempty"`
	Relation int32  `json:"relationship_kind,omitempty"`
	FromKind int32  `json:"from_kind,omitempty"`
	FromUID  string `json:"from_uid,omitempty"`
	ToKind   int32  `json:"to_kind,omitempty"`
	ToUID    string `json:"to_uid,omitempty"`
}

func retainKubernetesInventoryPart(ctx context.Context, sc tenancy.Scope, key []any, windows []kubernetesInventoryWindow,
	rows []*agentv1.KubernetesInventoryRow) error {
	var records []kubernetesInventoryCopyRow
	for _, row := range rows {
		if !validKubernetesInventoryRow(row) || uint64(row.WindowIndex) >= uint64(len(windows)) {
			return ErrKubernetesInventoryInput
		}
		kind := windows[row.WindowIndex].Kind
		item := kubernetesInventoryCopyRow{Window: row.WindowIndex, Kind: int32(kind)}
		switch field := row.Record.(type) {
		case *agentv1.KubernetesInventoryRow_Object:
			if field.Object.Kind != kind {
				return ErrKubernetesInventoryInput
			}
			item.UID, item.Name = field.Object.Uid, field.Object.Name
			item.Unowned = field.Object.ControllerUnowned
		case *agentv1.KubernetesInventoryRow_Address:
			if field.Address.Kind != kind {
				return ErrKubernetesInventoryInput
			}
			item.UID, item.Address = field.Address.Uid, field.Address.Address
		case *agentv1.KubernetesInventoryRow_Relationship:
			edge := field.Relationship
			witnessKind, witnessUID := edge.FromKind, edge.FromUid
			if edge.Relation == kubernetesBackend {
				witnessKind, witnessUID = kubernetesSlice, edge.EndpointSliceUid
			}
			if witnessKind != kind {
				return ErrKubernetesInventoryInput
			}
			item.UID, item.Relation = witnessUID, int32(edge.Relation)
			item.FromKind, item.FromUID, item.ToKind, item.ToUID = int32(edge.FromKind), edge.FromUid, int32(edge.ToKind), edge.ToUid
		}
		records = append(records, item)
	}
	wire, err := json.Marshal(records)
	if err != nil {
		return ErrKubernetesInventoryInput
	}
	_, err = sc.Q.Exec(ctx, `
WITH input AS MATERIALIZED (
    SELECT * FROM jsonb_to_recordset($5::jsonb) AS r(window_index bigint,object_kind smallint,object_uid text,
        object_name text,controller_unowned boolean,ip inet,relationship_kind smallint,from_kind smallint,from_uid text,to_kind smallint,to_uid text)
), objects AS (
    INSERT INTO kubernetes_inventory_objects(tenant_id,context_id,source_id,generation_id,window_index,object_kind,object_uid,object_name,controller_unowned)
    SELECT $1,$2,$3,$4,window_index,object_kind,object_uid,object_name,controller_unowned FROM input WHERE object_name IS NOT NULL
), addresses AS (
    INSERT INTO kubernetes_inventory_addresses(tenant_id,context_id,source_id,generation_id,window_index,object_kind,object_uid,ip)
    SELECT $1,$2,$3,$4,window_index,object_kind,object_uid,ip FROM input WHERE ip IS NOT NULL
)
INSERT INTO kubernetes_inventory_relationships(tenant_id,context_id,source_id,generation_id,window_index,witness_kind,witness_uid,
    relationship_kind,from_kind,from_uid,to_kind,to_uid)
SELECT $1,$2,$3,$4,window_index,object_kind,object_uid,relationship_kind,from_kind,from_uid,to_kind,to_uid
FROM input WHERE relationship_kind IS NOT NULL`, append(key, wire)...)
	return err
}
