// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// ConfigureLibreNMSHTTPSource records only the approved origin and a
// tenant-namespaced reference. The caller must authorize nms.import.write on
// this routing context and provide deployment-owned CIDRs, CA trust and secret
// prefix. A source body cannot supply these values. The configuration starts
// no request; the live capture route must separately opt in to fetching.
// Every change advances config_version, invalidating an in-flight plan.
func (s CaptureStore) ConfigureLibreNMSHTTPSource(ctx context.Context, contextID,
	instanceRef, origin, credentialRef, allowedRefPrefix string,
	approved []netip.Prefix, caFile string, timeout time.Duration) (string, error) {
	if s.pool == nil || s.audit == nil {
		return "", ErrCaptureAuditUnavailable
	}
	contextUUID, err := uuid.Parse(contextID)
	if err != nil || contextUUID == uuid.Nil || !safeInstanceRef(instanceRef) {
		return "", ErrPlanUnavailable
	}
	contextID = contextUUID.String()
	newID, err := captureUUID()
	if err != nil {
		return "", err
	}
	var sourceID string
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		tenantID := sc.Tenant.String()
		var exists bool
		if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM entity_contexts
			WHERE tenant_id=$1 AND id=$2)`, tenantID, contextID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrPlanUnavailable
		}
		if !allowedSourceRef(tenantID, allowedRefPrefix, credentialRef) {
			return ErrSourceUnavailable
		}
		if _, err := crypto.PinnedHTTPSClient(origin, approved, caFile, timeout); err != nil {
			return ErrSourceUnavailable
		}
		if err := sc.Q.QueryRow(ctx, `INSERT INTO nms_import_sources
			(tenant_id,context_id,id,source_kind,instance_ref,https_origin,
			 credential_ref,fetch_enabled,config_version)
			VALUES ($1,$2,$3,'librenms',$4,$5,$6,true,1)
			ON CONFLICT (tenant_id,context_id,source_kind,instance_ref)
			DO UPDATE SET https_origin=EXCLUDED.https_origin,
			 credential_ref=EXCLUDED.credential_ref,fetch_enabled=true,
			 config_version=nms_import_sources.config_version+1
			RETURNING id::text`, tenantID, contextID, newID, instanceRef,
			origin, credentialRef).Scan(&sourceID); err != nil {
			// PostgreSQL constraint details can include the submitted origin or
			// reference. Do not turn them into a client/audit existence oracle.
			return ErrSourceUnavailable
		}
		return s.audit(ctx, sc, "nms_import.source_configured", sourceID,
			map[string]any{"context_id": contextID, "source_kind": LibreNMS,
				"fetch_enabled": true})
	})
	if err != nil {
		return "", err
	}
	return sourceID, nil
}
