// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// LibreNMSFetchPolicy is deployment-owned. A tenant request or source body
// cannot supply CIDRs, trust roots, reference namespace or secret resolver.
// An empty policy fails closed and makes no outbound request.
type LibreNMSFetchPolicy struct {
	ApprovedCIDRs    []netip.Prefix
	CAFile           string
	AllowedRefPrefix string
	Resolver         SourceTokenResolver
	Timeout          time.Duration
}

// OpenConfiguredLibreNMS returns one documented inventory response after a
// tenant-first plan/source lookup. The caller must authorize nms.import.write
// for the chosen context and close the body after bounded streaming decode.
func (s CaptureStore) OpenConfiguredLibreNMS(ctx context.Context, contextID,
	planID, resource string, policy LibreNMSFetchPolicy) (io.ReadCloser, error) {
	return s.openConfiguredLibreNMS(ctx, contextID, planID, resource, "", policy)
}

// CaptureConfiguredLibreNMSDevices is the focused live-source proof: it binds
// one configured HTTPS response to the same tenant plan, bounded decoder,
// page/audit transaction and inert seal as a streamed export. The full
// multi-resource importer must capture locations, groups, memberships and
// rules before publishing any preview or apply action.
func (s CaptureStore) CaptureConfiguredLibreNMSDevices(ctx context.Context,
	contextID, planID string, policy LibreNMSFetchPolicy) (string, error) {
	body, err := s.OpenConfiguredLibreNMS(ctx, contextID, planID, "devices", policy)
	if err != nil {
		return "", err
	}
	defer body.Close()
	return s.CaptureLibreNMSDevices(ctx, contextID, planID, body)
}

// OpenConfiguredLibreNMSMembership derives its group name from the captured,
// tenant-owned group row. The caller supplies only a canonical group ID; a
// lower-trust response or request cannot select an arbitrary URL segment.
func (s CaptureStore) OpenConfiguredLibreNMSMembership(ctx context.Context,
	contextID, planID, groupID string, policy LibreNMSFetchPolicy) (io.ReadCloser, error) {
	return s.openConfiguredLibreNMS(ctx, contextID, planID, "membership", groupID, policy)
}

func (s CaptureStore) openConfiguredLibreNMS(ctx context.Context, contextID,
	planID, resource, groupID string, policy LibreNMSFetchPolicy) (io.ReadCloser, error) {
	if s.pool == nil || s.audit == nil {
		return nil, ErrCaptureAuditUnavailable
	}
	contextUUID, err := uuid.Parse(contextID)
	if err != nil || contextUUID == uuid.Nil {
		return nil, ErrPlanUnavailable
	}
	planUUID, err := uuid.Parse(planID)
	if err != nil || planUUID == uuid.Nil {
		return nil, ErrPlanUnavailable
	}
	contextID, planID = contextUUID.String(), planUUID.String()
	var body io.ReadCloser
	var fetchErr error
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var origin, credentialRef string
		var planVersion, sourceVersion int64
		// Keep a read lock until the request has obtained its response. A
		// concurrent disable/reconfiguration cannot commit before this request
		// starts; any later capture write also checks the plan's version.
		err := sc.Q.QueryRow(ctx, `SELECT s.https_origin,s.credential_ref,
			p.source_config_version,s.config_version
			FROM nms_import_plans p JOIN nms_import_sources s
			  ON s.tenant_id=p.tenant_id AND s.context_id=p.context_id AND s.id=p.source_id
			WHERE p.tenant_id=$1 AND p.context_id=$2 AND p.id=$3
			  AND p.state='capturing' AND p.expires_at>clock_timestamp()
			  AND s.source_kind='librenms' AND s.fetch_enabled
			FOR SHARE OF p,s`, sc.Tenant.String(), contextID, planID).
			Scan(&origin, &credentialRef, &planVersion, &sourceVersion)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPlanUnavailable
		}
		if err != nil {
			return err
		}
		if planVersion == 0 || planVersion != sourceVersion {
			return ErrPlanUnavailable
		}
		switch resource {
		case "devices", "locations", "groups", "rules", "membership":
		default:
			return ErrSourceUnavailable
		}
		name := ""
		if resource == "membership" {
			if groupID == "" {
				return ErrSourceUnavailable
			}
			err = sc.Q.QueryRow(ctx, `SELECT coalesce(label,'') FROM nms_import_rows
				WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
				  AND object_kind='group' AND external_id=$4 AND action='captured'`,
				sc.Tenant.String(), contextID, planID, groupID).Scan(&name)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrSourceUnavailable
			}
			if err != nil {
				return err
			}
		}
		source, err := NewLibreNMSHTTPSource(sc.Tenant.String(), origin,
			policy.ApprovedCIDRs, policy.CAFile, credentialRef,
			policy.AllowedRefPrefix, policy.Resolver, policy.Timeout)
		if err != nil {
			return ErrSourceUnavailable
		}
		// Commit a bounded tenant audit event even when the source request
		// fails. An audit failure refuses the request before any network I/O.
		if err := s.audit(ctx, sc, "nms_import.source_fetch_attempted", planID,
			map[string]any{"context_id": contextID, "resource": resource}); err != nil {
			return err
		}
		if resource == "membership" {
			body, fetchErr = source.OpenMembership(ctx, name)
		} else {
			body, fetchErr = source.Open(ctx, resource)
		}
		return nil
	})
	if err != nil {
		if body != nil {
			body.Close()
		}
		return nil, err
	}
	if fetchErr != nil {
		if body != nil {
			body.Close()
		}
		return nil, ErrSourceUnavailable
	}
	return body, nil
}
