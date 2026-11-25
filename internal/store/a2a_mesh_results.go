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
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/a2a"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrA2AMeshReportRefused = errors.New("store: inactive A2A reporter or conflicting result")

// ActiveAgentIdentityRegistration reads the enrolled agent's current
// registration for the exact active certificate serial in this tenant.
func ActiveAgentIdentityRegistration(ctx context.Context, sc tenancy.Scope, agent, serial string) (time.Time, error) {
	var registeredAt time.Time
	err := sc.Q.QueryRow(ctx, `SELECT a.registered_at FROM agent_identities AS i JOIN agents AS a
    ON a.tenant_id=i.tenant_id AND a.id::text=i.agent_id AND a.spiffe_id=i.spiffe_id
  WHERE i.tenant_id=$1 AND i.agent_id=$2 AND i.spiffe_id=$3 AND i.serial=$4
    AND i.revoked_at IS NULL AND i.not_after > statement_timestamp()`,
		sc.Tenant.String(), agent, crypto.AgentSPIFFEID(sc.Tenant.String(), agent), serial).Scan(&registeredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, nil
	}
	return registeredAt, err
}

// RecordA2AMeshResult inserts the first signed measurement for a role. The
// scoped transaction must acquire the incident and audit locks first if this
// result can open or update an incident. The tenant comes from the mTLS identity.
func RecordA2AMeshResult(ctx context.Context, sc tenancy.Scope, report a2a.VerifiedMeshReport, serial string) (bool, error) {
	tenant := sc.Tenant.String()
	result := report.WireResult
	if result == nil || serial == "" || tenant != report.TenantID || tenant != result.GetTenantId() ||
		report.AgentID != result.GetAgentId() || report.AgentID == "" || report.RegisteredAt.IsZero() || report.Digest == ([32]byte{}) {
		return false, ErrA2AMeshReportRefused
	}
	spiffe := crypto.AgentSPIFFEID(tenant, report.AgentID)
	var present int
	// Preserve agent deletion's registry-before-identity lock order. A
	// concurrent delete, revoke or rotate must finish before this transaction
	// validates the exact serial or wait until after it commits.
	if err := sc.Q.QueryRow(ctx, `SELECT 1 FROM agents
 WHERE tenant_id=$1 AND id=$2::uuid AND spiffe_id=$3 AND registered_at=$4
 FOR SHARE`, tenant, report.AgentID, spiffe, report.RegisteredAt).Scan(&present); err != nil {
		return false, meshResultAuthorityError(err)
	}
	if err := sc.Q.QueryRow(ctx, `SELECT 1 FROM agent_identities
 WHERE tenant_id=$1 AND agent_id=$2 AND spiffe_id=$3 AND serial=$4 AND revoked_at IS NULL
   AND clock_timestamp() < LEAST(not_after,$5::timestamptz)
 FOR SHARE`, tenant, report.AgentID, spiffe, serial, report.ExpiresAt).Scan(&present); err != nil {
		return false, meshResultAuthorityError(err)
	}
	peerID := result.GetAttributes()["a2a.peer_agent_id"]
	tag, err := sc.Q.Exec(ctx, `INSERT INTO a2a_mesh_results
 (tenant_id,session_id,role,agent_id,peer_agent_id,result_id,payload_sha256,started_unix_nano,duration_nano,expires_at,metrics)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING`,
		tenant, report.SessionID, report.Role, report.AgentID, peerID, result.ResultId, report.Digest[:],
		result.StartTimeUnixNano, result.DurationNano, report.ExpiresAt, result.Metrics)
	if err != nil || tag.RowsAffected() == 1 {
		return err == nil, err
	}
	var digest []byte
	err = sc.Q.QueryRow(ctx, `SELECT payload_sha256 FROM a2a_mesh_results
 WHERE tenant_id=$1 AND session_id=$2 AND role=$3 AND agent_id=$4 AND result_id=$5`,
		tenant, report.SessionID, report.Role, report.AgentID, result.ResultId).Scan(&digest)
	if err != nil {
		return false, meshResultAuthorityError(err)
	}
	if !bytes.Equal(digest, report.Digest[:]) {
		return false, ErrA2AMeshReportRefused
	}
	return false, nil
}

func meshResultAuthorityError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrA2AMeshReportRefused
	}
	return err
}

// CurrentA2AAgentRegistrations intersects scheduler candidates with the tenant's own
// registered agents and current issued regular-agent identities.
func CurrentA2AAgentRegistrations(ctx context.Context, sc tenancy.Scope, ids []string) (map[string]time.Time, error) {
	rows, err := sc.Q.Query(ctx, `SELECT a.id::text, a.registered_at FROM agents AS a
 WHERE a.tenant_id=$1 AND a.id=ANY($2::uuid[]) AND EXISTS (
   SELECT 1 FROM agent_identities AS i WHERE i.tenant_id=a.tenant_id
     AND i.agent_id=a.id::text AND i.spiffe_id=a.spiffe_id AND i.revoked_at IS NULL
     AND i.not_after > statement_timestamp())`, sc.Tenant.String(), ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	active := make(map[string]time.Time, len(ids))
	for rows.Next() {
		var id string
		var registered time.Time
		if err := rows.Scan(&id, &registered); err != nil {
			return nil, err
		}
		active[id] = registered
	}
	return active, rows.Err()
}
