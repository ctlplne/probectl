// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrEvidenceIdentityInactive = errors.New("entity: evidence identity is not active")

// Evidence is an observation, not permanent identity authority. A source
// that stops reporting loses its current canonical join after this window;
// the original row remains available for historical citations.
const evidenceFreshness = 24 * time.Hour

// WriteEvidenceBatch persists operator-anchored claims, or an unanchored
// flow/BMP device backed by one exact independent current SNMP observation. The caller must
// supply authenticatedAgentID from a verified evidence SVID; tenant comes from
// ctx, while context and canonical entity come from the current FORCE-RLS
// source/agent assignments. An unanchored source with no unique support stays
// unresolved; the collector never chooses an entity ID.
func (s *EntityRegistry) WriteEvidenceBatch(ctx context.Context, authenticatedAgentID, certificateSerial string, raw []entity.Observation) (int, int, error) {
	if s == nil || s.pool == nil {
		return 0, 0, ErrEntityRegistryUnavailable
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant.String() == "" {
		return 0, 0, entity.ErrScopeMismatch
	}
	if certificateSerial == "" || len(raw) == 0 || len(raw) > 64 {
		return 0, 0, entity.ErrInvalidClaim
	}
	now := time.Now()
	claims := make([]entity.Observation, 0, len(raw))
	for _, item := range raw {
		claim, err := item.Normalize(now)
		if err != nil || claim.Source.AgentID != authenticatedAgentID {
			return 0, 0, entity.ErrInvalidClaim
		}
		claims = append(claims, claim)
	}
	accepted, unresolved := 0, 0
	err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		// Hold the exact issued SVID row until the evidence transaction ends.
		// A concurrent DELETE/revocation must finish before this write or wait
		// until it commits; the earlier RPC lookup alone has a replay race.
		var active int
		var senderIssuedAt time.Time
		var senderNotAfter time.Time
		if err := sc.Q.QueryRow(ctx, `SELECT 1,issued_at,not_after FROM agent_identities
			WHERE tenant_id=$1 AND agent_id=$2 AND spiffe_id=$3
			  AND serial=$4 AND revoked_at IS NULL
			  AND not_after > clock_timestamp()
			FOR SHARE`, tenant.String(), authenticatedAgentID,
			crypto.EntitySPIFFEID(tenant.String(), authenticatedAgentID),
			certificateSerial).Scan(&active, &senderIssuedAt, &senderNotAfter); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrEvidenceIdentityInactive
			}
			return err
		}
		for _, claim := range claims {
			if claim.ObservedAt.Before(senderIssuedAt) || !claim.ObservedAt.Before(senderNotAfter) {
				// An SVID attests only observations inside its issuance window.
				// Raw telemetry remains on its original lane.
				unresolved++
				continue
			}
			// A persisted UUID is immutable even after its source is rebound,
			// expired or its independent neighbor support disappears. Check it
			// before current-authority resolution, which might now be unable to
			// select the original canonical endpoint. The exact replay only
			// acknowledges the old row; it never renews its authority.
			found, same, err := existingEvidenceClaim(ctx, sc, tenant.String(),
				authenticatedAgentID, certificateSerial, claim)
			if err != nil {
				return err
			}
			if found {
				if !same {
					return entity.ErrConflictingEvidence
				}
				accepted++
				continue
			}
			authority, ready, err := resolveEvidenceAuthority(ctx, sc, tenant.String(),
				authenticatedAgentID, claim, senderNotAfter)
			if err != nil {
				return err
			}
			if !ready {
				unresolved++
				continue
			}
			endpoint, ready, err := resolveEvidenceEndpoint(ctx, sc, tenant.String(),
				authenticatedAgentID, claim, authority)
			if err != nil {
				return err
			}
			if !ready {
				unresolved++
				continue
			}
			if err := persistEvidenceClaim(ctx, sc, tenant.String(), authenticatedAgentID,
				certificateSerial, claim, authority, endpoint); err != nil {
				return err
			}
			accepted++
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	return accepted, unresolved, nil
}

type evidenceAuthority struct {
	contextID string
	anchorID  string
	supportID string
}

type evidenceEndpoint struct {
	entityID         string
	neighborRemoteID string
	interfaceClaim   bool
	neighborClaim    bool
}

// Resolve current operator authority while the tenant transaction holds the
// exact sender certificate row. A missing/rebound assignment is unresolved.
func resolveEvidenceAuthority(ctx context.Context, sc tenancy.Scope, tenantID,
	agentID string, claim entity.Observation, senderNotAfter time.Time) (evidenceAuthority, bool, error) {
	var originNotAfter time.Time
	if claim.Source.Kind == entity.BMPPeer {
		// A queued observation must still name the exact live router
		// certificate that supplied its BMP frame. A replacement SVID
		// cannot reactivate evidence from a revoked/deleted old serial.
		var originActive int
		err := sc.Q.QueryRow(ctx, `SELECT 1,not_after FROM agent_identities
				WHERE tenant_id=$1 AND agent_id=$2 AND spiffe_id=$3
				  AND serial=$4 AND revoked_at IS NULL
				  AND issued_at <= $5 AND not_after > $5
				  AND not_after > clock_timestamp()
				FOR SHARE`, tenantID, claim.Source.SourceRef,
			crypto.BMPSPIFFEID(tenantID, claim.Source.SourceRef),
			claim.OriginSerial, claim.ObservedAt).Scan(&originActive, &originNotAfter)
		if errors.Is(err, pgx.ErrNoRows) {
			return evidenceAuthority{}, false, nil
		}
		if err != nil {
			return evidenceAuthority{}, false, err
		}
	}
	var contextID string
	var anchorID, anchorKind *string
	var sourceAssignedAt, agentAssignedAt time.Time
	var sourceExpiresAt, agentExpiresAt *time.Time
	err := sc.Q.QueryRow(ctx, `
			SELECT m.context_id::text, m.anchor_entity_id::text, n.kind,
			       m.assigned_at,m.expires_at,a.assigned_at,a.expires_at
			  FROM entity_source_contexts m
			  JOIN entity_agent_contexts a ON
			       (a.tenant_id,a.agent_id,a.context_id)=
			       (m.tenant_id,m.agent_id,m.context_id)
			  LEFT JOIN entities n ON
			       (n.tenant_id,n.context_id,n.id)=
			       (m.tenant_id,m.context_id,m.anchor_entity_id)
			 WHERE m.tenant_id=$1 AND m.agent_id=$2
			   AND m.source_kind=$3 AND m.source_ref=$4
			   AND NOT EXISTS (
			       SELECT 1 FROM agent_identities i
			        WHERE i.tenant_id=m.tenant_id AND i.agent_id=m.agent_id
			          AND i.revoked_at IS NOT NULL
			          AND i.revoked_by IS DISTINCT FROM 'entity_registry_delete')
		 FOR UPDATE OF m,a`,
		tenantID, agentID, string(claim.Source.Kind),
		claim.Source.SourceRef).Scan(&contextID, &anchorID, &anchorKind,
		&sourceAssignedAt, &sourceExpiresAt, &agentAssignedAt, &agentExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return evidenceAuthority{}, false, nil
	}
	if err != nil {
		return evidenceAuthority{}, false, err
	}
	var writeAt time.Time
	if err := sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&writeAt); err != nil {
		return evidenceAuthority{}, false, err
	}
	if !writeAt.Before(senderNotAfter) ||
		(claim.Source.Kind == entity.BMPPeer && !writeAt.Before(originNotAfter)) ||
		sourceAssignedAt.After(writeAt) || agentAssignedAt.After(writeAt) ||
		// A later operator binding cannot retroactively assign an earlier
		// observation to a VRF. This also closes a rebind/backdate path.
		sourceAssignedAt.After(claim.ObservedAt) ||
		agentAssignedAt.After(claim.ObservedAt) ||
		(sourceExpiresAt != nil && !writeAt.Before(*sourceExpiresAt)) ||
		(agentExpiresAt != nil && !writeAt.Before(*agentExpiresAt)) {
		return evidenceAuthority{}, false, nil
	}
	supportID := ""
	if anchorID == nil || anchorKind == nil {
		if claim.Source.Kind != entity.FlowExporter && claim.Source.Kind != entity.BMPPeer {
			return evidenceAuthority{}, false, nil
		}
		address, err := inferredObservationAddress(claim)
		if err != nil {
			return evidenceAuthority{}, false, err
		}
		deviceID, exactSupportID, err := independentSNMPSupport(ctx, sc,
			tenantID, contextID, address, claim.ObservedAt)
		if err != nil {
			return evidenceAuthority{}, false, err
		}
		if deviceID == "" {
			return evidenceAuthority{}, false, nil
		}
		deviceKind := string(entity.Device)
		anchorID, anchorKind, supportID = &deviceID, &deviceKind, exactSupportID
	}
	if claim.Source.Kind == entity.AgentSite {
		if *anchorKind != string(entity.Site) {
			return evidenceAuthority{}, false, entity.ErrInvalidClaim
		}
	} else if *anchorKind != string(entity.Device) {
		return evidenceAuthority{}, false, entity.ErrInvalidClaim
	}
	return evidenceAuthority{contextID: contextID, anchorID: *anchorID, supportID: supportID}, true, nil
}

// The endpoint is selected under the same tenant and assignment locks as its
// authority; collector aliases cannot create cross-context identity.
func resolveEvidenceEndpoint(ctx context.Context, sc tenancy.Scope, tenantID,
	agentID string, claim entity.Observation, authority evidenceAuthority) (evidenceEndpoint, bool, error) {
	entityID := authority.anchorID
	interfaceClaim := claim.Alias.Kind == entity.SNMPInterfaceAlias
	neighborClaim := claim.Alias.Kind == entity.PhysicalNeighborAlias
	if claim.Source.Kind == entity.DeviceTarget && claim.Alias.Kind == entity.AddressAlias {
		// The SNMP address belongs to the observed interface when its
		// ifIndex claim created one. Keep the address on that interface
		// for detail, while address resolution projects its parent device
		// for flow/BMP/path joins. An invalid or absent interface cannot
		// make an address escape the operator's device anchor.
		if indexText, hasIndex := strings.CutPrefix(claim.SourceRef, "snmp:ifIndex:"); hasIndex {
			index, parseErr := strconv.ParseUint(indexText, 10, 32)
			if parseErr != nil || index == 0 || strconv.FormatUint(index, 10) != indexText {
				return evidenceEndpoint{}, false, entity.ErrInvalidClaim
			}
			var interfaceID, parentID string
			err := sc.Q.QueryRow(ctx, `SELECT id::text,parent_entity_id::text FROM entities
					WHERE tenant_id=$1 AND context_id=$2 AND kind='interface'
					  AND source_agent_id=$3 AND configured_ref=$4 AND interface_index=$5
					FOR SHARE`, tenantID, authority.contextID, agentID,
				claim.Source.SourceRef, int64(index)).Scan(&interfaceID, &parentID)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return evidenceEndpoint{}, false, err
			}
			if err == nil {
				if parentID != authority.anchorID {
					// A reanchored source cannot launder an old ifIndex IP
					// into a different canonical device.
					return evidenceEndpoint{}, false, nil
				}
				entityID = interfaceID
			}
		}
	}
	neighborRemoteID := ""
	neighborOrphaned := false
	if interfaceClaim {
		if claim.Source.Kind != entity.DeviceTarget {
			return evidenceEndpoint{}, false, entity.ErrInvalidClaim
		}
		index, err := strconv.ParseUint(claim.Alias.Value, 10, 32)
		if err != nil || index == 0 {
			return evidenceEndpoint{}, false, entity.ErrInvalidClaim
		}
		var parentID string
		err = sc.Q.QueryRow(ctx, `SELECT id::text,parent_entity_id::text
				FROM entities WHERE tenant_id=$1 AND context_id=$2
				AND source_agent_id=$3 AND configured_ref=$4
				AND interface_index=$5 FOR UPDATE`, tenantID, authority.contextID,
			agentID, claim.Source.SourceRef, int64(index)).Scan(&entityID, &parentID)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			entityID, err = newRegistryID()
			if err != nil {
				return evidenceEndpoint{}, false, err
			}
			// Entity listing needs only entities.read. Keep the raw
			// ifName/ifDescr on the metrics.read-gated evidence page.
			label := "ifIndex " + claim.Alias.Value
			_, err = sc.Q.Exec(ctx, `INSERT INTO entities
					(tenant_id,context_id,id,kind,label,parent_entity_id,
					 source_agent_id,configured_ref,interface_index)
					VALUES ($1,$2,$3,'interface',$4,$5,$6,$7,$8)`,
				tenantID, authority.contextID, entityID, label, authority.anchorID,
				agentID, claim.Source.SourceRef, int64(index))
			if err != nil {
				return evidenceEndpoint{}, false, err
			}
		case err != nil:
			return evidenceEndpoint{}, false, err
		case parentID != authority.anchorID:
			// Reanchoring the same source to a different device cannot
			// silently move an old ifIndex identity to that device.
			return evidenceEndpoint{}, false, nil
		}
	}
	if neighborClaim {
		// The local ifIndex has meaning only inside this authenticated
		// collector's configured device. Never infer it from a port name.
		err := sc.Q.QueryRow(ctx, `SELECT id::text FROM entities
				WHERE tenant_id=$1 AND context_id=$2 AND kind='interface'
				  AND parent_entity_id=$3 AND source_agent_id=$4
				  AND configured_ref=$5 AND interface_index=$6`,
			tenantID, authority.contextID, authority.anchorID, agentID,
			claim.Source.SourceRef, int64(claim.NeighborLocalIfIndex)).Scan(&entityID)
		if errors.Is(err, pgx.ErrNoRows) {
			return evidenceEndpoint{}, false, nil
		}
		if err != nil {
			return evidenceEndpoint{}, false, err
		}
		// A replay of an already persisted observation compares against
		// the original endpoint and metadata below. A later conflicting
		// remote lookup must not turn a changed UUID payload into a
		// harmless "unresolved" response.
		var priorEvidenceID string
		err = sc.Q.QueryRow(ctx, `SELECT e.id::text,COALESCE(l.to_entity_id::text,'')
				FROM entity_evidence e LEFT JOIN entity_links l ON
				 (l.tenant_id,l.context_id,l.evidence_id)=
				 (e.tenant_id,e.context_id,e.id)
				 AND l.kind='physical'
				WHERE e.tenant_id=$1 AND e.agent_id=$2
				 AND e.source_kind=$3 AND e.configured_ref=$4
				 AND e.observation_id=$5
				FOR SHARE OF e`,
			tenantID, agentID, string(claim.Source.Kind),
			claim.Source.SourceRef, claim.ID).Scan(&priorEvidenceID, &neighborRemoteID)
		if errors.Is(err, pgx.ErrNoRows) {
			kind, value := entity.SNMPDeviceAlias, claim.NeighborDeviceName
			if claim.NeighborAddress != "" {
				kind, value = entity.AddressAlias, claim.NeighborAddress
			}
			neighborRemoteID, err = resolveNeighborRemote(ctx, sc, tenantID,
				authority.contextID, kind, value)
		} else if err == nil && neighborRemoteID == "" {
			// Deleting the remote canonical device cascades its physical
			// link, but retains this original local LLDP observation.
			// A byte-identical retry must not reattach it to a new device
			// that later acquired the same address.
			neighborOrphaned = true
		}
		if err != nil {
			return evidenceEndpoint{}, false, err
		}
		if (neighborRemoteID == "" && !neighborOrphaned) || neighborRemoteID == authority.anchorID {
			return evidenceEndpoint{}, false, nil
		}
	}
	return evidenceEndpoint{entityID: entityID, neighborRemoteID: neighborRemoteID,
		interfaceClaim: interfaceClaim, neighborClaim: neighborClaim}, true, nil
}

func persistEvidenceClaim(ctx context.Context, sc tenancy.Scope, tenantID, agentID,
	serial string, claim entity.Observation, authority evidenceAuthority, endpoint evidenceEndpoint) error {
	// Random evidence PKs come through internal/crypto. The observation
	// UUID is a client idempotency key, never the canonical evidence PK.
	evidenceID, err := newRegistryID()
	if err != nil {
		return err
	}
	var inserted string
	err = sc.Q.QueryRow(ctx, `
			INSERT INTO entity_evidence
			 (tenant_id,context_id,id,observation_id,entity_id,
			  alias_kind,alias_value,source,source_ref,agent_id,
			  source_kind,configured_ref,observed_at,expires_at,sender_serial,origin_serial,
			  interface_name,interface_description,
			  neighbor_protocol,neighbor_local_if_index,neighbor_local_port_id,
			  neighbor_remote_port_id,neighbor_chassis_id,neighbor_device_name,
			  neighbor_management_address,support_evidence_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
		        NULLIF($16,'')::text,NULLIF($17,'')::text,NULLIF($18,'')::text,
		        NULLIF($19,'')::text,NULLIF($20,0)::bigint,NULLIF($21,'')::text,
		        NULLIF($22,'')::text,NULLIF($23,'')::text,NULLIF($24,'')::text,
		        NULLIF($25,'')::text,NULLIF($26,'')::uuid)
			ON CONFLICT (tenant_id,agent_id,source_kind,configured_ref,observation_id)
			DO NOTHING RETURNING id::text`,
		tenantID, authority.contextID, evidenceID, claim.ID, endpoint.entityID,
		string(claim.Alias.Kind), claim.Alias.Value, string(claim.Source.Kind),
		claim.SourceRef, agentID, string(claim.Source.Kind),
		claim.Source.SourceRef, claim.ObservedAt,
		claim.ObservedAt.Add(evidenceFreshness), serial,
		claim.OriginSerial, claim.InterfaceName,
		claim.InterfaceDescription, claim.NeighborProtocol,
		int64(claim.NeighborLocalIfIndex), claim.NeighborLocalPortID,
		claim.NeighborRemotePortID, claim.NeighborChassisID,
		claim.NeighborDeviceName, claim.NeighborAddress, authority.supportID).Scan(&inserted)
	if err == nil {
		if endpoint.interfaceClaim {
			linkID, err := newRegistryID()
			if err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_links
					(tenant_id,context_id,id,from_entity_id,to_entity_id,
					 evidence_id,kind,observed_at)
					VALUES ($1,$2,$3,$4,$5,$6,'contains',$7)`,
				tenantID, authority.contextID, linkID, authority.anchorID, endpoint.entityID,
				evidenceID, claim.ObservedAt); err != nil {
				return err
			}
		}
		if endpoint.neighborClaim {
			linkID, err := newRegistryID()
			if err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_links
					(tenant_id,context_id,id,from_entity_id,to_entity_id,
					 evidence_id,kind,observed_at)
					VALUES ($1,$2,$3,$4,$5,$6,'physical',$7)`,
				tenantID, authority.contextID, linkID, endpoint.entityID,
				endpoint.neighborRemoteID, evidenceID, claim.ObservedAt); err != nil {
				return err
			}
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	// Another writer inserted this UUID after our first point lookup.
	// Compare only immutable collector fields: the server may have
	// selected different current support while both writes raced.
	found, same, err := existingEvidenceClaim(ctx, sc, tenantID,
		agentID, serial, claim)
	if err != nil {
		return err
	}
	if !found || !same {
		return entity.ErrConflictingEvidence
	}
	return nil
}

// The tenant/agent/source/UUID index makes this a bounded point lookup. The
// comparison covers every collector-supplied field; context, canonical entity
// and support row are selected by the server and remain historical on replay.
func existingEvidenceClaim(ctx context.Context, sc tenancy.Scope, tenantID,
	agentID, serial string, claim entity.Observation) (bool, bool, error) {
	var same bool
	err := sc.Q.QueryRow(ctx, `SELECT
		alias_kind=$6 AND alias_value=$7 AND source_ref=$8 AND observed_at=$9
		AND COALESCE(sender_serial,'')=$10 AND COALESCE(origin_serial,'')=$11
		AND COALESCE(interface_name,'')=$12
		AND COALESCE(interface_description,'')=$13
		AND COALESCE(neighbor_protocol,'')=$14
		AND COALESCE(neighbor_local_if_index,0)=$15
		AND COALESCE(neighbor_local_port_id,'')=$16
		AND COALESCE(neighbor_remote_port_id,'')=$17
		AND COALESCE(neighbor_chassis_id,'')=$18
		AND COALESCE(neighbor_device_name,'')=$19
		AND COALESCE(neighbor_management_address,'')=$20
		FROM entity_evidence
		WHERE tenant_id=$1 AND agent_id=$2 AND source_kind=$3
		  AND configured_ref=$4 AND observation_id=$5
		FOR SHARE`,
		tenantID, agentID, string(claim.Source.Kind), claim.Source.SourceRef,
		claim.ID, string(claim.Alias.Kind), claim.Alias.Value, claim.SourceRef,
		claim.ObservedAt, serial, claim.OriginSerial, claim.InterfaceName,
		claim.InterfaceDescription, claim.NeighborProtocol,
		int64(claim.NeighborLocalIfIndex), claim.NeighborLocalPortID,
		claim.NeighborRemotePortID, claim.NeighborChassisID,
		claim.NeighborDeviceName, claim.NeighborAddress).Scan(&same)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	return err == nil, same, err
}

// resolveNeighborRemote is deliberately stricter than general alias lookup:
// a physical adjacency needs one independently observed SNMP device in this
// exact tenant/context. A flow exporter or BMP peer alone cannot turn an
// untrusted LLDP chassis string into a physical cable. Zero or two candidates
// means unresolved; neither a private IP nor a system name selects a VRF.
func resolveNeighborRemote(ctx context.Context, sc tenancy.Scope, tenantID, contextID string,
	kind entity.AliasKind, value string) (string, error) {
	rows, err := sc.Q.Query(ctx, `
		SELECT DISTINCT COALESCE(n.parent_entity_id,n.id)::text AS device_id
		  FROM entity_evidence e
		  JOIN entities n ON (n.tenant_id,n.context_id,n.id)=
		                     (e.tenant_id,e.context_id,e.entity_id)
		  JOIN entity_source_contexts m ON
		       (m.tenant_id,m.context_id,m.agent_id,m.source_kind,m.source_ref)=
		       (e.tenant_id,e.context_id,e.agent_id,e.source_kind,e.configured_ref)
		     AND m.anchor_entity_id=COALESCE(n.parent_entity_id,n.id)
		  JOIN entity_agent_contexts a ON
		       (a.tenant_id,a.agent_id,a.context_id)=
		       (m.tenant_id,m.agent_id,m.context_id)
		 WHERE e.tenant_id=$1 AND e.context_id=$2
		   AND e.alias_kind=$3 AND e.alias_value=$4
		   AND e.source_kind='device_target'
		   AND n.kind IN ('device','interface')
		   AND e.observed_at <= statement_timestamp()
		   AND (e.expires_at IS NULL OR e.expires_at > statement_timestamp())
		   AND m.assigned_at <= statement_timestamp()
		   AND m.assigned_at <= e.observed_at
		   AND (m.expires_at IS NULL OR m.expires_at > statement_timestamp())
		   AND a.assigned_at <= statement_timestamp()
		   AND a.assigned_at <= e.observed_at
		   AND (a.expires_at IS NULL OR a.expires_at > statement_timestamp())
		   AND NOT EXISTS (SELECT 1 FROM agent_identities i
		       WHERE i.tenant_id=e.tenant_id AND i.agent_id=e.agent_id
		         AND i.revoked_at IS NOT NULL
		         AND i.revoked_by IS DISTINCT FROM 'entity_registry_delete')
		   AND EXISTS (SELECT 1 FROM agent_identities sender
		       WHERE sender.tenant_id=e.tenant_id AND sender.agent_id=e.agent_id
		         AND sender.serial=e.sender_serial
		         AND sender.spiffe_id='spiffe://probectl/tenant/' || e.tenant_id::text || '/entity/' || e.agent_id
		         AND sender.revoked_at IS NULL
		         AND sender.issued_at <= e.observed_at
		         AND sender.not_after > statement_timestamp())
		 ORDER BY device_id LIMIT 2`, tenantID, contextID, string(kind), value)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	ids := make([]string, 0, 2)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return "", err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(ids) != 1 {
		return "", nil
	}
	return ids[0], nil
}
