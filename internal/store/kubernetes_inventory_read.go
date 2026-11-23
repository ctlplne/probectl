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
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type KubernetesInventoryFact struct {
	SourceID, GenerationID, Serial string
	WindowIndex                    int64
	From, Until                    time.Time
	WitnessKind                    agentv1.KubernetesInventoryKind
	WitnessUID, Name, Address      string
	ControllerUnowned              bool
	Relationship                   agentv1.KubernetesInventoryRelationshipKind
	FromKind, ToKind               agentv1.KubernetesInventoryKind
	FromUID, ToUID                 string
	ProjectionAt                   *time.Time
}

type KubernetesInventorySnapshot struct {
	Scope          entity.Scope
	Sources        []KubernetesInventorySource
	Facts          []KubernetesInventoryFact
	flowCohort     bool
	flowIncomplete bool
}

const (
	kubernetesInventoryReadRange = iota
	kubernetesInventoryReadPoint
	kubernetesInventoryReadLatest
	kubernetesInventoryReadFlows
)

// ReadKubernetesInventoryInScope takes an already scoped read snapshot. The
// caller authorizes each current collector before any facts are read. An
// inaccessible source fails the complete read because dropping a competitor
// could change ambiguous ownership into a positive identification.
func ReadKubernetesInventoryInScope(ctx context.Context, sc tenancy.Scope, raw entity.Scope, from, until time.Time,
	memoryBytes int64, authorize func(KubernetesInventorySource) error) (KubernetesInventorySnapshot, error) {
	if from.IsZero() || !until.After(from) {
		return KubernetesInventorySnapshot{}, ErrKubernetesInventoryInput
	}
	return readKubernetesInventory(ctx, sc, raw, from, until, kubernetesInventoryReadRange, memoryBytes, authorize)
}

// ReadKubernetesFlowInventoryInScope widens the original event window by the
// authorized context's recorded maximum flow-to-inventory clock difference.
// An unattested source cannot be used to establish unique address ownership.
func ReadKubernetesFlowInventoryInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, from, until time.Time,
	memoryBytes int64, authorize func(KubernetesInventorySource) error) (KubernetesInventorySnapshot, error) {
	if from.IsZero() || !until.After(from) {
		return KubernetesInventorySnapshot{}, ErrKubernetesInventoryInput
	}
	return readKubernetesInventory(ctx, sc, scope, from, until, kubernetesInventoryReadFlows, memoryBytes, authorize)
}

func (snapshot KubernetesInventorySnapshot) FlowClockError() (time.Duration, bool) {
	if len(snapshot.Sources) == 0 || snapshot.flowIncomplete {
		return 0, false
	}
	var millis int64
	for _, source := range snapshot.Sources {
		if source.FlowClockErrorMS == nil || !validKubernetesFlowClockError(source.FlowClockErrorMS) {
			return 0, false
		}
		millis = max(millis, *source.FlowClockErrorMS)
	}
	return time.Duration(millis) * time.Millisecond, true
}

// ReadKubernetesTopologyInScope selects the original inventory known at an
// explicit time. A zero time selects the last completed Pod observation
// per source, including its actual witness time. A fully observed empty Pod
// list still establishes when supplemental objects were observed.
func ReadKubernetesTopologyInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, at time.Time,
	memoryBytes int64, authorize func(KubernetesInventorySource) error) (KubernetesInventorySnapshot, error) {
	mode := kubernetesInventoryReadPoint
	if at.IsZero() {
		mode = kubernetesInventoryReadLatest
	}
	return readKubernetesInventory(ctx, sc, scope, at, at, mode, memoryBytes, authorize)
}

func readKubernetesInventory(ctx context.Context, sc tenancy.Scope, raw entity.Scope, from, until time.Time,
	mode int, memoryBytes int64, authorize func(KubernetesInventorySource) error) (KubernetesInventorySnapshot, error) {
	scope, err := raw.Normalize()
	tenant, bound := tenancy.FromContext(ctx)
	if err != nil || !bound || tenant != sc.Tenant || tenant.String() != scope.TenantID || sc.Q == nil || authorize == nil {
		return KubernetesInventorySnapshot{}, ErrKubernetesInventoryAuthority
	}
	admission := roleInputAdmission{memory: memoryBytes, work: memoryBytes / 1024}
	if err := admission.charge(ctx, 4096, 1); err != nil {
		return KubernetesInventorySnapshot{}, kubernetesInventoryReadError(err)
	}
	sources, err := readKubernetesInventorySources(ctx, sc, scope, &admission)
	if err != nil {
		return KubernetesInventorySnapshot{}, kubernetesInventoryReadError(err)
	}
	ids := make([]string, 0, len(sources))
	for _, source := range sources {
		if err := authorize(source); err != nil {
			return KubernetesInventorySnapshot{}, err
		}
		ids = append(ids, source.ID)
	}
	out := KubernetesInventorySnapshot{Scope: scope, Sources: sources, flowCohort: mode == kubernetesInventoryReadFlows}
	if len(ids) == 0 {
		return out, ctx.Err()
	}
	if mode == kubernetesInventoryReadFlows {
		clockError, known := out.FlowClockError()
		if !known {
			return out, ctx.Err()
		}
		from, until = from.Add(-clockError), until.Add(clockError)
		// Check visibility without reading any objects from inaccessible
		// sources. A hidden address witness cannot make another owner unique.
		if err := sc.Q.QueryRow(ctx, kubernetesIncompleteFlowWindowsSQL, scope.TenantID, scope.ContextID, from, until, ids).Scan(&out.flowIncomplete); err != nil {
			return KubernetesInventorySnapshot{}, err
		}
		if out.flowIncomplete {
			return out, ctx.Err()
		}
		mode = kubernetesInventoryReadRange
	}
	out.Facts, err = readKubernetesInventoryFacts(ctx, sc, scope, ids, from, until, mode, &admission)
	if err != nil {
		return KubernetesInventorySnapshot{}, kubernetesInventoryReadError(err)
	}
	return out, ctx.Err()
}

func kubernetesInventoryReadError(err error) error {
	if errors.Is(err, entity.ErrInterfaceRoleBudget) {
		return ErrKubernetesInventoryBudget
	}
	return err
}

func readKubernetesInventorySources(ctx context.Context, sc tenancy.Scope, scope entity.Scope, admission *roleInputAdmission) ([]KubernetesInventorySource, error) {
	rows, err := sc.Q.Query(ctx, `
SELECT b.id::text,b.cluster_id::text,b.namespace,b.agent_id,b.flow_clock_error_ms,b.assigned_at
FROM kubernetes_inventory_sources b
JOIN entity_agent_contexts a ON (a.tenant_id,a.agent_id,a.context_id)=(b.tenant_id,b.agent_id,b.context_id)
JOIN agents collector ON collector.tenant_id=b.tenant_id AND collector.id::text=b.agent_id AND collector.status<>'revoked'
JOIN flow_snapshot_epochs epoch ON epoch.tenant_id=b.tenant_id
WHERE b.tenant_id=$1 AND b.context_id=$2 AND b.closed_at IS NULL
  AND NOT epoch.invalidating AND NOT epoch.observation_erasing
  AND b.assigned_at<=transaction_timestamp() AND a.assigned_at<=transaction_timestamp()
  AND (a.expires_at IS NULL OR a.expires_at>transaction_timestamp())
ORDER BY b.id LIMIT $3`, scope.TenantID, scope.ContextID, admission.memory/1024+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []KubernetesInventorySource
	for rows.Next() {
		if err := admission.charge(ctx, 1024, 1); err != nil {
			return nil, err
		}
		source := KubernetesInventorySource{ContextID: scope.ContextID}
		if err := rows.Scan(&source.ID, &source.ClusterID, &source.Namespace, &source.AgentID, &source.FlowClockErrorMS, &source.AssignedAt); err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	return sources, rows.Err()
}

type kubernetesInventoryWindowReference struct {
	SourceID     string    `json:"source_id"`
	GenerationID string    `json:"generation_id"`
	WindowIndex  int64     `json:"window_index"`
	Serial       string    `json:"serial"`
	From         time.Time `json:"valid_from"`
	Until        time.Time `json:"valid_until"`
}

// KubernetesInventoryAuthorityProof is the compact clock and source selection
// for one completed projection. It contains no object labels or addresses.
type KubernetesInventoryAuthorityProof struct {
	Scope      entity.Scope                         `json:"scope"`
	Sources    []KubernetesInventorySource          `json:"sources"`
	Windows    []kubernetesInventoryWindowReference `json:"windows"`
	FlowCohort bool                                 `json:"flow_cohort,omitempty"`
}

func (snapshot KubernetesInventorySnapshot) AuthorityProof(ctx context.Context, memoryBytes int64) (KubernetesInventoryAuthorityProof, error) {
	admission := roleInputAdmission{memory: memoryBytes, work: memoryBytes / 1024}
	scope, original, err := snapshot.projectionSources(ctx, &admission)
	if err != nil {
		return KubernetesInventoryAuthorityProof{}, kubernetesInventoryReadError(err)
	}
	proof := KubernetesInventoryAuthorityProof{Scope: scope, Sources: snapshot.Sources, FlowCohort: snapshot.flowCohort}
	seen := make(map[kubernetesInventoryWindowReference]bool)
	for _, fact := range snapshot.Facts {
		if err := admission.charge(ctx, 0, 1); err != nil {
			return KubernetesInventoryAuthorityProof{}, kubernetesInventoryReadError(err)
		}
		if !fact.validWithinSources(original) {
			return KubernetesInventoryAuthorityProof{}, ErrKubernetesInventoryAuthority
		}
		ref := kubernetesInventoryWindowReference{
			SourceID: fact.SourceID, GenerationID: fact.GenerationID, WindowIndex: fact.WindowIndex,
			Serial: fact.Serial, From: fact.From.UTC(), Until: fact.Until.UTC(),
		}
		if seen[ref] {
			continue
		}
		if err := admission.charge(ctx, 1024, 0); err != nil {
			return KubernetesInventoryAuthorityProof{}, kubernetesInventoryReadError(err)
		}
		seen[ref] = true
		proof.Windows = append(proof.Windows, ref)
	}
	return proof, ctx.Err()
}

// RecheckKubernetesInventoryInScope reauthorizes the original source epochs
// and exact window witnesses in a fresh read snapshot. Later inventory can
// have arrived since the requested observation. It carries no grant to the
// original response and does not change its selected graph or flow inputs.
func RecheckKubernetesInventoryInScope(ctx context.Context, sc tenancy.Scope, snapshot KubernetesInventorySnapshot,
	memoryBytes int64, authorize func(KubernetesInventorySource) error) error {
	proof, err := snapshot.AuthorityProof(ctx, memoryBytes)
	if err != nil {
		return err
	}
	return RecheckKubernetesInventoryProofInScope(ctx, sc, proof, memoryBytes, authorize)
}

func RecheckKubernetesInventoryProofInScope(ctx context.Context, sc tenancy.Scope, proof KubernetesInventoryAuthorityProof,
	memoryBytes int64, authorize func(KubernetesInventorySource) error) error {
	if sc.Q == nil || sc.Tenant.String() != proof.Scope.TenantID || authorize == nil {
		return ErrKubernetesInventoryAuthority
	}
	admission := roleInputAdmission{memory: memoryBytes, work: memoryBytes / 1024}
	snapshot := KubernetesInventorySnapshot{Scope: proof.Scope, Sources: proof.Sources}
	scope, original, err := snapshot.projectionSources(ctx, &admission)
	if err != nil {
		return kubernetesInventoryReadError(err)
	}
	current, err := readKubernetesInventorySources(ctx, sc, scope, &admission)
	if err != nil {
		return kubernetesInventoryReadError(err)
	}
	if proof.FlowCohort && len(current) != len(original) {
		return ErrKubernetesInventoryAuthority
	}
	matched := 0
	for _, source := range current {
		prior, exists := original[source.ID]
		if !exists {
			continue
		}
		if source.AgentID != prior.AgentID || source.ClusterID != prior.ClusterID ||
			source.Namespace != prior.Namespace || !source.AssignedAt.Equal(prior.AssignedAt) ||
			!sameKubernetesClockError(source.FlowClockErrorMS, prior.FlowClockErrorMS) {
			return ErrKubernetesInventoryAuthority
		}
		if err := authorize(source); err != nil {
			return err
		}
		matched++
	}
	if matched != len(original) {
		return ErrKubernetesInventoryAuthority
	}
	return recheckKubernetesInventoryWindows(ctx, sc, scope, original, proof.Windows, &admission)
}

func sameKubernetesClockError(left, right *int64) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func recheckKubernetesInventoryWindows(ctx context.Context, sc tenancy.Scope, scope entity.Scope,
	sources map[string]KubernetesInventorySource, references []kubernetesInventoryWindowReference, admission *roleInputAdmission) error {
	if len(references) == 0 {
		return ctx.Err()
	}
	if int64(len(references)) > admission.memory/1024 {
		return ErrKubernetesInventoryBudget
	}
	seen := make(map[kubernetesInventoryWindowReference]bool)
	for _, ref := range references {
		if err := admission.charge(ctx, 1024, 1); err != nil {
			return kubernetesInventoryReadError(err)
		}
		source, exists := sources[ref.SourceID]
		if !exists || seen[ref] || !canonicalKubernetesUploadID(ref.GenerationID) || ref.WindowIndex < 0 ||
			ref.From.Before(source.AssignedAt) || !ref.Until.After(ref.From) || ref.Serial == "" || len(ref.Serial) > 128 {
			return ErrKubernetesInventoryAuthority
		}
		seen[ref] = true
	}
	wire, err := json.Marshal(references)
	if err != nil {
		return err
	}
	var matched int64
	err = sc.Q.QueryRow(ctx, recheckKubernetesInventoryWindowsSQL, scope.TenantID, scope.ContextID, string(wire)).Scan(&matched)
	if err != nil {
		return err
	}
	if matched != int64(len(references)) {
		return ErrKubernetesInventoryAuthority
	}
	return ctx.Err()
}

const kubernetesInventoryFactBytes = 2048

func readKubernetesInventoryFacts(ctx context.Context, sc tenancy.Scope, scope entity.Scope, ids []string,
	from, until time.Time, mode int, admission *roleInputAdmission) ([]KubernetesInventoryFact, error) {
	rows, err := sc.Q.Query(ctx, kubernetesInventoryFactsSQL,
		scope.TenantID, scope.ContextID, ids, from, until, admission.memory/kubernetesInventoryFactBytes+1, mode)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var facts []KubernetesInventoryFact
	for rows.Next() {
		if err := admission.charge(ctx, kubernetesInventoryFactBytes, 1); err != nil {
			return nil, err
		}
		var fact KubernetesInventoryFact
		var witness, relation, fromKind, toKind int32
		if err := rows.Scan(&fact.SourceID, &fact.GenerationID, &fact.Serial, &fact.WindowIndex, &fact.From, &fact.Until,
			&witness, &fact.WitnessUID, &fact.Name, &fact.Address, &fact.ControllerUnowned, &relation, &fromKind, &fact.FromUID, &toKind, &fact.ToUID,
			&fact.ProjectionAt); err != nil {
			return nil, err
		}
		fact.WitnessKind = agentv1.KubernetesInventoryKind(witness)
		fact.Relationship = agentv1.KubernetesInventoryRelationshipKind(relation)
		fact.FromKind, fact.ToKind = agentv1.KubernetesInventoryKind(fromKind), agentv1.KubernetesInventoryKind(toKind)
		facts = append(facts, fact)
	}
	return facts, rows.Err()
}

// A generation's exact certificate witnesses the original windows. A renewed
// certificate for the same agent supplies no authority over prior windows.
// All three fact families join the same admissible windows under tenant RLS.
const kubernetesCurrentWindowJoins = `
 FROM kubernetes_inventory_sources b
 JOIN entity_agent_contexts a ON (a.tenant_id,a.agent_id,a.context_id)=(b.tenant_id,b.agent_id,b.context_id)
 JOIN agents collector ON collector.tenant_id=b.tenant_id AND collector.id::text=b.agent_id AND collector.status<>'revoked'
 JOIN flow_snapshot_epochs epoch ON epoch.tenant_id=b.tenant_id
 JOIN kubernetes_inventory_windows w ON (w.tenant_id,w.context_id,w.source_id)=(b.tenant_id,b.context_id,b.id)
 JOIN kubernetes_inventory_generations g
   ON (g.tenant_id,g.context_id,g.source_id,g.id)=(w.tenant_id,w.context_id,w.source_id,w.generation_id)
 JOIN agent_identities sender
   ON (sender.tenant_id,sender.agent_id,sender.serial)=(b.tenant_id,b.agent_id,g.sender_serial)
`

const kubernetesCurrentWindowFilters = `
   AND b.closed_at IS NULL AND (a.expires_at IS NULL OR a.expires_at>transaction_timestamp())
   AND NOT epoch.invalidating AND NOT epoch.observation_erasing
   AND sender.spiffe_id='spiffe://probectl/tenant/' || b.tenant_id::text || '/entity/' || b.agent_id
   AND sender.revoked_at IS NULL AND sender.not_after>transaction_timestamp()
   AND w.valid_from>=greatest(b.assigned_at,a.assigned_at,sender.issued_at,epoch.observation_not_before)
   AND w.valid_until<=least(coalesce(a.expires_at,sender.not_after),sender.not_after,transaction_timestamp())
`

const kubernetesIncompleteFlowWindowsSQL = `
SELECT EXISTS (
 SELECT 1 FROM kubernetes_inventory_windows candidate
 WHERE candidate.tenant_id=$1 AND candidate.context_id=$2
   AND candidate.object_kind IN (1,2)
   AND candidate.valid_until>$3 AND candidate.valid_from<$4
   AND EXISTS (
     SELECT 1 FROM kubernetes_inventory_addresses address
     WHERE (address.tenant_id,address.context_id,address.source_id,address.generation_id,address.window_index)=
       (candidate.tenant_id,candidate.context_id,candidate.source_id,candidate.generation_id,candidate.window_index)
   )
   AND NOT EXISTS (SELECT 1` + kubernetesCurrentWindowJoins + `
     WHERE (w.tenant_id,w.context_id,w.source_id,w.generation_id,w.window_index)=
       (candidate.tenant_id,candidate.context_id,candidate.source_id,candidate.generation_id,candidate.window_index)
     AND b.id IN (SELECT unnest($5::text[])::uuid)` + kubernetesCurrentWindowFilters + `
   )
)`

const recheckKubernetesInventoryWindowsSQL = `SELECT count(*)` + kubernetesCurrentWindowJoins + `
 JOIN jsonb_to_recordset($3::jsonb) AS original(source_id uuid,generation_id uuid,window_index bigint,
       serial text,valid_from timestamptz,valid_until timestamptz)
   ON (w.source_id,w.generation_id,w.window_index,g.sender_serial,w.valid_from,w.valid_until)=
      (original.source_id,original.generation_id,original.window_index,original.serial,original.valid_from,original.valid_until)
 WHERE b.tenant_id=$1 AND b.context_id=$2` + kubernetesCurrentWindowFilters

const kubernetesInventoryFactsSQL = `
WITH candidate_windows AS MATERIALIZED (
 SELECT w.tenant_id,w.context_id,w.source_id,w.generation_id,w.window_index,w.object_kind,w.valid_from,w.valid_until,g.sender_serial` +
	kubernetesCurrentWindowJoins + ` WHERE b.tenant_id=$1 AND b.context_id=$2
   AND b.id IN (SELECT unnest($3::text[])::uuid)` + kubernetesCurrentWindowFilters + `
   AND ($7=2 OR (w.valid_until>$4::timestamptz AND
        (w.valid_from<$5::timestamptz OR ($7=1 AND w.valid_from=$4::timestamptz))))
), latest_pods AS (
 SELECT DISTINCT ON (source_id) source_id,generation_id,valid_until-interval '1 microsecond' AS observed_at
 FROM candidate_windows WHERE $7=2 AND object_kind=1
 ORDER BY source_id,valid_until DESC,generation_id
), current_windows AS MATERIALIZED (
 SELECT w.*,CASE WHEN $7=2 THEN latest.observed_at WHEN $7=1 THEN $4::timestamptz END AS projection_at
 FROM candidate_windows w LEFT JOIN latest_pods latest USING (source_id,generation_id)
 WHERE $7<>2 OR (w.valid_from<=latest.observed_at AND latest.observed_at<w.valid_until)
), facts AS (
 SELECT w.source_id,w.generation_id,w.sender_serial,w.window_index,w.valid_from,w.valid_until,
        o.object_kind AS witness_kind,o.object_uid AS witness_uid,o.object_name AS name,''::text AS address,
        o.controller_unowned,0 AS relation,0 AS from_kind,''::text AS from_uid,0 AS to_kind,''::text AS to_uid,w.projection_at
 FROM current_windows w JOIN kubernetes_inventory_objects o USING (tenant_id,context_id,source_id,generation_id,window_index)
 UNION ALL
 SELECT w.source_id,w.generation_id,w.sender_serial,w.window_index,w.valid_from,w.valid_until,
        a.object_kind,a.object_uid,'',a.address_text,false,0,0,'',0,'',w.projection_at
 FROM current_windows w JOIN kubernetes_inventory_addresses a USING (tenant_id,context_id,source_id,generation_id,window_index)
 UNION ALL
 SELECT w.source_id,w.generation_id,w.sender_serial,w.window_index,w.valid_from,w.valid_until,
        r.witness_kind,r.witness_uid,'','',false,r.relationship_kind,r.from_kind,r.from_uid,r.to_kind,r.to_uid,w.projection_at
 FROM current_windows w JOIN kubernetes_inventory_relationships r USING (tenant_id,context_id,source_id,generation_id,window_index)
)
SELECT source_id::text,generation_id::text,sender_serial,window_index,valid_from,valid_until,witness_kind,witness_uid,
       name,address,controller_unowned,relation,from_kind,from_uid,to_kind,to_uid,projection_at
FROM facts ORDER BY source_id,generation_id,window_index,witness_kind,witness_uid,name,address,relation,from_kind,from_uid,to_kind,to_uid
LIMIT $6`
