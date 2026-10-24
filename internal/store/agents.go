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
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Agent is a registered agent. It is tenant-bound (F50): its id and tenant come
// from its mTLS certificate's SPIFFE identity.
type Agent struct {
	ID           string            `json:"id"`
	TenantID     string            `json:"tenant_id"`
	Name         string            `json:"name"`
	Hostname     string            `json:"hostname"`
	AgentVersion string            `json:"agent_version"`
	Status       string            `json:"status"`
	Capabilities []string          `json:"capabilities"`
	Labels       map[string]string `json:"labels"`
	SPIFFEID     string            `json:"spiffe_id"`
	RegisteredAt time.Time         `json:"registered_at"`
	LastSeenAt   *time.Time        `json:"last_seen_at,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	// TestSetVersion is the central test-set version the agent last reported
	// as verified and applied (G9; 0 = none). Surfaced by the fleet view as
	// test_set, next to the tenant's current version.
	TestSetVersion uint64 `json:"-"`
	// L7CapturePosture is the L7 capture posture the agent last reported
	// over its mTLS channel (D-43); nil for agents that never reported one.
	L7CapturePosture *L7CapturePosture `json:"l7_capture_posture,omitempty"`
}

// L7CapturePosture is an eBPF agent's reported L7 capture state (D-43). Every
// string in it came from the agent and was bounded and validated by the
// transport before it was stored; the consent tenant is kept only when it
// equals the agent's own (certificate) tenant.
type L7CapturePosture struct {
	Enabled         bool      `json:"enabled"`
	ConsentTenant   string    `json:"consent_tenant,omitempty"`
	ConsentMismatch bool      `json:"consent_mismatch,omitempty"`
	Scope           []string  `json:"scope"`
	RedactionMode   string    `json:"redaction_mode"`
	EffectiveMode   string    `json:"effective_mode,omitempty"`
	RedactionFloor  string    `json:"redaction_floor,omitempty"`
	Active          bool      `json:"active"`
	State           string    `json:"state"`
	ReportedAt      time.Time `json:"reported_at"`
}

// Consented reports whether the posture states all three consent statements
// (enable, a consent tenant equal to the agent's, a non-empty scope).
func (p L7CapturePosture) Consented() bool {
	return p.Enabled && p.ConsentTenant != "" && len(p.Scope) > 0
}

// SameMaterial reports whether two postures agree on everything an audit
// receipt records: consent, scope, the local and effective modes, the floor
// and the state. ReportedAt and Active alone never make a change material.
func (p L7CapturePosture) SameMaterial(o L7CapturePosture) bool {
	if p.Enabled != o.Enabled || p.ConsentTenant != o.ConsentTenant || p.ConsentMismatch != o.ConsentMismatch ||
		p.RedactionMode != o.RedactionMode || p.EffectiveMode != o.EffectiveMode ||
		p.RedactionFloor != o.RedactionFloor || p.State != o.State || len(p.Scope) != len(o.Scope) {
		return false
	}
	for i := range p.Scope {
		if p.Scope[i] != o.Scope[i] {
			return false
		}
	}
	return true
}

// AgentL7Posture pairs an agent id with its recorded L7 capture posture.
type AgentL7Posture struct {
	AgentID string
	Posture L7CapturePosture
}

// L7CapturePostures lists the scoped tenant's agents that reported an L7
// capture posture, in id order, at most limit (truncated reports more exist).
func (Agents) L7CapturePostures(ctx context.Context, s tenancy.Scope, limit int) ([]AgentL7Posture, bool, error) {
	rows, err := s.Q.Query(ctx,
		`SELECT id::text, l7_capture_posture FROM agents WHERE l7_capture_posture IS NOT NULL ORDER BY id LIMIT $1`, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []AgentL7Posture
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, false, err
		}
		var p L7CapturePosture
		if json.Unmarshal(raw, &p) != nil {
			continue
		}
		out = append(out, AgentL7Posture{AgentID: id, Posture: p})
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	truncated := len(out) > limit
	if truncated {
		out = out[:limit]
	}
	return out, truncated, nil
}

// RecordL7CapturePosture stores an agent's reported L7 capture posture and
// returns the one it replaces (nil when none was recorded). The row is locked
// for the read-compare-write so two concurrent reports cannot both see the
// same prior; RLS confines it to s.Tenant. An apierror NotFound means no such
// agent is registered in this tenant.
func (Agents) RecordL7CapturePosture(ctx context.Context, s tenancy.Scope, id string, p L7CapturePosture) (*L7CapturePosture, error) {
	var raw []byte
	if err := s.Q.QueryRow(ctx, `SELECT l7_capture_posture FROM agents WHERE id = $1 FOR UPDATE`, id).Scan(&raw); err != nil {
		return nil, notFound("agent", err)
	}
	var prior *L7CapturePosture
	if len(raw) > 0 {
		prior = &L7CapturePosture{}
		if err := json.Unmarshal(raw, prior); err != nil {
			prior = nil // an unreadable prior is replaced, and the change is treated as new
		}
	}
	next, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if _, err := s.Q.Exec(ctx, `UPDATE agents SET l7_capture_posture = $2::jsonb WHERE id = $1`, id, string(next)); err != nil {
		return nil, err
	}
	return prior, nil
}

// Agents is the tenant-scoped agent registry.
type Agents struct{}

// ProducerReadiness is the bounded onboarding view for one shipped producer
// plane. Registered means a tenant-scoped registry row exists; Connected means
// that row has completed at least one authenticated transport registration or
// heartbeat; Healthy additionally requires an online, recent heartbeat.
type ProducerReadiness struct {
	ID         string `json:"id"`
	Registered bool   `json:"registered"`
	Connected  bool   `json:"connected"`
	Healthy    bool   `json:"healthy"`
}

const agentCols = `id::text, tenant_id::text, name, hostname, agent_version, status,
	capabilities, labels, spiffe_id, registered_at, last_seen_at, created_at,
	COALESCE(test_set_version, 0), l7_capture_posture`

// AgentOnlineWindow is how long after its last heartbeat or verified batch an
// agent still reads "online" (DPR-082). gRPC agents heartbeat every 30 s and a
// bus collector is touched at most once a minute by the ingest path, so five
// minutes tolerates a missed beat without letting a dead agent stay "online"
// for hours.
const AgentOnlineWindow = 5 * time.Minute

// agentNow is the clock the status derivation reads; tests override it.
var agentNow = time.Now

// deriveStatus turns the stored status into the truth the fleet view owes
// the operator (DPR-082): "online" is a claim about NOW, so it holds only
// while the last heartbeat or verified batch is inside AgentOnlineWindow; an
// agent seen longer ago reads "offline", one never seen reads "registered".
// The stored column is untouched — revoked/registered states pass through.
func deriveStatus(stored string, lastSeen *time.Time, now time.Time) string {
	if stored != "online" {
		return stored
	}
	if lastSeen == nil {
		return "registered"
	}
	if now.Sub(*lastSeen) > AgentOnlineWindow {
		return "offline"
	}
	return "online"
}

func scanAgent(row interface{ Scan(...any) error }, a *Agent) error {
	var caps, labels, posture []byte
	var testSet int64
	if err := row.Scan(&a.ID, &a.TenantID, &a.Name, &a.Hostname, &a.AgentVersion, &a.Status,
		&caps, &labels, &a.SPIFFEID, &a.RegisteredAt, &a.LastSeenAt, &a.CreatedAt, &testSet, &posture); err != nil {
		return err
	}
	if len(posture) > 0 {
		var p L7CapturePosture
		if json.Unmarshal(posture, &p) == nil {
			a.L7CapturePosture = &p
		}
	}
	if testSet > 0 {
		a.TestSetVersion = uint64(testSet)
	}
	a.Status = deriveStatus(a.Status, a.LastSeenAt, agentNow())
	a.Capabilities = []string{}
	a.Labels = map[string]string{}
	if len(caps) > 0 {
		if err := json.Unmarshal(caps, &a.Capabilities); err != nil {
			return err
		}
	}
	if len(labels) > 0 {
		if err := json.Unmarshal(labels, &a.Labels); err != nil {
			return err
		}
	}
	return nil
}

// Reserve records an issued tenant-bound identity without claiming that its
// holder has connected to the mTLS transport. Enrollment calls this after SVID
// issuance so registry binding can fail closed immediately while operational
// readiness remains false until Register or Heartbeat observes the agent.
func (Agents) Reserve(ctx context.Context, s tenancy.Scope, id, name, hostname, version, spiffeID string, capabilities []string) (*Agent, error) {
	if capabilities == nil {
		capabilities = []string{}
	}
	caps, err := json.Marshal(capabilities)
	if err != nil {
		return nil, err
	}
	// CRY-09: a (tenant, name) collision raises SQLSTATE 23505 and ABORTS the
	// enclosing transaction. The savepoint keeps the conflict recoverable so the
	// enrollment path can disambiguate a shared-hostname name and retry, and so a
	// residual collision surfaces as a clean typed Conflict (409) rather than an
	// internal 500. Same idiom as Register.
	savepoint := false
	if _, sErr := s.Q.Exec(ctx, "SAVEPOINT agent_reserve"); sErr == nil {
		savepoint = true
	}
	var a Agent
	err = scanAgent(s.Q.QueryRow(ctx,
		`INSERT INTO agents (id, tenant_id, name, hostname, agent_version, status, capabilities, spiffe_id, last_seen_at)
		 VALUES ($1, $2, $3, $4, $5, 'registered', $6::jsonb, $7, NULL)
		 ON CONFLICT (id) DO UPDATE SET
		   name = EXCLUDED.name, hostname = EXCLUDED.hostname, agent_version = EXCLUDED.agent_version,
		   capabilities = EXCLUDED.capabilities, spiffe_id = EXCLUDED.spiffe_id
		 RETURNING `+agentCols,
		id, s.Tenant.String(), name, hostname, version, string(caps), spiffeID), &a)
	if err != nil {
		if savepoint {
			_, _ = s.Q.Exec(ctx, "ROLLBACK TO SAVEPOINT agent_reserve")
		}
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return nil, apierror.Conflict(fmt.Sprintf("an agent named %q is already registered in this tenant: reuse its agent_id, or enroll with another name", name))
		}
		return nil, err
	}
	if savepoint {
		_, _ = s.Q.Exec(ctx, "RELEASE SAVEPOINT agent_reserve")
	}
	return &a, nil
}

// Register upserts an agent identified by its certificate-derived id, marking
// it online after an authenticated transport registration. It is idempotent —
// an agent may re-register at any time. The id and tenant are authoritative
// (from the verified certificate), so this can never write into another tenant:
// RLS confines the row to s.Tenant.
func (Agents) Register(ctx context.Context, s tenancy.Scope, id, name, hostname, version, spiffeID string, capabilities []string) (*Agent, error) {
	return (Agents{}).RegisterWithLabels(ctx, s, id, name, hostname, version, spiffeID, capabilities, nil)
}

// RegisterWithLabels is Register plus bounded, operator-supplied placement
// metadata. The authenticated mTLS identity remains authoritative for tenant
// and agent id; labels can describe a vantage but can never select a tenant.
func (Agents) RegisterWithLabels(ctx context.Context, s tenancy.Scope, id, name, hostname, version, spiffeID string, capabilities []string, labels map[string]string) (*Agent, error) {
	if capabilities == nil {
		capabilities = []string{}
	}
	caps, err := json.Marshal(capabilities)
	if err != nil {
		return nil, err
	}
	if labels == nil {
		labels = map[string]string{}
	}
	labelJSON, err := json.Marshal(labels)
	if err != nil {
		return nil, err
	}
	// DPR-216: the (tenant, name) uniqueness below raises SQLSTATE 23505, and a
	// raised error ABORTS the enclosing transaction. Returning a friendly typed
	// conflict out of a dead transaction is a promise the caller cannot act on:
	// its next statement — including the documented idempotent re-register of the
	// same agent id — fails with 25P02 "current transaction is aborted". The
	// savepoint keeps the conflict recoverable, which is what a conflict means.
	// Same idiom as touchCredential in credentiallocators.go. If there is no
	// transaction to take a savepoint in, this is a no-op and behavior is
	// exactly as before.
	savepoint := false
	if _, sErr := s.Q.Exec(ctx, "SAVEPOINT agent_register"); sErr == nil {
		savepoint = true
	}
	var a Agent
	err = scanAgent(s.Q.QueryRow(ctx,
		`INSERT INTO agents (id, tenant_id, name, hostname, agent_version, status, capabilities, labels, spiffe_id, last_seen_at)
		 VALUES ($1, $2, $3, $4, $5, 'online', $6::jsonb, $7::jsonb, $8, now())
		 ON CONFLICT (id) DO UPDATE SET
		   name = EXCLUDED.name, hostname = EXCLUDED.hostname, agent_version = EXCLUDED.agent_version,
		   status = 'online', capabilities = EXCLUDED.capabilities, labels = EXCLUDED.labels,
		   spiffe_id = EXCLUDED.spiffe_id,
		   last_seen_at = now()
		 RETURNING `+agentCols,
		id, s.Tenant.String(), name, hostname, version, string(caps), string(labelJSON), spiffeID), &a)
	if err != nil {
		if savepoint {
			// Undo only the failed insert, leaving the caller's transaction alive.
			_, _ = s.Q.Exec(ctx, "ROLLBACK TO SAVEPOINT agent_register")
		}
		// DPR-048: the (tenant, name) uniqueness is a conflict the operator can
		// act on — reuse the existing registration or pick another name — not
		// a raw SQLSTATE 23505 for the CLI to print.
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return nil, apierror.Conflict(fmt.Sprintf("an agent or collector named %q is already registered in this tenant: reuse its agent_id, or register with another name", name))
		}
		return nil, err
	}
	if savepoint {
		_, _ = s.Q.Exec(ctx, "RELEASE SAVEPOINT agent_register")
	}
	return &a, nil
}

// RecordVersion stores the build version a verified batch reported for an
// agent (DPR-093). A no-op when the registry already holds it.
func (Agents) RecordVersion(ctx context.Context, s tenancy.Scope, id, version string) error {
	if version == "" {
		return nil
	}
	_, err := s.Q.Exec(ctx,
		`UPDATE agents SET agent_version = $2 WHERE id = $1 AND agent_version IS DISTINCT FROM $2`, id, version)
	return err
}

// HeartbeatVersion is Heartbeat for a producer that knows its own build
// version (the BMP listener, DPR-093): liveness and version in one touch.
func (Agents) HeartbeatVersion(ctx context.Context, s tenancy.Scope, id, version string) (*Agent, error) {
	var a Agent
	if err := scanAgent(s.Q.QueryRow(ctx,
		`UPDATE agents SET status = 'online', last_seen_at = now(),
		        agent_version = CASE WHEN $2 = '' THEN agent_version ELSE $2 END
		  WHERE id = $1 RETURNING `+agentCols, id, version), &a); err != nil {
		return nil, notFound("agent", err)
	}
	return &a, nil
}

// Heartbeat marks an agent online and records the time it was last seen.
func (Agents) Heartbeat(ctx context.Context, s tenancy.Scope, id string) (*Agent, error) {
	var a Agent
	if err := scanAgent(s.Q.QueryRow(ctx,
		`UPDATE agents SET status = 'online', last_seen_at = now() WHERE id = $1 RETURNING `+agentCols, id), &a); err != nil {
		return nil, notFound("agent", err)
	}
	return &a, nil
}

// Get returns an agent by id (RLS guarantees it belongs to the tenant).
func (Agents) Get(ctx context.Context, s tenancy.Scope, id string) (*Agent, error) {
	var a Agent
	if err := scanAgent(s.Q.QueryRow(ctx,
		`SELECT `+agentCols+` FROM agents WHERE id = $1`, id), &a); err != nil {
		return nil, notFound("agent", err)
	}
	return &a, nil
}

// ExistingIDs returns the subset of ids that are enrolled agents of the scoped
// tenant, as a set, in one query (RLS fences the result to the tenant). Callers
// must pass well-formed UUIDs — agents.id is uuid-typed, and a malformed value
// would raise a 22P02 that aborts the tenant transaction.
func (Agents) ExistingIDs(ctx context.Context, s tenancy.Scope, ids []string) (map[string]struct{}, error) {
	present := make(map[string]struct{}, len(ids))
	if len(ids) == 0 {
		return present, nil
	}
	rows, err := s.Q.Query(ctx, `SELECT id FROM agents WHERE id = ANY($1::uuid[])`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		present[id] = struct{}{}
	}
	return present, rows.Err()
}

// ProducerReadiness reports all six shipped producer planes in a fixed-size
// query. The query runs through the tenant transaction, so Postgres RLS is the
// outer boundary; application code never receives another tenant's agents.
func (Agents) ProducerReadiness(ctx context.Context, s tenancy.Scope, freshAfter time.Time) ([]ProducerReadiness, error) {
	rows, err := s.Q.Query(ctx, `
		WITH planes(id) AS (
			VALUES ('synthetic'), ('flow'), ('bgp'), ('device'), ('ebpf'), ('endpoint')
		), matching AS (
			SELECT p.id, a.status, a.last_seen_at
			FROM planes p
			LEFT JOIN agents a ON CASE
				WHEN p.id = 'synthetic' THEN
					NOT (a.capabilities ? 'collector') OR
					a.capabilities ?| ARRAY['icmp', 'tcp', 'udp', 'http', 'dns', 'browser', 'voice']
				ELSE a.capabilities ? p.id
			END
		)
		SELECT id,
		       count(status) > 0,
		       count(last_seen_at) > 0,
		       count(*) FILTER (WHERE status = 'online' AND last_seen_at >= $1) > 0
		FROM matching
		GROUP BY id
		ORDER BY CASE id
			WHEN 'synthetic' THEN 0 WHEN 'flow' THEN 1 WHEN 'bgp' THEN 2
			WHEN 'device' THEN 3 WHEN 'ebpf' THEN 4 ELSE 5 END`, freshAfter)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ProducerReadiness, 0, 6)
	for rows.Next() {
		var readiness ProducerReadiness
		if err := rows.Scan(&readiness.ID, &readiness.Registered, &readiness.Connected, &readiness.Healthy); err != nil {
			return nil, err
		}
		out = append(out, readiness)
	}
	return out, rows.Err()
}

// Rename updates an agent's display name (the agent's id and tenant remain
// certificate-derived; only the human label is editable via the API).
func (Agents) Rename(ctx context.Context, s tenancy.Scope, id, name string) (*Agent, error) {
	var a Agent
	if err := scanAgent(s.Q.QueryRow(ctx,
		`UPDATE agents SET name = $2 WHERE id = $1 RETURNING `+agentCols, id, name), &a); err != nil {
		return nil, notFound("agent", err)
	}
	return &a, nil
}

// Delete deregisters an agent. The agent will re-create its registration if it
// reconnects; this removes the current record (e.g. for a decommissioned host).
func (Agents) Delete(ctx context.Context, s tenancy.Scope, id string) error {
	tag, err := s.Q.Exec(ctx, `DELETE FROM agents WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return apierror.NotFound("agent not found")
	}
	return nil
}

// list returns the tenant's agents.
func (Agents) list(ctx context.Context, s tenancy.Scope) ([]Agent, error) {
	rows, err := s.Q.Query(ctx, `SELECT `+agentCols+` FROM agents ORDER BY registered_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		var a Agent
		if err := scanAgent(rows, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DefaultAgentPageSize bounds an unspecified agents page (SCALE-010).
const DefaultAgentPageSize = 200

// ListPage returns one cursor page of agents ordered by id, starting AFTER the
// given cursor id (empty = first page), capped at limit (SCALE-010). Cursor
// pagination keeps a fleet-scale /v1/agents response bounded — the unbounded
// list() loaded every row, which falls over at 10k+ agents. The id ordering is
// stable (UUID PK), so the next cursor is simply the last returned id.
func (Agents) ListPage(ctx context.Context, s tenancy.Scope, afterID string, limit int) ([]Agent, error) {
	if limit <= 0 || limit > 1000 {
		limit = DefaultAgentPageSize
	}
	// SCALE-002/012: empty cursor = first page. id is a uuid PK; binding "" to
	// `id > $1` makes Postgres reject the empty string as uuid (SQLSTATE 22P02),
	// so omit the cursor predicate on the first page.
	q := `SELECT ` + agentCols + ` FROM agents WHERE id > $1 ORDER BY id LIMIT $2`
	args := []any{afterID, limit}
	if afterID == "" {
		q = `SELECT ` + agentCols + ` FROM agents ORDER BY id LIMIT $1`
		args = []any{limit}
	}
	rows, err := s.Q.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		var a Agent
		if err := scanAgent(rows, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// HeartbeatBatchVersions marks a WINDOW of agents online in one statement
// (Sprint 14, SCALE-012): the per-RPC UPDATE scaled linearly with fleet size;
// the transport now coalesces heartbeats and flushes per tenant. Within-window
// heartbeats collapse (same now()) — exactly the wanted semantics. It also
// records the central test-set version each agent reported as verified and
// applied (G9), so GET /v1/agents can say whether the agent runs the tenant's
// current tests. ids and versions are parallel slices.
func (Agents) HeartbeatBatchVersions(ctx context.Context, s tenancy.Scope, ids []string, versions []uint64) error {
	if len(ids) == 0 {
		return nil
	}
	if len(ids) != len(versions) {
		return apierror.Internal("heartbeat batch ids and versions differ in length")
	}
	vs := make([]int64, len(versions))
	for i, v := range versions {
		vs[i] = int64(v)
	}
	_, err := s.Q.Exec(ctx,
		`UPDATE agents AS a SET status = 'online', last_seen_at = now(), test_set_version = v.ver
		   FROM unnest($1::uuid[], $2::bigint[]) AS v(id, ver)
		  WHERE a.id = v.id`, ids, vs)
	return err
}
