// SPDX-License-Identifier: LicenseRef-probectl-TBD

package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// Agent is a registered agent. It is tenant-bound (F50): its id and tenant come
// from its mTLS certificate's SPIFFE identity.
type Agent struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id"`
	Name         string     `json:"name"`
	Hostname     string     `json:"hostname"`
	AgentVersion string     `json:"agent_version"`
	Status       string     `json:"status"`
	Capabilities []string   `json:"capabilities"`
	SPIFFEID     string     `json:"spiffe_id"`
	RegisteredAt time.Time  `json:"registered_at"`
	LastSeenAt   *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// Agents is the tenant-scoped agent registry.
type Agents struct{}

const agentCols = `id::text, tenant_id::text, name, hostname, agent_version, status,
	capabilities, spiffe_id, registered_at, last_seen_at, created_at`

func scanAgent(row interface{ Scan(...any) error }, a *Agent) error {
	var caps []byte
	if err := row.Scan(&a.ID, &a.TenantID, &a.Name, &a.Hostname, &a.AgentVersion, &a.Status,
		&caps, &a.SPIFFEID, &a.RegisteredAt, &a.LastSeenAt, &a.CreatedAt); err != nil {
		return err
	}
	a.Capabilities = []string{}
	if len(caps) > 0 {
		if err := json.Unmarshal(caps, &a.Capabilities); err != nil {
			return err
		}
	}
	return nil
}

// Register upserts an agent identified by its certificate-derived id, marking it
// online. It is idempotent — an agent may re-register at any time. The id and
// tenant are authoritative (from the verified certificate), so this can never
// write into another tenant: RLS confines the row to s.Tenant.
func (Agents) Register(ctx context.Context, s tenancy.Scope, id, name, hostname, version, spiffeID string, capabilities []string) (*Agent, error) {
	if capabilities == nil {
		capabilities = []string{}
	}
	caps, err := json.Marshal(capabilities)
	if err != nil {
		return nil, err
	}
	var a Agent
	err = scanAgent(s.Q.QueryRow(ctx,
		`INSERT INTO agents (id, tenant_id, name, hostname, agent_version, status, capabilities, spiffe_id, last_seen_at)
		 VALUES ($1, $2, $3, $4, $5, 'online', $6::jsonb, $7, now())
		 ON CONFLICT (id) DO UPDATE SET
		   name = EXCLUDED.name, hostname = EXCLUDED.hostname, agent_version = EXCLUDED.agent_version,
		   status = 'online', capabilities = EXCLUDED.capabilities, spiffe_id = EXCLUDED.spiffe_id,
		   last_seen_at = now()
		 RETURNING `+agentCols,
		id, s.Tenant.String(), name, hostname, version, string(caps), spiffeID), &a)
	if err != nil {
		return nil, err
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

// List returns the tenant's agents.
func (Agents) List(ctx context.Context, s tenancy.Scope) ([]Agent, error) {
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
// List() loaded every row, which falls over at 10k+ agents. The id ordering is
// stable (UUID PK), so the next cursor is simply the last returned id.
func (Agents) ListPage(ctx context.Context, s tenancy.Scope, afterID string, limit int) ([]Agent, error) {
	if limit <= 0 || limit > 1000 {
		limit = DefaultAgentPageSize
	}
	rows, err := s.Q.Query(ctx,
		`SELECT `+agentCols+` FROM agents WHERE id > $1 ORDER BY id LIMIT $2`, afterID, limit)
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

// HeartbeatBatch marks a WINDOW of agents online in one statement (Sprint 14,
// SCALE-012): the per-RPC UPDATE scaled linearly with fleet size; the
// transport now coalesces heartbeats and flushes per tenant. Within-window
// heartbeats collapse (same now()) — exactly the wanted semantics.
func (Agents) HeartbeatBatch(ctx context.Context, s tenancy.Scope, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.Q.Exec(ctx,
		`UPDATE agents SET status = 'online', last_seen_at = now() WHERE id = ANY($1)`, ids)
	return err
}
