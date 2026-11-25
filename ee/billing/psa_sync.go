// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package billing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/notify"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type haloBillingRoute struct {
	Tenant string `json:"tenant_id"`
	Origin string `json:"origin"`
	HaloSubscriptions
	notify.HaloCredentials
}

// PSASync exports one scoped inventory snapshot at a time to the MSP's PSA.
type PSASync struct {
	pool     *pgxpool.Pool
	routes   []psaBillingRoute
	canWrite func() bool
	log      *slog.Logger
}

type psaBillingRoute struct {
	tenant string
	vendor string
	run    func(context.Context) error
}

// PSAConfigurations contains resolved deployment secret payloads.
type PSAConfigurations struct {
	Halo     []byte
	Autotask []byte
}

const (
	psaSyncInterval  = 15 * time.Minute
	psaSyncTimeout   = 45 * time.Second
	psaTenantLockKey = "hashtextextended('billing-psa:' || $1::text, 0)"
)

var (
	errPSABillingReadOnly  = errors.New("billing: commercial writes are read-only")
	errPSABillingBusy      = errors.New("billing: another sync owns this tenant")
	errPSAInventoryChanged = errors.New("billing: inventory changed before the PSA update")
)

// NewPSASync consumes the resolved deployment configuration after the MSP
// entitlement gate. Configuration errors never include credentials or URLs.
func NewPSASync(raw PSAConfigurations, pool *pgxpool.Pool, canWrite func() bool, log *slog.Logger, client notify.Doer) (*PSASync, error) {
	if pool == nil || canWrite == nil {
		return nil, errors.New("billing: PSA sync requires tenant storage and commercial write authority")
	}
	halo, err := decodePSARoutes[haloBillingRoute](raw.Halo)
	if err != nil {
		return nil, fmt.Errorf("billing: Halo configuration: %w", err)
	}
	autotask, err := decodePSARoutes[autotaskBillingRoute](raw.Autotask)
	if err != nil {
		return nil, fmt.Errorf("billing: Autotask configuration: %w", err)
	}
	if log == nil {
		log = slog.Default()
	}
	worker := &PSASync{pool: pool, canWrite: canWrite, log: log}
	tenants := make(map[string]bool, len(halo)+len(autotask))
	if err := worker.addHaloRoutes(halo, tenants, client); err != nil {
		return nil, err
	}
	if err := worker.addAutotaskRoutes(autotask, tenants, client); err != nil {
		return nil, err
	}
	return worker, nil
}

func decodePSARoutes[T any](raw []byte) ([]T, error) {
	if raw == nil {
		return nil, nil
	}
	var mappings []T
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&mappings) != nil || decoder.Decode(new(json.RawMessage)) != io.EOF || mappings == nil {
		return nil, errors.New("expected a JSON list of billing routes")
	}
	return mappings, nil
}

func validateBillingTenant(value string, used map[string]bool) error {
	tenant, err := uuid.Parse(value)
	if err != nil || tenant == uuid.Nil || tenant.String() != value {
		return errors.New("requires a canonical tenant UUID")
	}
	if used[value] {
		return errors.New("repeats a tenant already mapped for PSA billing")
	}
	return nil
}

func (s *PSASync) addHaloRoutes(mappings []haloBillingRoute, tenants map[string]bool, client notify.Doer) error {
	type subscription struct {
		instance string
		id       int32
	}
	destinations := map[subscription]bool{}
	for i, mapping := range mappings {
		if err := validateBillingTenant(mapping.Tenant, tenants); err != nil {
			return fmt.Errorf("billing: Halo route %d: %w", i+1, err)
		}
		writer, err := NewHaloBillingWriter(mapping.Tenant, mapping.Origin, mapping.HaloCredentials, mapping.HaloSubscriptions, client)
		if err != nil {
			return fmt.Errorf("billing: Halo route %d: %w", i+1, err)
		}
		instance, err := psaOriginKey(mapping.Origin)
		if err != nil {
			return fmt.Errorf("billing: Halo route %d: %w", i+1, err)
		}
		for _, id := range []int32{mapping.DevicesSubscription, mapping.AgentsSubscription} {
			to := subscription{instance, id}
			if destinations[to] {
				return fmt.Errorf("billing: Halo route %d reuses a subscription", i+1)
			}
			destinations[to] = true
		}
		tenants[mapping.Tenant] = true
		s.routes = append(s.routes, psaBillingRoute{tenant: mapping.Tenant, vendor: "halopsa", run: func(ctx context.Context) error {
			return s.syncTenant(ctx, writer)
		}})
	}
	return nil
}

func psaOriginKey(origin string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		return "", errors.New("billing: invalid PSA instance")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	port := 443
	if raw := u.Port(); raw != "" {
		port, err = strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 {
			return "", errors.New("billing: invalid PSA instance port")
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// Run reconciles under the deployment singleton's leadership and fencing
// context. Only tenants configured by the MSP are visited.
func (s *PSASync) Run(ctx context.Context) {
	s.reconcile(ctx)
	ticker := time.NewTicker(psaSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reconcile(ctx)
		}
	}
}

func (s *PSASync) reconcile(ctx context.Context) {
	for _, route := range s.routes {
		if ctx.Err() != nil || !s.canWrite() {
			return
		}
		op, cancel := context.WithTimeout(ctx, psaSyncTimeout)
		err := route.run(op)
		cancel()
		if err != nil && !errors.Is(err, errPSABillingBusy) {
			s.log.Warn("billing: PSA sync deferred", "tenant_id", route.tenant, "vendor", route.vendor, "error", err)
		}
	}
}

func (s *PSASync) syncTenant(ctx context.Context, route *HaloBillingWriter) error {
	if err := s.checkWrite(ctx); err != nil {
		return err
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(route.tenant))
	var counts PSAQuantities
	hasChanges := false
	err := s.withEgress(ctx, func(ctx context.Context, scope tenancy.Scope) error {
		var err error
		counts, err = psaInventory(ctx, scope)
		if err != nil {
			return err
		}
		_, changes, err := route.quantityChanges(ctx, scope.Tenant.String(), counts)
		hasChanges = len(changes) != 0
		return err
	})
	if err != nil || !hasChanges {
		return err
	}

	// Commit the intent before external mutation. The tenant audit transition
	// and the egress lease run in separate transactions so no second connection
	// waits for a lock already held by this operation.
	started, err := s.record(ctx, "billing.psa.sync.requested", map[string]any{
		"devices":                 counts.Devices,
		"agents":                  counts.Agents,
		"customer_id":             route.subscriptions.CustomerID,
		"devices_subscription_id": route.subscriptions.DevicesSubscription,
		"agents_subscription_id":  route.subscriptions.AgentsSubscription,
	})
	if err != nil {
		return err
	}
	changed := false
	writeErr := s.withEgress(ctx, func(ctx context.Context, scope tenancy.Scope) error {
		current, err := psaInventory(ctx, scope)
		if err != nil {
			return err
		}
		if current != counts {
			return errPSAInventoryChanged
		}
		changed, err = route.sync(ctx, scope.Tenant.String(), counts, func() error {
			if err := tenancy.RequireTenantCollection(ctx, scope); err != nil {
				return err
			}
			return s.checkWrite(ctx)
		})
		return err
	})
	outcome := "already_current"
	switch {
	case writeErr != nil:
		outcome = "unconfirmed"
	case changed:
		outcome = "confirmed"
	}
	_, recordErr := s.record(ctx, "billing.psa.sync.result", map[string]any{
		"request_seq": started,
		"outcome":     outcome,
	})
	return errors.Join(writeErr, recordErr)
}

func (s *PSASync) checkWrite(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.canWrite() {
		return errPSABillingReadOnly
	}
	return nil
}

func (s *PSASync) record(ctx context.Context, action string, data map[string]any) (int64, error) {
	var seq int64
	err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, scope tenancy.Scope) error {
		event, err := audit.TenantAppend(ctx, scope, "system:psa-billing", action, "halopsa", data)
		seq = event.Seq
		return err
	})
	return seq, err
}

// withEgress holds the tenant lifecycle and PSA writer locks for each bounded
// vendor operation. Keep the singleton epoch lock on the short audit
// transactions only, so a slow vendor cannot block the cluster heartbeat.
func (s *PSASync) withEgress(ctx context.Context, run func(context.Context, tenancy.Scope) error) error {
	return tenancy.InTenant(tenancy.WithTxGuard(ctx, nil), s.pool, func(ctx context.Context, scope tenancy.Scope) error {
		if err := tenancy.RequireTenantCollection(ctx, scope); err != nil {
			return err
		}
		var acquired bool
		if err := scope.Q.QueryRow(ctx,
			`SELECT pg_try_advisory_xact_lock(`+psaTenantLockKey+`)`,
			scope.Tenant.String()).Scan(&acquired); err != nil {
			return err
		}
		if !acquired {
			return errPSABillingBusy
		}
		if err := s.checkWrite(ctx); err != nil {
			return err
		}
		return run(ctx, scope)
	})
}

func psaInventory(ctx context.Context, scope tenancy.Scope) (PSAQuantities, error) {
	var counts PSAQuantities
	// The query reads one statement snapshot. An active device target needs
	// both a current agent/context binding and a canonical device anchor.
	// Multiple valid pollers for one device count once in its routing context.
	// Use the same permanent-revocation predicate as AgentIdentities.IsAgentRevoked.
	const sql = `
WITH registered_agents AS (
    SELECT a.id, a.tenant_id FROM agents a
    WHERE a.tenant_id = $1 AND NOT EXISTS (
        SELECT 1 FROM agent_identities revoked
        WHERE revoked.tenant_id = a.tenant_id AND revoked.agent_id = a.id::text
          AND revoked.revoked_at IS NOT NULL
          AND revoked.revoked_by IS DISTINCT FROM 'entity_registry_delete'
    )
)
SELECT (
    SELECT count(DISTINCT (src.context_id, src.anchor_entity_id))
    FROM entity_source_contexts src
    JOIN entity_agent_contexts ac
      ON (ac.tenant_id, ac.agent_id, ac.context_id) = (src.tenant_id, src.agent_id, src.context_id)
    JOIN entities device
      ON (device.tenant_id, device.context_id, device.id) = (src.tenant_id, src.context_id, src.anchor_entity_id)
    JOIN registered_agents agent ON agent.tenant_id = src.tenant_id AND agent.id::text = src.agent_id
    WHERE src.tenant_id = $1 AND src.source_kind = 'device_target' AND device.kind = 'device'
      AND src.assigned_at <= statement_timestamp()
      AND (src.expires_at IS NULL OR statement_timestamp() < src.expires_at)
      AND ac.assigned_at <= statement_timestamp()
      AND (ac.expires_at IS NULL OR statement_timestamp() < ac.expires_at)
), (
    SELECT count(*) FROM registered_agents
)`
	err := scope.Q.QueryRow(ctx, sql, scope.Tenant.String()).Scan(&counts.Devices, &counts.Agents)
	return counts, err
}
