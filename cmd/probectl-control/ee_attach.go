// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build !probectl_core

// Commercial linkage seam: imported ee/ source is governed separately by
// ee/LICENSE; this MPL-licensed wiring file grants no rights to that source.
//
// This file is THE sanctioned ee attach seam (allowlisted in
// scripts/check_editions_imports.sh): the one place core meets ee/. The
// default build links the commercial tree (one repo, one binary lineage —
// runtime activation is license-gated, never source-gated); the core-only CI
// build (-tags probectl_core) compiles the no-op twin in ee_attach_core.go
// instead, proving core stands alone with ee/ absent.

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/ee/billing"
	"github.com/ctlplne/probectl/ee/governance"
	"github.com/ctlplne/probectl/ee/provider"
	eeremediation "github.com/ctlplne/probectl/ee/remediation"
	"github.com/ctlplne/probectl/ee/silo"
	"github.com/ctlplne/probectl/ee/tenantkeys"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/cluster"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/store/ebpfstore"
	"github.com/ctlplne/probectl/internal/store/endpointstore"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/otelstore"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
	"github.com/ctlplne/probectl/internal/tenantlife"
	"github.com/ctlplne/probectl/internal/topology"
	"github.com/ctlplne/probectl/internal/usage"
)

// attachEE wires licensed ee/ features onto the core server — the Build* seam
// pattern (CLAUDE.md §6, editions): one Has() check per feature, here and
// nowhere else. Unlicensed features are simply never constructed; their
// surfaces stay hidden (404).
func attachEE(ctx context.Context, srv *control.Server, cfg *config.Config, log *slog.Logger,
	lic *license.Manager, pool *pgxpool.Pool, results *control.LatestResults,
	flowStore flowstore.Store, pathCH *pathstore.ClickHouse, ebpfStore ebpfstore.Store, otelStore otelstore.Store, endpointStore endpointstore.Store,
	life *tenantlife.Engine,
	worm *audit.WormExporter,
	resolveSecret func(context.Context, string) ([]byte, func(), error),
	fairGate *fairness.Gate, topoStore topology.Store,
	singletons *cluster.Coordinator) error {
	// One dynamic lifecycle capability is shared by every attached commercial
	// mutation adapter. Entitlement stays in the Has checks below; this method
	// value re-evaluates the license clock on every write, so active/grace can
	// become read-only without rebuilding or restarting the server.
	writeCapability := lic.WriteCapability()

	// Siloed/hybrid isolation (S-T2). Attached BEFORE the provider plane so
	// tenant provisioning can create isolated stores from the first call.
	var siloOps provider.SiloOps
	var routerInvalidate func()
	if lic.Has(license.FeatureSiloedIsolation) {
		planes, err := silo.ParseDataPlanes(cfg.DataPlanes)
		if err != nil {
			return err
		}
		// The ClickHouse leg exists per plane only when that store runs
		// ClickHouse; memory stores are process-local (logically tenant-keyed).
		// TENANT-001: ALL FOUR planes (flow/path/eBPF/otel) get the silo router
		// and a per-tenant database, not flow alone.
		router := silo.NewRouter(pool, planes, 0)

		var ch silo.CHPlanes
		var flowCH *flowstore.ClickHouse
		var ebpfCH *ebpfstore.ClickHouse
		var otelCH *otelstore.ClickHouse
		var endpointCH *endpointstore.ClickHouse
		if c, ok := flowstore.ClickHouseStore(flowStore); ok {
			flowCH, ch.Flows = c, c
			c.WithRouter(func(ctx context.Context, tenantID string) (flowstore.Target, error) {
				t, err := router.TargetsFor(ctx, tenantID)
				if err != nil {
					return flowstore.Target{}, err
				}
				return flowstore.Target{BaseURL: t.CHBaseURL, Database: t.CHDatabase}, nil
			})
		}
		if pathCH != nil {
			ch.Paths = pathCH
			pathCH.WithRouter(func(ctx context.Context, tenantID string) (pathstore.Target, error) {
				t, err := router.TargetsFor(ctx, tenantID)
				if err != nil {
					return pathstore.Target{}, err
				}
				return pathstore.Target{BaseURL: t.CHBaseURL, Database: t.CHDatabase}, nil
			})
		}
		if c, ok := ebpfstore.ClickHouseStore(ebpfStore); ok {
			ebpfCH, ch.EBPF = c, c
			c.WithRouter(func(ctx context.Context, tenantID string) (ebpfstore.Target, error) {
				t, err := router.TargetsFor(ctx, tenantID)
				if err != nil {
					return ebpfstore.Target{}, err
				}
				return ebpfstore.Target{BaseURL: t.CHBaseURL, Database: t.CHDatabase}, nil
			})
		}
		if c, ok := otelstore.ClickHouseStore(otelStore); ok {
			otelCH, ch.Otel = c, c
			c.WithRouter(func(ctx context.Context, tenantID string) (otelstore.Target, error) {
				t, err := router.TargetsFor(ctx, tenantID)
				if err != nil {
					return otelstore.Target{}, err
				}
				return otelstore.Target{BaseURL: t.CHBaseURL, Database: t.CHDatabase}, nil
			})
		}
		if c, ok := endpointstore.ClickHouseStore(endpointStore); ok {
			endpointCH, ch.Endpoint = c, c
			c.WithRouter(func(ctx context.Context, tenantID string) (endpointstore.Target, error) {
				t, err := router.TargetsFor(ctx, tenantID)
				if err != nil {
					return endpointstore.Target{}, err
				}
				return endpointstore.Target{BaseURL: t.CHBaseURL, Database: t.CHDatabase}, nil
			})
		}
		prov := silo.NewProvisioner(pool, ch, planes, cfg.FlowRetentionDays, log).
			WithEndpointRetentionDays(cfg.EndpointRetentionDays)
		// Startup catch-up is a routing precondition (ARCH-001): a siloed tenant
		// must not become routable until its storage/query-layer schema is at the
		// current public shape. Idempotent DDL keeps retries safe; failures keep
		// the control plane from serving a stale silo.
		if err := siloCatchUpAll(ctx, pool, prov, log); err != nil {
			return fmt.Errorf("silo catch-up before routing: %w", err)
		}
		tenancy.SetRouter(router) // Postgres search_path + bus lanes + object prefixes
		siloOps, routerInvalidate = prov, router.Invalidate
		log.Info("siloed/hybrid isolation attached (S-T2; TENANT-001 all planes)",
			"data_planes", silo.PlaneNames(planes),
			"flow_routed", flowCH != nil, "path_routed", pathCH != nil,
			"ebpf_routed", ebpfCH != nil, "otel_routed", otelCH != nil, "endpoint_routed", endpointCH != nil)
	}

	// Per-tenant metering + quotas (S-T3). The recorder hooks the core usage
	// seam (results/flows/AI calls meter as they already flow); the collector
	// snapshots per-tenant gauges INSIDE each tenant's own scope; the quota
	// checker gates resource creation (telemetry is never quota-dropped).
	var metering *provider.Metering
	if lic.Has(license.FeatureMetering) {
		bstore := billing.NewPGStore(pool)
		recorder := billing.NewRecorder(bstore, log)
		usage.SetRecorder(recorder)
		checker := billing.NewQuotaChecker(bstore, billing.PGTenantCounter(pool), 30*time.Second)
		usage.SetQuotaChecker(checker)
		collector := billing.NewCollector(bstore, billing.PGTenantLister(pool), billing.PGTenantCounter(pool), log)
		go recorder.Run(ctx, time.Minute)
		go collector.Run(ctx, 15*time.Minute)
		metering = &provider.Metering{Store: bstore, Quotas: checker}
		log.Info("per-tenant metering attached (S-T3)", "flush", "1m", "snapshot", "15m")
	}

	// Per-tenant key isolation / BYOK (S-T6). The keyring replaces the
	// deployment envelope as the PRIMARY sealer; the deployment sealer stays
	// registered as an opener (main installed it), so pre-existing dv1 rows
	// keep decrypting — decrypt-on-read, no migration. BYOK references
	// resolve through the S41 secrets resolver at use time and are validated
	// resolvable BEFORE activation (the lockout guard in ee/tenantkeys).
	if lic.Has(license.FeatureBYOK) {
		if cfg.EnvelopeKey == "" {
			// Fail loudly: a licensed byok deployment without a master KEK
			// would silently store managed tenant KEKs unprotectable.
			return fmt.Errorf("byok is licensed but PROBECTL_ENVELOPE_KEY is not set (the deployment master wraps managed tenant keys)")
		}
		kp, err := crypto.NewStaticKeyProviderFromBase64(cfg.EnvelopeKeyID, cfg.EnvelopeKey)
		if err != nil {
			return fmt.Errorf("byok master key: %w", err)
		}
		ring, err := tenantkeys.NewKeyring(tenantkeys.NewPGStore(pool), crypto.NewEnvelope(kp), tenantkeys.RefResolver(resolveSecret))
		if err != nil {
			return err
		}
		tenantcrypto.SetPrimary(ring) // dv1 opener stays registered (main)
		srv.WithKeyManager(tenantcrypto.GateKeyManagerWrites(tenantkeys.NewManager(ring), writeCapability))
		log.Info("per-tenant key isolation attached (S-T6)", "scheme", "tk1", "modes", "managed|byok")
	}

	// Advanced data governance (S-EE3). The governance feature installs the
	// per-tenant classification + redaction POLICY onto the core govern seam
	// (so redacted exports honor per-tenant overrides) and exposes the
	// composed governance view on the provider plane. Classification +
	// redaction MECHANISM is core; this is the policy + surface.
	var governanceCap *provider.Governance
	if lic.Has(license.FeatureGovernance) {
		gstore := governance.NewStore(pool)
		govern.SetSource(gstore)
		governanceCap = &provider.Governance{Store: gstore, Pool: pool}
		log.Info("advanced data governance attached (S-EE3)")
	}

	// Guarded agentic remediation (S-EE5, F44 — guardrail-critical). The AI
	// PROPOSES; a human APPROVES; probectl NEVER executes — there is NO executor
	// in the codebase. The dry-run blast radius is a READ-ONLY S43 topology
	// what-if; approvals are advisory-only by default (the master switch off)
	// and the full propose→approve→reject trail is written to the tenant's
	// tamper-evident audit stream. Unlicensed: the whole surface 404s.
	if lic.Has(license.FeatureRemediation) {
		estimator := eeremediation.NewTopologyEstimator(topoStore, nil) // SLO impact optional
		remed := eeremediation.New(eeremediation.NewPGStore(pool), estimator, eeremediation.NewTenantAudit(pool), eeremediation.Config{
			ApprovalsEnabled: cfg.RemediationApprovalsEnabled,
			MaxBlastRadius:   cfg.RemediationMaxBlastRadius,
		})
		srv.WithRemediation(remediation.GateServiceWrites(remed, writeCapability))
		log.Info("guarded remediation attached (S-EE5)",
			"approvals_enabled", cfg.RemediationApprovalsEnabled,
			"max_blast_radius", cfg.RemediationMaxBlastRadius)
	}

	if lic.Has(license.FeatureProviderPlane) {
		irSidecar, investigator, err := buildIRInvestigator(
			ctx,
			cfg,
			log,
			pool,
			worm,
		)
		if err != nil {
			return err
		}
		srv.WithIRInvestigator(investigator)
		life.WithIRAttributionLifecycle(investigator)
		h, err := provider.Build(cfg, provider.Deps{
			Reaper: func(svc *provider.Service) {
				// One replica sweeps (the coordinator elects it), bounded per
				// run, on the configured cadence. Abandoning tears down the
				// stranded silo BEFORE removing the staging row, so the sweep
				// can never create the orphan it exists to remove.
				_ = singletons.Register("provider-provision-reaper", func(ctx context.Context, _ cluster.LeaseToken) error {
					ticker := time.NewTicker(cfg.ProvisionReapInterval)
					defer ticker.Stop()
					for {
						select {
						case <-ctx.Done():
							return nil
						case <-ticker.C:
							n, err := svc.ReapStrandedProvisions(ctx, "system:provision-reaper",
								cfg.ProvisionReapAfter, cfg.ProvisionReapMax)
							if err != nil {
								log.Warn("stranded provisioning sweep incomplete", "reaped", n, "error", err.Error())
								continue
							}
							if n > 0 {
								log.Info("abandoned stranded provisioning attempts", "count", n)
							}
						}
					}
				})
			},
			Pool:      pool,
			License:   lic,
			Log:       log,
			Results:   results,
			Sessions:  srv.SessionManager(),
			Perms:     srv.PermissionLoader(),
			IRSidecar: irSidecar,
			Silo:      siloOps,
			SiloInvalidate: func() {
				if routerInvalidate != nil {
					routerInvalidate()
				}
			},
			Metering:  metering,
			Lifecycle: life,
			// S-T7: operator fairness views over the CORE gate (enforcement
			// is core; only the views/tuning ride the provider plane).
			Fairness: &provider.Fairness{Gate: fairGate, Store: fairness.NewPGStore(pool)},
			// S-EE3: the data-governance policy store + composed view.
			Governance: governanceCap,
		})
		if err != nil {
			return err
		}
		srv.WithProviderPlane(h)
		log.Info("provider plane attached (S-T1)",
			"tier", lic.Tier(), "state", lic.State(), "tenant_band", lic.TenantBand())
	}
	return nil
}

func attachProviderIRDurability(
	ctx context.Context,
	worm *audit.WormExporter,
	sidecar *audit.IRStagePG,
) error {
	if worm == nil {
		// DPR-011: provider/break-glass audit rows must have a signed WORM
		// export before any operator is admitted. Name the setting.
		return errors.New(
			"provider plane admission requires signed WORM audit export: set PROBECTL_AUDIT_WORM_DIR to a durable absolute directory (deploy/compose/provider.yml or Helm control.extraEnv; docs/provider-plane.md)",
		)
	}
	if sidecar == nil {
		return errors.New("provider IR sidecar is unavailable")
	}
	worm.WithIRWORMDurability(sidecar)
	if err := worm.ReconcileIRWORMDurability(ctx); err != nil {
		return fmt.Errorf(
			"provider IR WORM reconciliation before admission: %w",
			err,
		)
	}
	return nil
}

type siloCatchUpper interface {
	CatchUp(ctx context.Context, tenantID string) error
}

// siloCatchUpAll runs the schema catch-up for every siloed tenant.
func siloCatchUpAll(ctx context.Context, pool *pgxpool.Pool, prov siloCatchUpper, log *slog.Logger) error {
	var ids []string
	err := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		rows, err := q.Query(ctx,
			`SELECT id::text FROM tenants WHERE isolation_model = 'siloed' AND status IN ('active','suspended')`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	return siloCatchUpTenants(ctx, ids, prov, log)
}

func siloCatchUpTenants(ctx context.Context, ids []string, prov siloCatchUpper, log *slog.Logger) error {
	var errs []error
	for _, id := range ids {
		if err := prov.CatchUp(ctx, id); err != nil {
			log.Warn("silo catch-up failed for tenant", "tenant", id, "error", err.Error())
			errs = append(errs, fmt.Errorf("tenant %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

// attachEETenancyRouter (DPR-045) installs, for the one-shot DB commands, the
// same tenancy router the serving process installs in attachEE: it maps a
// siloed tenant to its own Postgres schema (and bus lanes / object prefixes).
// Without it `bootstrap-admin`, `mcp-token`, `scim-token`, `enroll-token` and
// `register-collector` wrote a siloed tenant's rows into the pooled public
// schema, where the serving control plane never looks — the documented
// first-admin path left a siloed tenant with no admin and every token minted
// for it answered 401. The core build is a no-op: siloed isolation is ee/.
func attachEETenancyRouter(cfg *config.Config, pool *pgxpool.Pool, _ *slog.Logger) error {
	if pool == nil {
		return nil
	}
	planes, err := silo.ParseDataPlanes(cfg.DataPlanes)
	if err != nil {
		return err
	}
	tenancy.SetRouter(silo.NewRouter(pool, planes, 0))
	return nil
}
