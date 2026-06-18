// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// tsdbQuerier is the read side of the in-memory TSDB the evaluator needs.
type tsdbQuerier interface {
	Query(metric string, match map[string]string) []tsdb.Series
}

// metricSource adapts the TSDB to alert.MetricSource for one tenant: every query
// is constrained to the tenant's series (tenant_id label), so the evaluator can
// never read another tenant's metrics (F50). It returns the latest value per
// distinct label set.
type metricSource struct {
	q      tsdbQuerier
	tenant string
}

func (m metricSource) Current(_ context.Context, metric string, match map[string]string) ([]alert.Sample, error) {
	scoped := map[string]string{"tenant_id": m.tenant}
	for k, v := range match {
		scoped[k] = v
	}
	rows := m.q.Query(metric, scoped)

	latest := make(map[string]alert.Sample, len(rows))
	order := make([]string, 0, len(rows))
	for _, s := range rows {
		fp := labelFingerprint(s.Labels)
		if _, seen := latest[fp]; !seen {
			order = append(order, fp)
		}
		latest[fp] = alert.Sample{Labels: s.Labels, Value: s.Value}
	}
	out := make([]alert.Sample, 0, len(order))
	for _, fp := range order {
		out = append(out, latest[fp])
	}
	return out, nil
}

// promInstantQuerier is the read side of a remote-write TSDB (Prometheus /
// VictoriaMetrics) the evaluator needs when there is no in-process store.
type promInstantQuerier interface {
	InstantVector(ctx context.Context, promql string) ([]tsdb.LabeledSample, error)
}

// promMetricSource adapts a Prometheus/VictoriaMetrics instant query to
// alert.MetricSource for one tenant (ARCH-002/CORRECT-006). It pins every query
// to the tenant's tenant_id label so the evaluator can never read another
// tenant's series, exactly like the in-memory metricSource.
type promMetricSource struct {
	q      promInstantQuerier
	tenant string
}

func (m promMetricSource) Current(ctx context.Context, metric string, match map[string]string) ([]alert.Sample, error) {
	var b strings.Builder
	b.WriteString(metric)
	b.WriteByte('{')
	b.WriteString(`tenant_id=`)
	b.WriteString(promQuote(m.tenant))
	for k, v := range match {
		b.WriteByte(',')
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(promQuote(v))
	}
	b.WriteByte('}')
	rows, err := m.q.InstantVector(ctx, b.String())
	if err != nil {
		return nil, err
	}
	out := make([]alert.Sample, 0, len(rows))
	for _, r := range rows {
		out = append(out, alert.Sample{Labels: r.Labels, Value: r.Value})
	}
	return out, nil
}

// promQuote renders a PromQL label-matcher value (double-quoted, escaped).
func promQuote(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

func labelFingerprint(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(labels[k])
		b.WriteByte(';')
	}
	return b.String()
}

// tenantRuleProvider loads a tenant's enabled rules through the RLS choke point.
type tenantRuleProvider struct {
	pool   *pgxpool.Pool
	tenant tenancy.ID
}

func (p tenantRuleProvider) Rules(ctx context.Context) ([]alert.Rule, error) {
	var rules []alert.Rule
	err := tenancy.InTenant(tenancy.WithTenant(ctx, p.tenant), p.pool,
		func(c context.Context, sc tenancy.Scope) error {
			rs, e := store.AlertRules{}.ListEnabled(c, sc)
			rules = rs
			return e
		})
	return rules, err
}

func alertWriterQueryable(writer any) bool {
	switch writer.(type) {
	case tsdbQuerier, promInstantQuerier:
		return true
	default:
		return false
	}
}

// BuildAlertEvaluator wires the alerting evaluator over the shared TSDB and the
// rule store for one tenant. It returns (nil, false) when the TSDB cannot be
// queried in-process or through an instant-query upstream; the caller skips the
// loop rather than accepting inert alert rules.
//
// A non-nil sink forwards every fired/resolved alert (e.g. into the incident
// correlator, S17).
func BuildAlertEvaluator(pool *pgxpool.Pool, writer any, deps alert.ChannelDeps,
	interval time.Duration, tenant tenancy.ID, sink func(context.Context, alert.Alert),
	log *slog.Logger) (*alert.Evaluator, bool) {
	if pool == nil || !alertWriterQueryable(writer) {
		return nil, false
	}
	// ARCH-002/CORRECT-006: pick a metric source for the deployment profile.
	// In-process TSDB (lightweight mode) → query it directly. Remote-write mode
	// (the production Kafka+CH+Prom profile) → query the upstream over its
	// instant API, so rules ACTUALLY evaluate instead of silently never firing.
	var source alert.MetricSource
	switch w := writer.(type) {
	case tsdbQuerier:
		source = metricSource{q: w, tenant: tenant.String()}
	case promInstantQuerier:
		source = promMetricSource{q: w, tenant: tenant.String()}
		log.Info("alerting: evaluating against the remote-write upstream (instant queries)", "tenant", tenant.String())
	default:
		return nil, false
	}
	var opts []alert.EngineOption
	if sink != nil {
		opts = append(opts, alert.WithAlertSink(sink))
	}
	engine := alert.NewEngine(source, alert.NewNotifier(deps, log), log, opts...)
	// ARCH-005 (scoped per the volatile-stores ADR): silences/acks are the
	// ADR's documented exception — reload them so a restart does not drop
	// operator state, and delete the row when the episode resolves.
	restoreCtx, cancelRestore := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelRestore()
	err := tenancy.InTenant(tenancy.WithTenant(restoreCtx, tenant), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			ops, lerr := (store.AlertOps{}).List(ctx, sc)
			if lerr != nil {
				return lerr
			}
			if len(ops) == 0 {
				return nil
			}
			restored := make(map[string]alert.RestoredOp, len(ops))
			for _, op := range ops {
				r := alert.RestoredOp{AckedBy: op.AckedBy}
				if op.SilencedUntil != nil {
					r.SilencedUntil = *op.SilencedUntil
				}
				if op.AckedAt != nil {
					r.AckedAt = *op.AckedAt
				}
				restored[op.Fingerprint] = r
			}
			engine.RestoreOps(restored)
			log.Info("alert silences/acks restored", "tenant", tenant.String(), "ops", len(ops))
			return nil
		})
	if err != nil {
		// Degrade loudly, never block alerting on the ops table.
		log.Warn("alert ops reload failed (silences/acks from before the restart are lost)",
			"tenant", tenant.String(), "error", err.Error())
	}
	engine.SetResolveHook(func(fingerprint string) {
		hctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tenancy.InTenant(tenancy.WithTenant(hctx, tenant), pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				return (store.AlertOps{}).Delete(ctx, sc, fingerprint)
			}); err != nil {
			// CODE-002: a failed resolve-cleanup leaves a stale ops row; log it
			// (the alert still resolves) rather than discard silently.
			log.Warn("alert resolve-hook cleanup failed", "tenant", tenant.String(), "fingerprint", fingerprint, "error", err.Error())
		}
	})
	provider := tenantRuleProvider{pool: pool, tenant: tenant}
	return alert.NewEvaluator(engine, provider, interval, log), true
}

// AlertEvaluatorSupervisor fans alert evaluation out across ACTIVE tenants. It
// keeps one engine per tenant (so active-alert/silence/ack state stays tenant-
// local), but each tick is evaluated through a bounded worker pool rather than
// one permanent goroutine per tenant.
type AlertEvaluatorSupervisor struct {
	pool     *pgxpool.Pool
	writer   any
	deps     alert.ChannelDeps
	interval time.Duration
	sink     func(context.Context, alert.Alert)
	log      *slog.Logger

	listTenants func(context.Context) ([]store.Tenant, error)
	register    func(string, AlertStateSource)
	unregister  func(string)

	maxConcurrent int
	mu            sync.Mutex
	evaluators    map[string]*alert.Evaluator
}

// BuildAlertEvaluatorSupervisor builds the multi-tenant alert fan-out. It
// returns false when alerting cannot run in this deployment profile.
func BuildAlertEvaluatorSupervisor(pool *pgxpool.Pool, writer any, deps alert.ChannelDeps,
	interval time.Duration, sink func(context.Context, alert.Alert), log *slog.Logger,
	register func(string, AlertStateSource), unregister func(string)) (*AlertEvaluatorSupervisor, bool) {
	if pool == nil || !alertWriterQueryable(writer) {
		return nil, false
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if log == nil {
		log = slog.Default()
	}
	s := &AlertEvaluatorSupervisor{
		pool:          pool,
		writer:        writer,
		deps:          deps,
		interval:      interval,
		sink:          sink,
		log:           log,
		register:      register,
		unregister:    unregister,
		maxConcurrent: 8,
		evaluators:    map[string]*alert.Evaluator{},
	}
	s.listTenants = func(ctx context.Context) ([]store.Tenant, error) {
		return store.NewTenants(pool).List(ctx)
	}
	return s, true
}

// Sync refreshes the active-tenant set and starts/stops per-tenant engines.
func (s *AlertEvaluatorSupervisor) Sync(ctx context.Context) error {
	tenants, err := s.listTenants(ctx)
	if err != nil {
		return err
	}
	active := make(map[string]tenancy.ID, len(tenants))
	for _, t := range tenants {
		if t.Status == "active" {
			active[t.ID] = tenancy.ID(t.ID)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for id, tid := range active {
		if _, ok := s.evaluators[id]; ok {
			continue
		}
		ev, ok := BuildAlertEvaluator(s.pool, s.writer, s.deps, s.interval, tid, s.sink, s.log)
		if !ok {
			continue
		}
		s.evaluators[id] = ev
		if s.register != nil {
			s.register(id, ev.Engine())
		}
		s.log.Info("alert evaluator started", "tenant", id)
	}
	for id := range s.evaluators {
		if _, ok := active[id]; ok {
			continue
		}
		delete(s.evaluators, id)
		if s.unregister != nil {
			s.unregister(id)
		}
		s.log.Info("alert evaluator stopped", "tenant", id)
	}
	return nil
}

// Tick evaluates every active tenant, bounded by maxConcurrent workers.
func (s *AlertEvaluatorSupervisor) Tick(ctx context.Context) {
	s.mu.Lock()
	evals := make([]*alert.Evaluator, 0, len(s.evaluators))
	for _, ev := range s.evaluators {
		evals = append(evals, ev)
	}
	limit := s.maxConcurrent
	s.mu.Unlock()
	if limit <= 0 {
		limit = 1
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for _, ev := range evals {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(ev *alert.Evaluator) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := ev.Tick(ctx); err != nil {
				s.log.Warn("alert evaluation tick failed", "error", err)
			}
		}(ev)
	}
	wg.Wait()
}

// Run periodically syncs tenants and evaluates all active tenant engines.
func (s *AlertEvaluatorSupervisor) Run(ctx context.Context) {
	if err := s.Sync(ctx); err != nil {
		s.log.Warn("alert tenant sync failed", "error", err)
	}
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Sync(ctx); err != nil {
				s.log.Warn("alert tenant sync failed", "error", err)
				continue
			}
			s.Tick(ctx)
		}
	}
}
