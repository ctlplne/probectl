package cost

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/incident"
)

// FlowSample is one observed flow, normalized for costing.
type FlowSample struct {
	Src   string
	Dst   string
	Bytes uint64
	At    time.Time
}

// Budget caps a team's or service's monthly network spend (USD). Breaches
// raise SIGNALS into the incident pipeline — probectl never throttles or
// blocks traffic (guardrail 9).
type Budget struct {
	Kind       string // "team" | "service"
	Name       string
	MonthlyUSD float64
}

// Key is the budget's stable identity ("team:payments").
func (b Budget) Key() string { return b.Kind + ":" + b.Name }

// ParseBudgets parses "team:payments=500,service:checkout=120".
func ParseBudgets(raw string) ([]Budget, error) {
	var out []Budget
	for _, part := range splitList(raw) {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("cost: budget %q is not kind:name=usd", part)
		}
		kind, name, ok := strings.Cut(strings.TrimSpace(kv[0]), ":")
		if !ok || (kind != "team" && kind != "service") || name == "" {
			return nil, fmt.Errorf("cost: budget %q must target team:<name> or service:<name>", part)
		}
		usd, err := strconv.ParseFloat(strings.TrimSpace(kv[1]), 64)
		if err != nil || usd <= 0 {
			return nil, fmt.Errorf("cost: budget %q has an invalid amount", part)
		}
		out = append(out, Budget{Kind: kind, Name: name, MonthlyUSD: usd})
	}
	return out, nil
}

// maxKeys bounds each per-tenant attribution map; overflow lumps into
// "(other)" rather than growing unbounded (honest, bounded memory).
const maxKeys = 1024

// trendHours is the hourly-trend retention (7 days).
const trendHours = 7 * 24

// Agg accumulates bytes and dollars.
type Agg struct {
	Bytes uint64  `json:"bytes"`
	USD   float64 `json:"usd"`
}

// PairFlow is one zone→zone service conversation (chatty-service detection).
type PairFlow struct {
	Service string       `json:"service"`
	SrcZone string       `json:"src_zone"`
	DstZone string       `json:"dst_zone"`
	Class   TrafficClass `json:"class"`
	Bytes   uint64       `json:"bytes"`
	USD     float64      `json:"usd"`
	Chatty  bool         `json:"chatty"` // exceeds the chatty threshold
}

// TrendPoint is one hourly cost/volume bucket.
type TrendPoint struct {
	Hour  time.Time `json:"hour"`
	Bytes uint64    `json:"bytes"`
	USD   float64   `json:"usd"`
}

// BudgetStatus is one budget with its month-to-date burn.
type BudgetStatus struct {
	Kind       string  `json:"kind"`
	Name       string  `json:"name"`
	MonthlyUSD float64 `json:"monthly_usd"`
	SpentUSD   float64 `json:"spent_usd"`
	Exceeded   bool    `json:"exceeded"`
}

// Summary is the tenant's cost picture (the /v1/cost/summary payload).
type Summary struct {
	Priced        bool                 `json:"priced"` // false = volume-only degraded mode
	ZonesMapped   bool                 `json:"zones_mapped"`
	PricingSource string               `json:"pricing_source,omitempty"`
	PricingAsOf   string               `json:"pricing_as_of,omitempty"`
	TotalBytes    uint64               `json:"total_bytes"`
	TotalUSD      float64              `json:"total_usd"`
	ByClass       map[TrafficClass]Agg `json:"by_class"`
	ByService     map[string]Agg       `json:"by_service"`
	ByTeam        map[string]Agg       `json:"by_team"` // the showback view
	ChattyPairs   []PairFlow           `json:"chatty_pairs"`
	Trend         []TrendPoint         `json:"trend"`
	Budgets       []BudgetStatus       `json:"budgets"`
}

// DefaultChattyThresholdBytes flags a zone-pair conversation as "chatty"
// once it crosses 1 GiB of paid cross-AZ/region traffic.
const DefaultChattyThresholdBytes = 1 << 30

// Engine aggregates flow volume into attributed cost, per tenant.
type Engine struct {
	mu      sync.Mutex
	mapper  *Mapper
	prices  *PriceTable // nil → volume-only (degraded honestly)
	budgets []Budget
	chatty  uint64
	tenants map[string]*tenantCost
	clock   func() time.Time
}

type tenantCost struct {
	byService map[string]*Agg
	byTeam    map[string]*Agg
	byClass   map[TrafficClass]*Agg
	pairs     map[string]*PairFlow
	trend     map[time.Time]*TrendPoint // truncated hour → bucket (pruned)
	monthUSD  map[string]float64        // budget key → month-to-date spend
	month     string                    // "2006-01" the accumulators cover
	alerted   map[string]bool           // budget key → alerted this month
}

// NewEngine builds the engine. prices nil = volume-only; mapper must be
// non-nil (use NewMapper(nil, nil) for the fully-degraded mode).
func NewEngine(mapper *Mapper, prices *PriceTable, budgets []Budget) *Engine {
	if mapper == nil {
		mapper = NewMapper(nil, nil)
	}
	return &Engine{
		mapper:  mapper,
		prices:  prices,
		budgets: budgets,
		chatty:  DefaultChattyThresholdBytes,
		tenants: map[string]*tenantCost{},
		clock:   time.Now,
	}
}

func (e *Engine) tenant(id string) *tenantCost {
	tc, ok := e.tenants[id]
	if !ok {
		tc = &tenantCost{
			byService: map[string]*Agg{},
			byTeam:    map[string]*Agg{},
			byClass:   map[TrafficClass]*Agg{},
			pairs:     map[string]*PairFlow{},
			trend:     map[time.Time]*TrendPoint{},
			monthUSD:  map[string]float64{},
			alerted:   map[string]bool{},
		}
		e.tenants[id] = tc
	}
	return tc
}

// Observe folds one flow into the tenant's cost picture and returns any
// budget-breach signals it raised (at most one per budget per month).
func (e *Engine) Observe(tenant string, f FlowSample) []incident.Signal {
	if tenant == "" || f.Src == "" || f.Dst == "" || f.Bytes == 0 {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	tc := e.tenant(tenant)

	// Month rollover resets the budget accumulators (trend/aggregates keep
	// their own windows).
	if month := f.At.Format("2006-01"); tc.month != month {
		tc.month = month
		tc.monthUSD = map[string]float64{}
		tc.alerted = map[string]bool{}
	}

	class := e.mapper.Classify(f.Src, f.Dst)
	usd, _ := e.prices.Price(class, f.Bytes)
	service, team := e.mapper.Owner(f.Src)
	if service == "" {
		service = "(unattributed)"
	}
	if team == "" {
		team = "(unattributed)"
	}

	bump(tc.byService, service, f.Bytes, usd)
	bump(tc.byTeam, team, f.Bytes, usd)
	bumpClass(tc.byClass, class, f.Bytes, usd)

	// Chatty zone-pair tracking: only PAID locality classes matter.
	if class == ClassInterAZ || class == ClassInterRegion {
		sZone, _, _ := e.mapper.Zone(f.Src)
		dZone, _, _ := e.mapper.Zone(f.Dst)
		key := service + "|" + sZone + "→" + dZone
		p, ok := tc.pairs[key]
		if !ok {
			if len(tc.pairs) >= maxKeys {
				key = "(other)"
			}
			if p, ok = tc.pairs[key]; !ok {
				p = &PairFlow{Service: service, SrcZone: sZone, DstZone: dZone, Class: class}
				tc.pairs[key] = p
			}
		}
		p.Bytes += f.Bytes
		p.USD += usd
		p.Chatty = p.Bytes >= e.chatty
	}

	// Hourly trend (bounded window).
	hour := f.At.UTC().Truncate(time.Hour)
	tp, ok := tc.trend[hour]
	if !ok {
		tp = &TrendPoint{Hour: hour}
		tc.trend[hour] = tp
		if len(tc.trend) > trendHours {
			var oldest time.Time
			first := true
			for h := range tc.trend {
				if first || h.Before(oldest) {
					oldest, first = h, false
				}
			}
			delete(tc.trend, oldest)
		}
	}
	tp.Bytes += f.Bytes
	tp.USD += usd

	// Budgets: month-to-date burn per target; breach raises ONE signal per
	// month per budget (alert fatigue is a cost problem too).
	var sigs []incident.Signal
	for _, b := range e.budgets {
		var hit bool
		switch b.Kind {
		case "team":
			hit = b.Name == team
		case "service":
			hit = b.Name == service
		}
		if !hit {
			continue
		}
		tc.monthUSD[b.Key()] += usd
		if tc.monthUSD[b.Key()] >= b.MonthlyUSD && !tc.alerted[b.Key()] {
			tc.alerted[b.Key()] = true
			sigs = append(sigs, incident.Signal{
				TenantID: tenant,
				Plane:    "cost",
				Kind:     "cost.budget_exceeded",
				Severity: incident.SeverityWarning,
				Title:    fmt.Sprintf("Network budget exceeded: %s %s", b.Kind, b.Name),
				Summary: fmt.Sprintf("%s %s has spent $%.2f of its $%.2f monthly network budget (%s)",
					b.Kind, b.Name, tc.monthUSD[b.Key()], b.MonthlyUSD, tc.month),
				Target: b.Key(),
				Attributes: map[string]string{
					"cost.budget_kind": b.Kind,
					"cost.budget_name": b.Name,
					"cost.month":       tc.month,
					"cost.spent_usd":   fmt.Sprintf("%.2f", tc.monthUSD[b.Key()]),
					"cost.budget_usd":  fmt.Sprintf("%.2f", b.MonthlyUSD),
				},
				OccurredAt: f.At,
			})
		}
	}
	return sigs
}

func bump(m map[string]*Agg, key string, bytes uint64, usd float64) {
	a, ok := m[key]
	if !ok {
		if len(m) >= maxKeys {
			key = "(other)"
		}
		if a, ok = m[key]; !ok {
			a = &Agg{}
			m[key] = a
		}
	}
	a.Bytes += bytes
	a.USD += usd
}

// bumpClass is bump for the class-keyed map.
func bumpClass(m map[TrafficClass]*Agg, key TrafficClass, bytes uint64, usd float64) {
	a, ok := m[key]
	if !ok {
		a = &Agg{}
		m[key] = a
	}
	a.Bytes += bytes
	a.USD += usd
}

// Summary returns the tenant's current cost picture (honesty flags included).
func (e *Engine) Summary(tenant string) Summary {
	e.mu.Lock()
	defer e.mu.Unlock()
	tc := e.tenant(tenant)

	s := Summary{
		Priced:      e.prices != nil,
		ZonesMapped: e.mapper.ZonesConfigured(),
		ByClass:     map[TrafficClass]Agg{},
		ByService:   map[string]Agg{},
		ByTeam:      map[string]Agg{},
	}
	if e.prices != nil {
		s.PricingSource = e.prices.Source
		s.PricingAsOf = e.prices.AsOf
	}
	for k, a := range tc.byClass {
		s.ByClass[k] = *a
		s.TotalBytes += a.Bytes
		s.TotalUSD += a.USD
	}
	for k, a := range tc.byService {
		s.ByService[k] = *a
	}
	for k, a := range tc.byTeam {
		s.ByTeam[k] = *a
	}
	for _, p := range tc.pairs {
		s.ChattyPairs = append(s.ChattyPairs, *p)
	}
	sort.Slice(s.ChattyPairs, func(i, j int) bool { return s.ChattyPairs[i].Bytes > s.ChattyPairs[j].Bytes })
	if len(s.ChattyPairs) > 50 {
		s.ChattyPairs = s.ChattyPairs[:50]
	}
	for h, tp := range tc.trend {
		_ = h
		s.Trend = append(s.Trend, *tp)
	}
	sort.Slice(s.Trend, func(i, j int) bool { return s.Trend[i].Hour.Before(s.Trend[j].Hour) })
	for _, b := range e.budgets {
		s.Budgets = append(s.Budgets, BudgetStatus{
			Kind: b.Kind, Name: b.Name, MonthlyUSD: b.MonthlyUSD,
			SpentUSD: tc.monthUSD[b.Key()], Exceeded: tc.monthUSD[b.Key()] >= b.MonthlyUSD,
		})
	}
	sort.Slice(s.Budgets, func(i, j int) bool {
		return s.Budgets[i].Kind+s.Budgets[i].Name < s.Budgets[j].Kind+s.Budgets[j].Name
	})
	if s.ChattyPairs == nil {
		s.ChattyPairs = []PairFlow{}
	}
	if s.Trend == nil {
		s.Trend = []TrendPoint{}
	}
	if s.Budgets == nil {
		s.Budgets = []BudgetStatus{}
	}
	return s
}
