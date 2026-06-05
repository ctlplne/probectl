// Package carbon is probectl's network carbon/power observability (S48,
// F48): Kepler-style ESG visibility for the network plane, computed from
// telemetry probectl already has — flow volume × published energy-per-byte
// coefficients × the operator's grid carbon intensity, attributed to
// services and teams through the same mapping the FinOps engine uses.
//
// The honesty contract is the whole feature: these are ESTIMATES from
// literature coefficients, not measured watts. Every response carries the
// methodology block (coefficient source, grid intensity, measured=false);
// numbers are reported as gCO2e-equivalent ESTIMATES so an ESG report
// built on them can cite exactly what they are. No external calls — the
// grid intensity is operator-set config (sovereignty, guardrail 2).
package carbon

import (
	"sort"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/cost"
)

// Coefficients pins the estimation model.
type Coefficients struct {
	// KWhPerGB by traffic class: transport through more network hops costs
	// more energy. Literature-derived defaults (see DefaultCoefficients).
	KWhPerGB map[cost.TrafficClass]float64
	// GridGCO2ePerKWh is the operator's grid carbon intensity.
	GridGCO2ePerKWh float64
	// Source documents where the coefficients came from (served verbatim).
	Source string
}

// DefaultCoefficients is the built-in model: fixed-network transmission
// energy in the ~0.01–0.06 kWh/GB band (Aslan et al. 2017 and successors,
// scaled by path locality), with the world-average grid intensity as the
// default — the operator should set their real grid figure.
func DefaultCoefficients(gridGCO2e float64) Coefficients {
	if gridGCO2e <= 0 {
		gridGCO2e = 436 // ~world average gCO2e/kWh (operator should override)
	}
	return Coefficients{
		KWhPerGB: map[cost.TrafficClass]float64{
			cost.ClassSameZone:    0.004,
			cost.ClassInterAZ:     0.01,
			cost.ClassInterRegion: 0.03,
			cost.ClassInternet:    0.06,
			cost.ClassUnknown:     0.01, // conservative mid-band when zones are unmapped
		},
		GridGCO2ePerKWh: gridGCO2e,
		Source:          "fixed-network transmission coefficients (Aslan et al. 2017 band, scaled by locality); operator-set grid intensity",
	}
}

// Agg accumulates one attribution bucket.
type Agg struct {
	Bytes uint64  `json:"bytes"`
	KWh   float64 `json:"kwh"`
	GCO2e float64 `json:"gco2e"`
}

// TrendPoint is one hourly energy/carbon bucket.
type TrendPoint struct {
	Hour  time.Time `json:"hour"`
	KWh   float64   `json:"kwh"`
	GCO2e float64   `json:"gco2e"`
}

// Methodology is the served honesty block.
type Methodology struct {
	Measured        bool    `json:"measured"` // always false — structural (estimates)
	Source          string  `json:"source"`
	GridGCO2ePerKWh float64 `json:"grid_gco2e_per_kwh"`
	Note            string  `json:"note"`
}

// Summary is one tenant's carbon picture (the /v1/carbon payload).
type Summary struct {
	TotalBytes  uint64                    `json:"total_bytes"`
	TotalKWh    float64                   `json:"total_kwh"`
	TotalGCO2e  float64                   `json:"total_gco2e"`
	ByClass     map[cost.TrafficClass]Agg `json:"by_class"`
	ByService   map[string]Agg            `json:"by_service"`
	ByTeam      map[string]Agg            `json:"by_team"`
	Trend       []TrendPoint              `json:"trend"`
	Methodology Methodology               `json:"methodology"`
}

// bounds (mirrors the cost engine's discipline).
const (
	maxKeys    = 1024
	trendHours = 7 * 24
)

// Engine estimates per-tenant network energy/carbon from the flow stream.
type Engine struct {
	mu      sync.Mutex
	mapper  *cost.Mapper
	coeff   Coefficients
	tenants map[string]*tenantCarbon
}

type tenantCarbon struct {
	byClass   map[cost.TrafficClass]*Agg
	byService map[string]*Agg
	byTeam    map[string]*Agg
	trend     map[time.Time]*TrendPoint
}

// NewEngine builds the engine over the SAME attribution mapper the cost
// engine uses (zones + owners), so FinOps dollars and ESG grams agree on
// who owns which traffic.
func NewEngine(mapper *cost.Mapper, coeff Coefficients) *Engine {
	if mapper == nil {
		mapper = cost.NewMapper(nil, nil)
	}
	if len(coeff.KWhPerGB) == 0 {
		coeff = DefaultCoefficients(coeff.GridGCO2ePerKWh)
	}
	return &Engine{mapper: mapper, coeff: coeff, tenants: map[string]*tenantCarbon{}}
}

func (e *Engine) tenant(id string) *tenantCarbon {
	tc, ok := e.tenants[id]
	if !ok {
		tc = &tenantCarbon{
			byClass:   map[cost.TrafficClass]*Agg{},
			byService: map[string]*Agg{},
			byTeam:    map[string]*Agg{},
			trend:     map[time.Time]*TrendPoint{},
		}
		e.tenants[id] = tc
	}
	return tc
}

// Observe folds one flow into the tenant's energy/carbon estimate.
func (e *Engine) Observe(tenant string, f cost.FlowSample) {
	if tenant == "" || f.Src == "" || f.Dst == "" || f.Bytes == 0 {
		return
	}
	class := e.mapper.Classify(f.Src, f.Dst)
	kwh := float64(f.Bytes) / float64(1<<30) * e.coeff.KWhPerGB[class]
	gco2e := kwh * e.coeff.GridGCO2ePerKWh
	service, team := e.mapper.Owner(f.Src)
	if service == "" {
		service = "(unattributed)"
	}
	if team == "" {
		team = "(unattributed)"
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	tc := e.tenant(tenant)
	bumpClass(tc.byClass, class, f.Bytes, kwh, gco2e)
	bump(tc.byService, service, f.Bytes, kwh, gco2e)
	bump(tc.byTeam, team, f.Bytes, kwh, gco2e)

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
	tp.KWh += kwh
	tp.GCO2e += gco2e
}

func bump(m map[string]*Agg, key string, bytes uint64, kwh, gco2e float64) {
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
	a.KWh += kwh
	a.GCO2e += gco2e
}

func bumpClass(m map[cost.TrafficClass]*Agg, key cost.TrafficClass, bytes uint64, kwh, gco2e float64) {
	a, ok := m[key]
	if !ok {
		a = &Agg{}
		m[key] = a
	}
	a.Bytes += bytes
	a.KWh += kwh
	a.GCO2e += gco2e
}

// Summary renders ONE tenant's carbon estimate.
func (e *Engine) Summary(tenant string) Summary {
	e.mu.Lock()
	defer e.mu.Unlock()
	tc := e.tenant(tenant)

	s := Summary{
		ByClass:   map[cost.TrafficClass]Agg{},
		ByService: map[string]Agg{},
		ByTeam:    map[string]Agg{},
		Trend:     []TrendPoint{},
		Methodology: Methodology{
			Measured:        false,
			Source:          e.coeff.Source,
			GridGCO2ePerKWh: e.coeff.GridGCO2ePerKWh,
			Note:            "coefficient-based ESTIMATE of network transmission energy — not measured device power; suitable for relative attribution and trends, cite the methodology in any ESG use",
		},
	}
	for class, a := range tc.byClass {
		s.ByClass[class] = *a
		s.TotalBytes += a.Bytes
		s.TotalKWh += a.KWh
		s.TotalGCO2e += a.GCO2e
	}
	for k, a := range tc.byService {
		s.ByService[k] = *a
	}
	for k, a := range tc.byTeam {
		s.ByTeam[k] = *a
	}
	for _, tp := range tc.trend {
		s.Trend = append(s.Trend, *tp)
	}
	sort.Slice(s.Trend, func(i, j int) bool { return s.Trend[i].Hour.Before(s.Trend[j].Hour) })
	return s
}
