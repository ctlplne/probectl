// Package metrics is probectl's self-observability surface (OPS-005): a
// tiny, dependency-FREE Prometheus text-exposition registry (CLAUDE.md §9 —
// no new dependency for this). "probectl observes probectl" (§8): the
// control plane scrapes its OWN operational health here, never tenant data —
// every series is a process/aggregate counter or gauge, so /metrics carries
// no per-tenant values and needs no tenant scoping.
//
// The format is the Prometheus text exposition format (v0.0.4): each metric
// gets a # HELP and # TYPE line then samples. Counters and gauges register
// at startup; runtime/process stats are sampled at scrape time.
package metrics

import (
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Registry holds the process's metrics. The zero value is unusable; call New.
type Registry struct {
	mu        sync.RWMutex
	counters  map[string]*Counter
	gauges    map[string]*gaugeFunc
	help      map[string]string
	startTime time.Time
	version   string
	commit    string
}

// Counter is a monotonically increasing value, safe for concurrent use.
type Counter struct{ v atomic.Uint64 }

// Inc adds 1.
func (c *Counter) Inc() { c.v.Add(1) }

// Add adds n.
func (c *Counter) Add(n uint64) { c.v.Add(n) }

// Value reads the counter.
func (c *Counter) Value() uint64 { return c.v.Load() }

type gaugeFunc struct {
	help string
	fn   func() float64
}

// New builds a registry stamped with build provenance (surfaced as
// probectl_build_info).
func New(version, commit string) *Registry {
	return &Registry{
		counters:  map[string]*Counter{},
		gauges:    map[string]*gaugeFunc{},
		help:      map[string]string{},
		startTime: time.Now(),
		version:   version,
		commit:    commit,
	}
}

// Counter returns (creating if needed) the named counter. Names must be valid
// Prometheus identifiers; callers use the probectl_ prefix by convention.
func (r *Registry) Counter(name, help string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.counters[name]; ok {
		return c
	}
	c := &Counter{}
	r.counters[name] = c
	r.help[name] = help
	return c
}

// Gauge registers a sampled gauge backed by fn (evaluated at scrape time).
func (r *Registry) Gauge(name, help string, fn func() float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gauges[name] = &gaugeFunc{help: help, fn: fn}
}

// Handler serves the Prometheus text exposition at /metrics. It exposes the
// registered counters/gauges plus Go runtime + process stats. No tenant data
// ever appears here (OPS-005 — self-metrics only).
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		// Build info + uptime (always present).
		fmt.Fprintf(w, "# HELP probectl_build_info Build provenance (always 1).\n# TYPE probectl_build_info gauge\n")
		fmt.Fprintf(w, "probectl_build_info{version=%q,commit=%q} 1\n", r.version, r.commit)
		fmt.Fprintf(w, "# HELP probectl_uptime_seconds Seconds since process start.\n# TYPE probectl_uptime_seconds gauge\n")
		fmt.Fprintf(w, "probectl_uptime_seconds %g\n", time.Since(r.startTime).Seconds())
		fmt.Fprintf(w, "# HELP process_start_time_seconds Unix start time (process_* convention).\n# TYPE process_start_time_seconds gauge\n")
		fmt.Fprintf(w, "process_start_time_seconds %d\n", r.startTime.Unix())

		// Go runtime stats (the standard go_* names operators expect).
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		writeGauge(w, "go_goroutines", "Number of goroutines.", float64(runtime.NumGoroutine()))
		writeGauge(w, "go_memstats_heap_alloc_bytes", "Heap bytes allocated and in use.", float64(ms.HeapAlloc))
		writeGauge(w, "go_memstats_sys_bytes", "Bytes obtained from the OS.", float64(ms.Sys))
		writeGauge(w, "go_threads", "OS threads created.", float64(runtimeThreads()))

		// Registered counters (sorted for stable output).
		r.mu.RLock()
		defer r.mu.RUnlock()
		names := make([]string, 0, len(r.counters))
		for n := range r.counters {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", n, r.help[n], n)
			fmt.Fprintf(w, "%s %d\n", n, r.counters[n].Value())
		}

		// Registered gauges (sorted).
		gnames := make([]string, 0, len(r.gauges))
		for n := range r.gauges {
			gnames = append(gnames, n)
		}
		sort.Strings(gnames)
		for _, n := range gnames {
			g := r.gauges[n]
			fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", n, g.help, n)
			fmt.Fprintf(w, "%s %g\n", n, g.fn())
		}
	})
}

func writeGauge(w http.ResponseWriter, name, help string, v float64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, v)
}

// runtimeThreads reports OS thread count without importing runtime/metrics
// (kept dependency-light; -1 means unknown).
func runtimeThreads() int {
	n, _ := runtime.ThreadCreateProfile(nil)
	return n
}
