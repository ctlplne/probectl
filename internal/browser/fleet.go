package browser

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/objectstore"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// DefaultRunTimeout bounds a single transaction run when none is configured.
const DefaultRunTimeout = 60 * time.Second

// Config tunes the browser fleet. Because browser workers are the heaviest canary
// (CPU/memory), the fleet caps concurrency, isolates each run with a timeout, and
// recycles workers to bound leaks.
type Config struct {
	// MaxConcurrency is the worker-pool size — at most this many runs execute at
	// once (the rest block). Defaults to 1.
	MaxConcurrency int
	// RecycleAfter recycles (Close + recreate) a worker's driver after this many
	// runs; 0 disables age-based recycling. A failed run always recycles.
	RecycleAfter int
	// RunTimeout isolates a single run; on timeout the run fails and the worker is
	// recycled. Defaults to DefaultRunTimeout.
	RunTimeout time.Duration
	// StoreOnSuccess also stores the page artifact on a successful run (default:
	// only on failure, to bound screenshot storage).
	StoreOnSuccess bool
}

// Fleet runs transaction scripts across a bounded pool of recyclable workers and
// stores failure artifacts in the object store.
type Fleet struct {
	cfg     Config
	factory func() Driver
	store   objectstore.Store
	log     *slog.Logger
	pool    chan *worker
}

type worker struct {
	driver Driver
	runs   int
}

// NewFleet builds a fleet. factory creates a fresh Driver (e.g. NewHTTPDriver, or
// an exec/Playwright driver); store receives failure artifacts.
func NewFleet(cfg Config, factory func() Driver, store objectstore.Store, log *slog.Logger) *Fleet {
	if cfg.MaxConcurrency < 1 {
		cfg.MaxConcurrency = 1
	}
	if cfg.RunTimeout <= 0 {
		cfg.RunTimeout = DefaultRunTimeout
	}
	if log == nil {
		log = slog.Default()
	}
	f := &Fleet{cfg: cfg, factory: factory, store: store, log: log, pool: make(chan *worker, cfg.MaxConcurrency)}
	for i := 0; i < cfg.MaxConcurrency; i++ {
		f.pool <- &worker{} // empty workers; the driver is built lazily on first use
	}
	return f
}

// Run executes a script for a tenant. It blocks until a worker is free (the
// concurrency cap), isolates the run with RunTimeout, uploads a failure artifact,
// and recycles the worker when due. A transaction failure is reported in the
// Result (Success=false); a returned error means the fleet itself was canceled.
func (f *Fleet) Run(ctx context.Context, tenant string, s Script) (Result, error) {
	if err := s.Validate(); err != nil {
		return Result{}, err
	}

	var w *worker
	select {
	case w = <-f.pool:
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
	if w.driver == nil {
		w.driver = f.factory()
	}

	runCtx, cancel := context.WithTimeout(ctx, f.cfg.RunTimeout)
	out, runErr := f.safeRun(runCtx, w.driver, s)
	cancel()

	res := out.Result
	res.Script = s.Name
	res.TenantID = tenant
	if runErr != nil {
		res.Success = false
		if errors.Is(runErr, context.DeadlineExceeded) {
			res.Error = fmt.Sprintf("run exceeded %s timeout", f.cfg.RunTimeout)
		} else if res.Error == "" {
			res.Error = runErr.Error()
		}
	}

	f.storeArtifact(ctx, tenant, s, &res, out)

	// Recycle on a failed run or when the worker hits its age limit.
	w.runs++
	recycle := runErr != nil ||
		(f.cfg.RecycleAfter > 0 && w.runs >= f.cfg.RecycleAfter)
	if recycle {
		f.closeDriver(w.driver)
		w.driver = nil
		w.runs = 0
	}
	f.pool <- w
	return res, nil
}

// safeRun runs the driver, converting a panic into an error so one bad run can't
// take the fleet down (and the worker is recycled).
func (f *Fleet) safeRun(ctx context.Context, d Driver, s Script) (out RunOutput, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("browser driver panic: %v", r)
		}
	}()
	return d.Run(ctx, s)
}

func (f *Fleet) storeArtifact(ctx context.Context, tenant string, s Script, res *Result, out RunOutput) {
	if f.store == nil || len(out.Screenshot) == 0 {
		return
	}
	if res.Success && !f.cfg.StoreOnSuccess {
		return
	}
	// Isolation-routed key (S-T2): siloed/hybrid tenants get their own object
	// namespace; pooled tenants keep the standard tenant/<id>/ prefix. A
	// routing failure stores nothing (fail closed) rather than misfiling.
	targets, err := tenancy.CurrentRouter().TargetsFor(ctx, tenant)
	if err != nil {
		f.log.Warn("browser: artifact not stored (isolation routing failed)", "tenant", tenant, "error", err)
		return
	}
	key := objectstore.PrefixedKey(targets.ObjectPrefix, tenant, "browser",
		fmt.Sprintf("%s-%d%s", safeName(s.Name), res.StartedAt.UnixNano(), ext(out.ScreenshotType)))
	if err := f.store.Put(ctx, key, out.ScreenshotType, out.Screenshot); err != nil {
		f.log.Warn("browser: store artifact failed", "tenant", tenant, "script", s.Name, "error", err)
		return
	}
	res.Screenshot = &ScreenshotRef{Key: key, ContentType: out.ScreenshotType, SizeBytes: int64(len(out.Screenshot))}
}

func (f *Fleet) closeDriver(d Driver) {
	if c, ok := d.(Closer); ok {
		if err := c.Close(); err != nil {
			f.log.Warn("browser: driver close failed", "error", err)
		}
	}
}

// Close disposes every worker's driver. The fleet must not be used afterward.
func (f *Fleet) Close() {
	for i := 0; i < f.cfg.MaxConcurrency; i++ {
		w := <-f.pool
		if w.driver != nil {
			f.closeDriver(w.driver)
			w.driver = nil
		}
	}
}

func ext(contentType string) string {
	switch contentType {
	case "image/png":
		return ".png"
	case "image/jpeg":
		return ".jpg"
	case "text/html":
		return ".html"
	default:
		return ".bin"
	}
}

func safeName(name string) string {
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "script"
	}
	return string(out)
}
