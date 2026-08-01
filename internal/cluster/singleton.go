// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cluster

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/errgroup"

	"github.com/ctlplne/probectl/internal/cluster/pglease"
	"github.com/ctlplne/probectl/internal/metrics"
)

const (
	// DefaultSingletonRenewInterval bounds normal singleton failover time. A
	// standby retries acquisition on this cadence while the holder renews its
	// fenced epoch on the same cadence.
	DefaultSingletonRenewInterval = 5 * time.Second
)

var (
	// ErrLeaseFenced means the caller's epoch is no longer the current epoch.
	ErrLeaseFenced = pglease.ErrFenced
	// ErrLeaseAlreadyHeld means Acquire was called twice on one lease handle.
	ErrLeaseAlreadyHeld = pglease.ErrAlreadyHeld
	// ErrSingletonTaskStopped means a registered forever-loop returned while
	// its lease context was still live. The coordinator relinquishes leadership
	// and retries the complete task set instead of running a partial leader.
	ErrSingletonTaskStopped = errors.New("cluster: singleton task stopped unexpectedly")
)

// LeaseToken fences one leadership term. It aliases the PostgreSQL backend's
// transport-neutral token so callers do not depend on backend internals.
type LeaseToken = pglease.Token

// LeaseBackend is the acquire/renew/release seam used by Coordinator. Unit
// tests use an in-process implementation to deterministically exercise two
// replicas without pretending that it proves PostgreSQL behavior.
type LeaseBackend interface {
	Acquire(ctx context.Context) (LeaseToken, bool, error)
	Renew(ctx context.Context, token LeaseToken) error
	Release(ctx context.Context, token LeaseToken) error
}

// PGLease is the production PostgreSQL advisory-lock backend.
type PGLease = pglease.Lease

// NewPGLease builds the PostgreSQL singleton lease. Empty holderID generates a
// hostname+random process identity through internal/crypto.
func NewPGLease(pool *pgxpool.Pool, name, holderID string) (*PGLease, error) {
	return pglease.New(pool, name, holderID)
}

// SingletonTask is one cluster-wide background loop. The function must honor
// ctx cancellation; token is the fencing epoch for logs or epoch-aware stores.
type SingletonTask struct {
	Name string
	Run  func(context.Context, LeaseToken) error
}

// Coordinator keeps all registered singleton loops on exactly one replica.
type Coordinator struct {
	lease    LeaseBackend
	interval time.Duration
	log      *slog.Logger

	mu      sync.Mutex
	started bool
	tasks   []SingletonTask

	holder            atomic.Bool
	epoch             atomic.Int64
	acquisitionMetric *metrics.Counter
	renewErrorMetric  *metrics.Counter
}

// NewSingletonCoordinator builds the production Postgres-backed coordinator.
func NewSingletonCoordinator(pool *pgxpool.Pool, name string, interval time.Duration, log *slog.Logger) (*Coordinator, error) {
	lease, err := NewPGLease(pool, name, "")
	if err != nil {
		return nil, err
	}
	return newCoordinator(lease, interval, log), nil
}

func newCoordinator(lease LeaseBackend, interval time.Duration, log *slog.Logger) *Coordinator {
	if interval <= 0 {
		interval = DefaultSingletonRenewInterval
	}
	if log == nil {
		log = slog.Default()
	}
	return &Coordinator{lease: lease, interval: interval, log: log}
}

// Register adds a task before Run starts.
func (c *Coordinator) Register(name string, run func(context.Context, LeaseToken) error) error {
	if name == "" || run == nil {
		return errors.New("cluster: singleton task requires a name and function")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {
		return fmt.Errorf("cluster: register singleton task %q after coordinator start", name)
	}
	for _, existing := range c.tasks {
		if existing.Name == name {
			return fmt.Errorf("cluster: duplicate singleton task %q", name)
		}
	}
	c.tasks = append(c.tasks, SingletonTask{Name: name, Run: run})
	return nil
}

// WithMetrics exposes holder/epoch plus transition counters. They contain no
// tenant labels or holder identity.
func (c *Coordinator) WithMetrics(reg *metrics.Registry) *Coordinator {
	if reg == nil {
		return c
	}
	reg.Gauge("probectl_cluster_singleton_lease_holder", "Whether this control-plane replica holds the cluster singleton lease (1 holder, 0 standby).", func() float64 {
		if c.holder.Load() {
			return 1
		}
		return 0
	})
	reg.Gauge("probectl_cluster_singleton_lease_epoch", "Current fenced singleton epoch on this replica (0 while standby).", func() float64 {
		return float64(c.epoch.Load())
	})
	c.acquisitionMetric = reg.Counter("probectl_cluster_singleton_lease_acquisitions_total", "Singleton leadership terms acquired by this process.")
	c.renewErrorMetric = reg.Counter("probectl_cluster_singleton_lease_renew_errors_total", "Singleton renew failures observed by this process.")
	return c
}

// IsHolder reports this process's current leadership state.
func (c *Coordinator) IsHolder() bool { return c.holder.Load() }

// Epoch reports the current epoch, or zero while this process is a standby.
func (c *Coordinator) Epoch() int64 { return c.epoch.Load() }

// Run keeps a hot acquire/renew loop until ctx ends. Expected acquisition and
// task failures relinquish the whole term, then retry after one interval.
func (c *Coordinator) Run(ctx context.Context) error {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return errors.New("cluster: singleton coordinator already started")
	}
	c.started = true
	tasks := append([]SingletonTask(nil), c.tasks...)
	c.mu.Unlock()
	if len(tasks) == 0 {
		return errors.New("cluster: singleton coordinator has no registered tasks")
	}

	standbyLogged := false
	for ctx.Err() == nil {
		opCtx, cancel := context.WithTimeout(ctx, c.interval)
		token, won, err := c.lease.Acquire(opCtx)
		cancel()
		if err != nil {
			if !standbyLogged {
				c.log.Warn("cluster singleton lease unavailable; replica standing by", "error", err)
				standbyLogged = true
			}
			if !waitSingleton(ctx, c.interval) {
				break
			}
			continue
		}
		if !won {
			if !standbyLogged {
				c.log.Info("cluster singleton standby", "renew_interval", c.interval.String())
				standbyLogged = true
			}
			if !waitSingleton(ctx, c.interval) {
				break
			}
			continue
		}

		standbyLogged = false
		c.holder.Store(true)
		c.epoch.Store(token.Epoch)
		if c.acquisitionMetric != nil {
			c.acquisitionMetric.Inc()
		}
		c.log.Info("cluster singleton lease acquired", "epoch", token.Epoch, "tasks", len(tasks), "renew_interval", c.interval.String())
		reason := c.holdTerm(ctx, token, tasks)
		c.holder.Store(false)
		c.epoch.Store(0)
		if ctx.Err() == nil && reason != nil {
			c.log.Warn("cluster singleton term ended; replica returning to standby", "epoch", token.Epoch, "error", reason)
		}
		if ctx.Err() == nil && !waitSingleton(ctx, c.interval) {
			break
		}
	}
	c.holder.Store(false)
	c.epoch.Store(0)
	return nil
}

func (c *Coordinator) holdTerm(parent context.Context, token LeaseToken, tasks []SingletonTask) error {
	workCtx, cancelWork := context.WithCancel(parent)
	taskDone := make(chan error, 1)
	go func() { taskDone <- runSingletonTasks(workCtx, token, tasks) }()
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	var reason error
selectLoop:
	for {
		select {
		case <-parent.Done():
			reason = parent.Err()
			break selectLoop
		case err := <-taskDone:
			reason = err
			taskDone = nil
			break selectLoop
		case <-ticker.C:
			opCtx, cancel := context.WithTimeout(parent, c.interval)
			err := c.lease.Renew(opCtx, token)
			cancel()
			if err != nil {
				if c.renewErrorMetric != nil {
					c.renewErrorMetric.Inc()
				}
				reason = err
				break selectLoop
			}
		}
	}
	cancelWork()
	if taskDone != nil {
		<-taskDone
	}
	releaseCtx, cancelRelease := context.WithTimeout(context.Background(), c.interval)
	releaseErr := c.lease.Release(releaseCtx, token)
	cancelRelease()
	if releaseErr != nil && !errors.Is(releaseErr, ErrLeaseFenced) {
		c.log.Error("cluster singleton lease release failed", "epoch", token.Epoch, "error", releaseErr)
	}
	return reason
}

func runSingletonTasks(ctx context.Context, token LeaseToken, tasks []SingletonTask) error {
	g, gctx := errgroup.WithContext(ctx)
	for _, task := range tasks {
		task := task
		g.Go(func() error {
			err := task.Run(gctx, token)
			if gctx.Err() != nil {
				return nil
			}
			if err == nil {
				return fmt.Errorf("%w: %s", ErrSingletonTaskStopped, task.Name)
			}
			return fmt.Errorf("cluster: singleton task %s: %w", task.Name, err)
		})
	}
	return g.Wait()
}

func waitSingleton(ctx context.Context, interval time.Duration) bool {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
