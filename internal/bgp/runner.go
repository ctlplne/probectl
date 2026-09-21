// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"time"
)

const (
	defaultAnalyzerBackoff    = time.Second
	defaultAnalyzerMaxBackoff = 30 * time.Second
	defaultAnalyzerFlush      = 10 * time.Second
)

// AnalyzerProcess describes one tenant-bound Python analyzer subprocess.
// Args never pass credentials: Kafka authentication stays in the Go publisher,
// and the child receives only the explicitly allow-listed environment.
type AnalyzerProcess struct {
	TenantID   string
	Executable string
	Args       []string
	Dir        string
	Env        []string
	Restart    bool
}

// AnalyzerRunner supervises the Python analyzer and bridges its stdout to the
// canonical BGP bus topic. It deliberately owns no listener and no API-server
// lifecycle: a missing/crashing analyzer degrades only this optional sidecar.
type AnalyzerRunner struct {
	process        AnalyzerProcess
	bridge         *Bridge
	log            *slog.Logger
	stderr         io.Writer
	minBackoff     time.Duration
	maxBackoff     time.Duration
	flushTimeout   time.Duration
	commandContext func(context.Context, string, ...string) *exec.Cmd
	wait           func(context.Context, time.Duration) error
}

// NewAnalyzerRunner builds a tenant-bound subprocess supervisor.
func NewAnalyzerRunner(pub Publisher, process AnalyzerProcess, log *slog.Logger) (*AnalyzerRunner, error) {
	if log == nil {
		log = slog.Default()
	}
	if process.TenantID == "" {
		return nil, errors.New("bgp analyzer runner: tenant_id is required")
	}
	if process.Executable == "" {
		return nil, errors.New("bgp analyzer runner: executable is required")
	}
	if pub == nil {
		return nil, errors.New("bgp analyzer runner: publisher is required")
	}
	return &AnalyzerRunner{
		process:        process,
		bridge:         NewBridge(pub, log).WithExpectedTenant(process.TenantID),
		log:            log,
		stderr:         os.Stderr,
		minBackoff:     defaultAnalyzerBackoff,
		maxBackoff:     defaultAnalyzerMaxBackoff,
		flushTimeout:   defaultAnalyzerFlush,
		commandContext: exec.CommandContext,
		wait:           waitAnalyzerBackoff,
	}, nil
}

// Run starts the analyzer. Finite MRT/replay processes return after one clean
// run; live processes restart after both crashes and unexpected clean exits.
// Backoff doubles to a hard cap, so a missing Python runtime cannot hot-loop.
func (r *AnalyzerRunner) Run(ctx context.Context) error {
	backoff := r.minBackoff
	for {
		started := time.Now()
		stats, err := r.runOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if !r.process.Restart {
			if err != nil {
				return fmt.Errorf("bgp analyzer run: %w", err)
			}
			r.log.Info("bgp analyzer completed",
				"tenant_id", r.process.TenantID,
				"published", stats.Published,
				"skipped", stats.Skipped,
			)
			return nil
		}
		if time.Since(started) >= r.maxBackoff {
			backoff = r.minBackoff
		}
		if err == nil {
			err = errors.New("analyzer exited unexpectedly")
		}
		r.log.Error("bgp analyzer stopped; restarting after bounded backoff",
			"tenant_id", r.process.TenantID,
			"backoff", backoff.String(),
			"published", stats.Published,
			"skipped", stats.Skipped,
			"error", err.Error(),
		)
		if err := r.wait(ctx, backoff); err != nil {
			return nil
		}
		backoff *= 2
		if backoff > r.maxBackoff {
			backoff = r.maxBackoff
		}
	}
}

func (r *AnalyzerRunner) runOnce(ctx context.Context) (Stats, error) {
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := r.commandContext(childCtx, r.process.Executable, r.process.Args...)
	cmd.Dir = r.process.Dir
	cmd.Env = append([]string(nil), r.process.Env...)
	cmd.Stderr = r.stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Stats{}, fmt.Errorf("bgp analyzer stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return Stats{}, fmt.Errorf("start bgp analyzer: %w", err)
	}

	stats, ingestErr := r.bridge.Ingest(childCtx, stdout)
	if ingestErr != nil {
		cancel()
	}
	waitErr := cmd.Wait()
	flushErr := r.flushAccepted(ctx)
	if ingestErr != nil {
		return stats, ingestErr
	}
	if flushErr != nil {
		return stats, flushErr
	}
	if ctx.Err() != nil {
		return stats, ctx.Err()
	}
	if waitErr != nil {
		return stats, fmt.Errorf("bgp analyzer process: %w", waitErr)
	}
	return stats, nil
}

func (r *AnalyzerRunner) flushAccepted(ctx context.Context) error {
	f, ok := r.bridge.bus.(interface{ Flush(context.Context) error })
	if !ok {
		return nil
	}
	flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.flushTimeout)
	defer cancel()
	if err := f.Flush(flushCtx); err != nil {
		return fmt.Errorf("flush bridged bgp events: %w", err)
	}
	return nil
}

func waitAnalyzerBackoff(ctx context.Context, delay time.Duration) error {
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
