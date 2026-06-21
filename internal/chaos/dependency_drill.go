// SPDX-License-Identifier: LicenseRef-probectl-TBD

package chaos

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/agent"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

const defaultDrillTimeout = 10 * time.Second

// DependencyDrillOptions configures the non-production dependency-chaos drill.
// WorkerCommand must run a process that speaks RunDependencyDrillWorker's
// line-oriented protocol. The command is killed with SIGKILL to model a pod
// dying while one message is in flight.
type DependencyDrillOptions struct {
	TempDir       string
	WorkerCommand []string
	WorkerEnv     []string
}

// DependencyDrillResult is the machine-readable proof printed by
// chaos-dependency-drill. Every field is a counter so CI logs can be copied into
// release evidence without interpreting prose.
type DependencyDrillResult struct {
	DiskFullEnqueued         int
	DiskFullRejected         int
	DiskFullDropped          uint64
	DiskFullBufferedBytes    int64
	DiskFullRecoveryDrained  int
	MemoryPressureAdmitted   int
	MemoryPressureDropped    int
	MemoryQuietAdmitted      int
	PodKillKilled            int
	PodKillRestarts          int
	PodKillRequeued          int
	PodKillRecoveredAcks     int
	DependencyHealthy        int
	DependencyOutageFailed   int
	DependencyRecovered      int
	RecoveryAssertionsPassed int
}

// RunDependencyDrill injects the locally-safe dependency failures from the
// release matrix and prints one result line. It does not touch a live cluster:
// "disk full" is the real agent buffer byte cap, "pod kill" is an actual
// throwaway process kill, and "dependency outage" is a loopback TCP endpoint.
func RunDependencyDrill(ctx context.Context, out io.Writer, opts DependencyDrillOptions) (DependencyDrillResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, defaultDrillTimeout)
	defer cancel()
	if out == nil {
		out = io.Discard
	}

	tempDir := opts.TempDir
	cleanup := func() {}
	if tempDir == "" {
		var err error
		tempDir, err = os.MkdirTemp("", "probectl-chaos-dependency-*")
		if err != nil {
			return DependencyDrillResult{}, fmt.Errorf("chaos dependency drill: temp dir: %w", err)
		}
		cleanup = func() { _ = os.RemoveAll(tempDir) }
	}
	defer cleanup()

	var res DependencyDrillResult
	if err := runDiskFullDrill(ctx, filepath.Join(tempDir, "agent-buffer"), &res); err != nil {
		return res, err
	}
	runMemoryPressureDrill(&res)
	if err := runPodKillDrill(ctx, opts, &res); err != nil {
		return res, err
	}
	if err := runDependencyOutageDrill(ctx, &res); err != nil {
		return res, err
	}

	if res.DiskFullRejected > 0 && res.DiskFullDropped > 0 && res.DiskFullRecoveryDrained == res.DiskFullEnqueued {
		res.RecoveryAssertionsPassed++
	}
	if res.MemoryPressureDropped > 0 && res.MemoryQuietAdmitted > 0 {
		res.RecoveryAssertionsPassed++
	}
	if res.PodKillKilled > 0 && res.PodKillRestarts > 0 && res.PodKillRequeued > 0 && res.PodKillRecoveredAcks >= 2 {
		res.RecoveryAssertionsPassed++
	}
	if res.DependencyOutageFailed > 0 && res.DependencyRecovered > 0 {
		res.RecoveryAssertionsPassed++
	}
	if res.RecoveryAssertionsPassed != 4 {
		return res, fmt.Errorf("chaos dependency drill: recovery assertions passed %d, want 4", res.RecoveryAssertionsPassed)
	}

	fmt.Fprintln(out, res.ResultLine())
	return res, nil
}

// ResultLine returns the stable CI evidence row.
func (r DependencyDrillResult) ResultLine() string {
	return fmt.Sprintf(
		"CHAOS_DEPENDENCY_RESULT disk_full_enqueued=%d disk_full_rejected=%d disk_full_dropped=%d disk_full_bytes=%d disk_full_recovery_drained=%d memory_pressure_admitted=%d memory_pressure_dropped=%d memory_pressure_quiet_admitted=%d pod_kill_killed=%d pod_kill_restarts=%d pod_kill_requeued=%d pod_kill_recovered_acks=%d dependency_healthy=%d dependency_outage_failed=%d dependency_recovered=%d recovery_assertions=%d",
		r.DiskFullEnqueued,
		r.DiskFullRejected,
		r.DiskFullDropped,
		r.DiskFullBufferedBytes,
		r.DiskFullRecoveryDrained,
		r.MemoryPressureAdmitted,
		r.MemoryPressureDropped,
		r.MemoryQuietAdmitted,
		r.PodKillKilled,
		r.PodKillRestarts,
		r.PodKillRequeued,
		r.PodKillRecoveredAcks,
		r.DependencyHealthy,
		r.DependencyOutageFailed,
		r.DependencyRecovered,
		r.RecoveryAssertionsPassed,
	)
}

func runDiskFullDrill(ctx context.Context, dir string, res *DependencyDrillResult) error {
	b, err := agent.OpenBufferWithBytes(dir, 1000, 220)
	if err != nil {
		return fmt.Errorf("chaos dependency drill: open agent buffer: %w", err)
	}
	payload := strings.Repeat("x", 100)
	for i := 0; i < 3; i++ {
		err := b.Enqueue([]byte(payload))
		switch {
		case err == nil:
			res.DiskFullEnqueued++
		case errors.Is(err, agent.ErrBufferFull):
			res.DiskFullRejected++
		default:
			return fmt.Errorf("chaos dependency drill: enqueue buffer payload %d: %w", i, err)
		}
	}
	res.DiskFullDropped = b.Dropped()
	res.DiskFullBufferedBytes = b.Bytes()
	drained, err := b.Drain(ctx, func([]byte) error { return nil })
	if err != nil {
		return fmt.Errorf("chaos dependency drill: drain agent buffer: %w", err)
	}
	res.DiskFullRecoveryDrained = drained
	return nil
}

func runMemoryPressureDrill(res *DependencyDrillResult) {
	limiter := pipeline.NewCardinalityLimiter(2, 10)
	for i := 0; i < 5; i++ {
		admitted, dropped := limiter.Filter("tenant-flood", "agent-1", []tsdb.Series{{
			Metric: fmt.Sprintf("chaos_metric_%d", i),
			Labels: map[string]string{"tenant_id": "tenant-flood"},
			Value:  1,
		}})
		res.MemoryPressureAdmitted += len(admitted)
		res.MemoryPressureDropped += dropped
	}
	admitted, _ := limiter.Filter("tenant-quiet", "agent-quiet", []tsdb.Series{{
		Metric: "steady_metric",
		Labels: map[string]string{"tenant_id": "tenant-quiet"},
		Value:  1,
	}})
	res.MemoryQuietAdmitted = len(admitted)
}

func runPodKillDrill(ctx context.Context, opts DependencyDrillOptions, res *DependencyDrillResult) error {
	if len(opts.WorkerCommand) == 0 {
		return errors.New("chaos dependency drill: worker command is required for pod-kill proof")
	}
	worker, err := startDrillWorker(ctx, opts)
	if err != nil {
		return err
	}
	defer worker.stop()

	if err := worker.send(ctx, "baseline"); err != nil {
		return fmt.Errorf("chaos dependency drill: baseline worker ack: %w", err)
	}
	if err := worker.write("inflight"); err != nil {
		return fmt.Errorf("chaos dependency drill: write inflight message: %w", err)
	}
	time.Sleep(25 * time.Millisecond)
	if err := worker.kill(); err != nil {
		return err
	}
	res.PodKillKilled++
	res.PodKillRequeued++

	worker, err = startDrillWorker(ctx, opts)
	if err != nil {
		return err
	}
	defer worker.stop()
	res.PodKillRestarts++
	if err := worker.send(ctx, "inflight"); err != nil {
		return fmt.Errorf("chaos dependency drill: requeued worker ack: %w", err)
	}
	res.PodKillRecoveredAcks++
	if err := worker.send(ctx, "after-restart"); err != nil {
		return fmt.Errorf("chaos dependency drill: recovery worker ack: %w", err)
	}
	res.PodKillRecoveredAcks++
	return nil
}

type drillWorker struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
}

func startDrillWorker(ctx context.Context, opts DependencyDrillOptions) (*drillWorker, error) {
	cmd := exec.CommandContext(ctx, opts.WorkerCommand[0], opts.WorkerCommand[1:]...)
	if len(opts.WorkerEnv) > 0 {
		cmd.Env = opts.WorkerEnv
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("chaos dependency drill: worker stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("chaos dependency drill: worker stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("chaos dependency drill: start worker: %w", err)
	}
	return &drillWorker{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout)}, nil
}

func (w *drillWorker) write(msg string) error {
	_, err := io.WriteString(w.stdin, msg+"\n")
	return err
}

func (w *drillWorker) send(ctx context.Context, msg string) error {
	if err := w.write(msg); err != nil {
		return err
	}
	type ack struct {
		line string
		err  error
	}
	ch := make(chan ack, 1)
	go func() {
		line, err := w.stdout.ReadString('\n')
		ch <- ack{line: strings.TrimSpace(line), err: err}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case got := <-ch:
		if got.err != nil {
			return got.err
		}
		want := "ack " + msg
		if got.line != want {
			return fmt.Errorf("got worker response %q, want %q", got.line, want)
		}
		return nil
	}
}

func (w *drillWorker) kill() error {
	if w.cmd.Process == nil {
		return errors.New("chaos dependency drill: worker process not started")
	}
	if err := w.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("chaos dependency drill: kill worker: %w", err)
	}
	_ = w.stdin.Close()
	_ = w.cmd.Wait()
	return nil
}

func (w *drillWorker) stop() {
	if w == nil {
		return
	}
	_ = w.stdin.Close()
	done := make(chan struct{})
	go func() {
		_ = w.cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		_ = w.cmd.Process.Kill()
		<-done
	}
}

func runDependencyOutageDrill(ctx context.Context, res *DependencyDrillResult) error {
	dep, err := startTCPDependency("127.0.0.1:0")
	if err != nil {
		return err
	}
	addr := dep.addr()
	if err := probeTCP(ctx, addr); err != nil {
		dep.close()
		return fmt.Errorf("chaos dependency drill: healthy dependency probe: %w", err)
	}
	res.DependencyHealthy++
	dep.close()
	if err := probeTCP(ctx, addr); err == nil {
		return errors.New("chaos dependency drill: dependency outage probe unexpectedly succeeded")
	}
	res.DependencyOutageFailed++

	dep, err = startTCPDependency(addr)
	if err != nil {
		return fmt.Errorf("chaos dependency drill: restart dependency: %w", err)
	}
	defer dep.close()
	if err := probeTCP(ctx, addr); err != nil {
		return fmt.Errorf("chaos dependency drill: recovered dependency probe: %w", err)
	}
	res.DependencyRecovered++
	return nil
}

type tcpDependency struct {
	ln   net.Listener
	done chan struct{}
}

func startTCPDependency(addr string) (*tcpDependency, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("chaos dependency drill: listen dependency %s: %w", addr, err)
	}
	dep := &tcpDependency{ln: ln, done: make(chan struct{})}
	go func() {
		defer close(dep.done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return dep, nil
}

func (d *tcpDependency) addr() string { return d.ln.Addr().String() }

func (d *tcpDependency) close() {
	_ = d.ln.Close()
	<-d.done
}

func probeTCP(ctx context.Context, addr string) error {
	dialer := net.Dialer{Timeout: 200 * time.Millisecond}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

// RunDependencyDrillWorker is the pod-kill helper process. It acknowledges one
// line at a time after ackDelay, giving the parent a real in-flight process to
// kill and restart.
func RunDependencyDrillWorker(in io.Reader, out io.Writer, ackDelay time.Duration) error {
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		if ackDelay > 0 {
			time.Sleep(ackDelay)
		}
		fmt.Fprintf(out, "ack %s\n", scanner.Text())
	}
	return scanner.Err()
}
