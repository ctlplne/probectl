//go:build linux && ebpf

package ebpf

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// U-021 kernel-matrix smoke: actually LOAD and ATTACH every BPF program on
// the running kernel (the ci job runs this inside QEMU on >=2 LTS kernels
// via vimto). The C9 digest verification runs inherently inside newLive*.
func TestLiveLoadAttachL4Flow(t *testing.T) {
	cfg := Default()
	cfg.TenantID = "kernel-matrix"
	src, err := newLiveSource(cfg)
	if err != nil {
		t.Fatalf("l4flow load+attach failed on this kernel: %v", err)
	}
	defer src.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	flows, err := src.Flows(ctx)
	if err != nil {
		t.Fatalf("flows stream: %v", err)
	}
	// Drain briefly: the tracepoint is attached; traffic is optional.
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-flows:
			if !ok {
				return
			}
		}
	}
}

func TestLiveLoadAttachSslsniff(t *testing.T) {
	cfg := Default()
	cfg.TenantID = "kernel-matrix"
	cfg.L7CaptureEnabled = true
	cfg.L7CaptureConsentTenant = "kernel-matrix" // U-003 consent for the smoke VM
	src, err := newLiveL7Source(cfg)
	if err != nil {
		t.Skipf("sslsniff attach unavailable (no libssl on this rootfs?): %v", err)
	}
	defer src.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := src.L7Events(ctx); err != nil {
		t.Fatalf("l7 events stream: %v", err)
	}
	<-ctx.Done()
}

// The agent end-to-end on a live kernel: capability probe, live source, one
// flush cycle — runs observe-only by construction (the static gate enforces
// program types; this proves the runtime path on the matrix kernel).
func TestLiveAgentBoot(t *testing.T) {
	cfg := Default()
	cfg.TenantID = "kernel-matrix"
	cfg.FlushInterval = 200 * time.Millisecond
	a, err := New(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("agent boot on this kernel: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.Run(ctx); err != nil {
		t.Fatalf("agent run: %v", err)
	}
}

// TestLiveOverheadReport (Sprint 17, DOCS-006): measure the REAL ring-buffer
// path — not the userspace fixture replay — on a live kernel: load + attach,
// generate loopback traffic through the tracepoints, and sample this
// process's CPU + RSS over the window. Prints the OVERHEAD ROW for
// docs/agent-overhead.md. Runs wherever the kernel-matrix smoke runs (QEMU
// CI job, reference hosts); PROBECTL_OVERHEAD_SECONDS tunes the window.
func TestLiveOverheadReport(t *testing.T) {
	secs := 10
	if v := os.Getenv("PROBECTL_OVERHEAD_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			secs = n
		}
	}
	cfg := Default()
	cfg.TenantID = "overhead"
	src, err := newLiveSource(cfg)
	if err != nil {
		t.Skipf("live source unavailable on this kernel/privileges: %v", err)
	}
	defer src.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs+5)*time.Second)
	defer cancel()
	flows, err := src.Flows(ctx)
	if err != nil {
		t.Fatalf("flows stream: %v", err)
	}

	// Traffic generator: loopback TCP connects exercise the connect/close
	// tracepoints + the ring buffer for the whole window.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	var before, after syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &before)
	start := time.Now()
	deadline := start.Add(time.Duration(secs) * time.Second)
	events, conns := 0, 0
	for time.Now().Before(deadline) {
		c, derr := net.Dial("tcp", ln.Addr().String())
		if derr == nil {
			_ = c.Close()
			conns++
		}
		drain := true
		for drain {
			select {
			case _, ok := <-flows:
				if !ok {
					drain = false
				} else {
					events++
				}
			default:
				drain = false
			}
		}
	}
	elapsed := time.Since(start)
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &after)

	cpuUser := time.Duration(after.Utime.Nano() - before.Utime.Nano())
	cpuSys := time.Duration(after.Stime.Nano() - before.Stime.Nano())
	cpuPct := 100 * float64(cpuUser+cpuSys) / float64(elapsed)
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	// The row docs/agent-overhead.md's live table records.
	t.Logf("OVERHEAD ROW | live ring-buffer | %ds window | %d conns | %d events | cpu %.2f%% (user %s sys %s) | heap %.1f MiB | maxrss %.1f MiB",
		secs, conns, events, cpuPct, cpuUser.Round(time.Millisecond), cpuSys.Round(time.Millisecond),
		float64(ms.HeapAlloc)/(1<<20), float64(after.Maxrss)/1024)
	if events == 0 {
		t.Log("note: zero ring-buffer events — check tracepoint coverage for loopback on this kernel")
	}
}
