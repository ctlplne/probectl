// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build linux && ebpf

package ebpf

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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

func TestLiveIPv6Flow(t *testing.T) {
	ln, done := liveTCPServer(t, "tcp6", "[::1]:0")
	defer ln.Close()

	cfg := Default()
	cfg.TenantID = "kernel-matrix"
	src, err := newLiveSource(cfg)
	if err != nil {
		t.Skipf("live source unavailable on this kernel/privileges: %v", err)
	}
	defer src.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	flows, err := src.Flows(ctx)
	if err != nil {
		t.Fatalf("flows stream: %v", err)
	}
	liveTCPTransfer(t, "tcp6", ln.Addr().String(), []byte("probectl-ipv6"))
	waitLiveTCPServer(t, ctx, done)

	f, ok := waitLiveFlow(ctx, flows, func(f Flow) bool {
		return f.NetworkType == NetworkIPv6 && (f.Source.Address == "::1" || f.Destination.Address == "::1")
	})
	if !ok {
		t.Fatal("no IPv6 flow observed from loopback transfer")
	}
	if f.Source.Address == "" || f.Destination.Address == "" {
		t.Fatalf("IPv6 flow carried empty endpoint: %+v", f)
	}
}

func TestLiveBytePacketCounters(t *testing.T) {
	ln, done := liveTCPServer(t, "tcp4", "127.0.0.1:0")
	defer ln.Close()

	cfg := Default()
	cfg.TenantID = "kernel-matrix"
	src, err := newLiveSource(cfg)
	if err != nil {
		t.Skipf("live source unavailable on this kernel/privileges: %v", err)
	}
	defer src.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	flows, err := src.Flows(ctx)
	if err != nil {
		t.Fatalf("flows stream: %v", err)
	}
	liveTCPTransfer(t, "tcp4", ln.Addr().String(), []byte(strings.Repeat("x", 4096)))
	waitLiveTCPServer(t, ctx, done)

	f, ok := waitLiveFlow(ctx, flows, func(f Flow) bool {
		return f.State == StateClose && f.Bytes > 0 && f.Packets > 0
	})
	if !ok {
		t.Fatal("no close-state flow with non-zero byte/packet counters observed")
	}
	if f.NetworkType != NetworkIPv4 {
		t.Fatalf("counter smoke expected IPv4 loopback flow, got %+v", f)
	}
}

func liveTCPServer(t *testing.T, network, addr string) (net.Listener, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("%s listen unavailable at %s: %v", network, addr, err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(io.Discard, c)
	}()
	return ln, done
}

func liveTCPTransfer(t *testing.T, network, addr string, payload []byte) {
	t.Helper()
	c, err := net.DialTimeout(network, addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s %s: %v", network, addr, err)
	}
	if _, err := c.Write(payload); err != nil {
		_ = c.Close()
		t.Fatalf("write transfer payload: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close transfer socket: %v", err)
	}
}

func waitLiveTCPServer(t *testing.T, ctx context.Context, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("server did not finish transfer before timeout: %v", ctx.Err())
	}
}

func waitLiveFlow(ctx context.Context, flows <-chan Flow, pred func(Flow) bool) (Flow, bool) {
	for {
		select {
		case <-ctx.Done():
			return Flow{}, false
		case f, ok := <-flows:
			if !ok {
				return Flow{}, false
			}
			if pred(f) {
				return f, true
			}
		}
	}
}

func TestLiveLoadAttachSslsniff(t *testing.T) {
	cfg := Default()
	cfg.TenantID = "kernel-matrix"
	cfg.L7CaptureEnabled = true
	cfg.L7CaptureConsentTenant = "kernel-matrix" // U-003 consent for the smoke VM
	// EBPF-001: attach now requires the third gate — an explicit workload
	// allowlist (here: this test process).
	cfg.L7CaptureScope = []string{"pid:" + strconv.Itoa(os.Getpid())}
	src, err := newLiveL7Source(cfg)
	if err != nil {
		t.Skipf("sslsniff attach unavailable (no supported TLS library on this rootfs?): %v", err)
	}
	defer src.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := src.L7Events(ctx); err != nil {
		t.Fatalf("l7 events stream: %v", err)
	}
	<-ctx.Done()
}

func TestLiveGnuTLSAttach(t *testing.T) {
	libs, err := discoverTLSProbeLibrariesDefault(os.Getenv("PROBECTL_EBPF_LIBSSL"))
	if err != nil {
		t.Skipf("no supported TLS libraries on this rootfs: %v", err)
	}
	gnutls := false
	for _, lib := range libs {
		if lib.name == "gnutls" {
			gnutls = true
			break
		}
	}
	if !gnutls {
		t.Skip("libgnutls not on this rootfs — GnuTLS attach smoke needs it")
	}

	cfg := Default()
	cfg.TenantID = "kernel-matrix"
	cfg.L7CaptureEnabled = true
	cfg.L7CaptureConsentTenant = "kernel-matrix"
	cfg.L7CaptureScope = []string{"pid:" + strconv.Itoa(os.Getpid())}
	src, err := newLiveL7Source(cfg)
	if err != nil {
		t.Fatalf("GnuTLS-capable sslsniff attach failed: %v", err)
	}
	defer src.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := src.L7Events(ctx); err != nil {
		t.Fatalf("l7 events stream: %v", err)
	}
	<-ctx.Done()
}

// Sprint 18 (EBPF-001/RED-003) kernel gate: the in-kernel allowlist. An
// openssl client doing real TLS through an OpenSSL-compatible library produces
// ZERO ring events while it is not in scope, and produces events once its binary is
// allowlisted (exe: entry picked up by the refresher). This is the
// "non-allowlisted process produces no events" acceptance run on the
// kernel matrix.
func TestLiveScopeAllowlistAttach(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl binary not on this rootfs — allowlist traffic test needs it")
	}
	if resolved, rerr := filepath.EvalSymlinks(openssl); rerr == nil {
		openssl = resolved // /proc/<pid>/exe reports the resolved path
	}

	// A local TLS server (Go crypto/tls — no libssl, so the SERVER side can
	// never pollute the capture; only the openssl CLIENT exercises SSL_*).
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	// Fast exe: re-resolution so phase 2 sees the child quickly.
	oldRefresh := scopeRefreshInterval
	scopeRefreshInterval = 200 * time.Millisecond
	defer func() { scopeRefreshInterval = oldRefresh }()

	// run pipes one HTTP request through `openssl s_client` and returns the
	// child's PID. SSL_write fires in the CHILD process (the scope subject).
	run := func(ctx context.Context, delay time.Duration) (int, error) {
		cmd := exec.CommandContext(ctx, openssl, "s_client", "-connect", addr, "-quiet", "-verify_quiet")
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return 0, err
		}
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if err := cmd.Start(); err != nil {
			return 0, err
		}
		go func() {
			defer stdin.Close()
			time.Sleep(delay) // let the refresher allowlist the pid first (phase 2)
			_, _ = io.WriteString(stdin, "GET / HTTP/1.0\r\nHost: x\r\n\r\n")
			time.Sleep(500 * time.Millisecond)
		}()
		go func() { _ = cmd.Wait() }()
		return cmd.Process.Pid, nil
	}

	countFrom := func(events <-chan L7Event, pid int, window time.Duration) int {
		n := 0
		deadline := time.After(window)
		for {
			select {
			case ev, ok := <-events:
				if !ok {
					return n
				}
				if int(ev.Source.PID) == pid {
					n++
				}
			case <-deadline:
				return n
			}
		}
	}

	// ---- Phase 1: NOT allowlisted (scope = pid:1) → zero events. ----
	cfg := Default()
	cfg.TenantID = "kernel-matrix"
	cfg.L7CaptureEnabled = true
	cfg.L7CaptureConsentTenant = "kernel-matrix"
	cfg.L7CaptureScope = []string{"pid:1"}
	src, err := newLiveL7Source(cfg)
	if err != nil {
		t.Skipf("sslsniff attach unavailable (no supported TLS library on this rootfs?): %v", err)
	}
	ctx1, cancel1 := context.WithTimeout(context.Background(), 10*time.Second)
	events, err := src.L7Events(ctx1)
	if err != nil {
		cancel1()
		t.Fatalf("l7 events stream: %v", err)
	}
	pid, err := run(ctx1, 0)
	if err != nil {
		cancel1()
		_ = src.Close()
		t.Fatalf("spawn openssl: %v", err)
	}
	if n := countFrom(events, pid, 3*time.Second); n != 0 {
		cancel1()
		_ = src.Close()
		t.Fatalf("EBPF-001 VIOLATION: %d plaintext events from a NON-allowlisted process reached userspace", n)
	}
	cancel1()
	_ = src.Close()

	// ---- Phase 2: allowlisted via exe: → events flow. ----
	cfg2 := Default()
	cfg2.TenantID = "kernel-matrix"
	cfg2.L7CaptureEnabled = true
	cfg2.L7CaptureConsentTenant = "kernel-matrix"
	cfg2.L7CaptureScope = []string{"exe:" + openssl}
	src2, err := newLiveL7Source(cfg2)
	if err != nil {
		t.Fatalf("attach with exe: scope: %v", err)
	}
	defer src2.Close()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel2()
	events2, err := src2.L7Events(ctx2)
	if err != nil {
		t.Fatalf("l7 events stream: %v", err)
	}
	pid2, err := run(ctx2, 1*time.Second) // > 2 refresh ticks before any SSL_write
	if err != nil {
		t.Fatalf("spawn openssl: %v", err)
	}
	if n := countFrom(events2, pid2, 8*time.Second); n == 0 {
		t.Fatal("allowlisted (exe:) process produced no events — scope refresher or kernel filter broken")
	}
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

// TestLiveHardenedLockdownIntegrity (Sprint 19, EBPF-008): the hardened-
// kernel matrix entry. Kernel lockdown is raised to INTEGRITY inside the
// ephemeral QEMU VM (a one-way sysfs write — exactly why it runs in a
// throwaway kernel), then the full load+attach path must still work:
// integrity mode permits BPF (only CONFIDENTIALITY blocks it, U-075), and
// the capability probe must report the mode truthfully. Gated on
// PROBECTL_TEST_SET_LOCKDOWN=integrity so the regular matrix entries never
// poison their VMs.
func TestLiveHardenedLockdownIntegrity(t *testing.T) {
	if os.Getenv("PROBECTL_TEST_SET_LOCKDOWN") != "integrity" {
		t.Skip("set PROBECTL_TEST_SET_LOCKDOWN=integrity to run the hardened-lockdown entry")
	}
	const lockdownPath = "/sys/kernel/security/lockdown"
	cur, err := os.ReadFile(lockdownPath)
	if err != nil {
		t.Skipf("kernel has no lockdown LSM (%v) — hardened entry needs CONFIG_SECURITY_LOCKDOWN_LSM; distro-kernel coverage is the [needs infra] residual", err)
	}
	if !strings.Contains(string(cur), "[integrity]") {
		if werr := os.WriteFile(lockdownPath, []byte("integrity"), 0); werr != nil {
			t.Skipf("cannot raise lockdown to integrity (%v) — need root in the VM", werr)
		}
	}

	// The probe must see the hardened state and still report ready.
	caps := Probe()
	if caps.Lockdown != "integrity" {
		t.Fatalf("probe reports lockdown %q, want integrity (U-075 visibility)", caps.Lockdown)
	}
	if caps.Mode != ModeLive {
		t.Fatalf("integrity lockdown must NOT block the agent (only confidentiality does): mode=%s reason=%s", caps.Mode, caps.Reason)
	}

	// Full load+attach under lockdown: the flow plane...
	cfg := Default()
	cfg.TenantID = "hardened"
	src, err := newLiveSource(cfg)
	if err != nil {
		t.Fatalf("l4flow load+attach under lockdown=integrity: %v", err)
	}
	defer src.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := src.Flows(ctx); err != nil {
		t.Fatalf("flows stream under lockdown: %v", err)
	}

	// ...and the uprobe plane (skip only for missing supported TLS libraries,
	// same as the regular smoke).
	cfg2 := Default()
	cfg2.TenantID = "hardened"
	cfg2.L7CaptureEnabled = true
	cfg2.L7CaptureConsentTenant = "hardened"
	cfg2.L7CaptureScope = []string{"pid:" + strconv.Itoa(os.Getpid())}
	l7src, err := newLiveL7Source(cfg2)
	if err != nil {
		t.Logf("sslsniff under lockdown skipped (no supported TLS library on this rootfs?): %v", err)
		return
	}
	defer l7src.Close()
	if _, err := l7src.L7Events(ctx); err != nil {
		t.Fatalf("l7 events stream under lockdown: %v", err)
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
