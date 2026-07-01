// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build linux && ebpf

package ebpf

// sslsniff uses uprobes (BPF_UPROBE → PT_REGS_PARM*). BPF_UPROBE is a libbpf
// ≥1.2 macro, so the libbpf BPF headers are vendored under bpf/headers and the
// compile no longer depends on the build host's libbpf-dev (bookworm's 1.1
// lacked BPF_UPROBE; see bpf/headers/VENDOR.md).
//
// Every bpf2go invocation (here, the Makefile, ci.yml, Dockerfile.ebpf) goes
// through gen_bpf.sh — one source of truth for the -I flags, the per-arch
// target, and the arch_compat opt-out. The arm64 register file (struct
// user_pt_regs) is absent from an x86-dumped vmlinux.h (supplied then by
// bpf/arch_compat.h) but PRESENT in an arm64-dumped one; gen_bpf.sh inspects
// vmlinux.h and sets -DPROBECTL_VMLINUX_HAS_USER_PT_REGS when the real struct
// is there, so native-arm64 builds and the x86→arm64 cross-build both compile.
// l4flow is arch-neutral (-target bpfel) and needs no per-arch build.
//go:generate bash gen_bpf.sh sslsniff

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	l7DropRingBufferFull     = uint32(0)
	l7DropActiveReadFailures = uint32(1)
)

// liveL7Source captures TLS plaintext via uprobes on supported TLS library
// read/write functions. OpenSSL and BoringSSL share the SSL_* API; GnuTLS uses
// gnutls_record_send/recv. Read functions are captured at the uretprobe because
// the buffer is filled on return. Built only under -tags ebpf.
//
// A captured chunk is keyed to a connection by the SSL* pointer. Resolving the
// full 5-tuple (and thus the precise service edge) requires correlating the
// SSL/fd to its socket via a kprobe — the documented productionization step
// (docs/ebpf-agent.md). Go's crypto/tls does NOT use libssl and needs the
// separate ret-offset + goroutine-tracking strategy (docs/ebpf-feasibility.md §7).
type liveL7Source struct {
	objs    sslsniffObjects
	links   []link.Link
	rd      *ringbuf.Reader
	cfg     *Config
	scope   []ScopeEntry
	exePIDs map[uint32]struct{} // tgids we programmed for exe: entries (refresher diff)
	drops   atomic.Uint64

	scopeRefresh *l7ScopeSyncMonitor
}

// scopeRefreshInterval is how often exe: entries are re-resolved against
// /proc while capture runs (new workers of an opted-in binary join scope;
// exited PIDs leave it). Test-tunable.
var scopeRefreshInterval = 10 * time.Second

func newLiveL7Source(cfg *Config, log *slog.Logger) (L7Source, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpf: remove memlock: %w", err)
	}
	// EBPF-001: the scope allowlist is the third consent gate — refuse to
	// attach at all without it (the maps would match nothing anyway; this
	// makes the refusal loud instead of silent).
	scope, err := ParseScopeEntries(cfg.L7CaptureScope)
	if err != nil {
		return nil, err
	}
	if len(scope) == 0 {
		return nil, fmt.Errorf("ebpf: l7_capture_scope is empty — TLS capture requires an explicit workload allowlist (EBPF-001)")
	}
	s := &liveL7Source{cfg: cfg, scope: scope, exePIDs: map[uint32]struct{}{}}
	if s.hasExeEntries() {
		s.scopeRefresh = newL7ScopeSyncMonitor(cfg, log, scopeExe)
	}
	// U-014: the embedded object must match the build-time manifest before
	// the kernel ever sees it; a tampered/stale object refuses to load. The
	// object (and so its manifest key) is per-arch — see the bpf2go directive.
	objName := "sslsniff_x86"
	if runtime.GOARCH == "arm64" {
		objName = "sslsniff_arm64"
	}
	if err := VerifyObjectDigest(objName, _SslsniffBytes, bpfObjectDigests[objName]); err != nil {
		return nil, err
	}
	if err := loadSslsniffObjects(&s.objs, nil); err != nil {
		return nil, fmt.Errorf("ebpf: load sslsniff objects (need a BTF kernel + CAP_BPF): %w", err)
	}

	// Program the kernel-side policy BEFORE attaching: the capture window
	// (EBPF-002 — the map's zero default is length-only, fail-closed) and
	// the process scope (EBPF-001 — empty maps match nothing). Order means
	// no probe ever fires against an unprogrammed policy.
	window := kernelWindowFor(cfg.L7CaptureRedaction, cfg.L7CaptureKernelWindow)
	if err := s.objs.CaptureCfg.Put(uint32(0), window); err != nil {
		_ = s.objs.Close()
		return nil, fmt.Errorf("ebpf: program capture window: %w", err)
	}
	if err := s.syncScope(); err != nil {
		_ = s.objs.Close()
		return nil, err
	}

	libs, err := tlsProbeLibraries()
	if err != nil {
		_ = s.objs.Close()
		return nil, fmt.Errorf("ebpf: %w", err)
	}
	for _, lib := range libs {
		if err := s.attachTLSLibrary(lib); err != nil {
			_ = s.Close()
			return nil, fmt.Errorf("ebpf: %w", err)
		}
	}

	rd, err := ringbuf.NewReader(s.objs.TlsChunks)
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("ebpf: open ring buffer: %w", err)
	}
	s.rd = rd
	return s, nil
}

func (s *liveL7Source) attachTLSLibrary(lib tlsProbeLibrary) error {
	ex, err := link.OpenExecutable(lib.path)
	if err != nil {
		return fmt.Errorf("open %s TLS library %q: %w", lib.name, lib.path, err)
	}
	attach := func(sym string, prog *cebpf.Program, ret bool) error {
		var (
			l   link.Link
			err error
		)
		if ret {
			l, err = ex.Uretprobe(sym, prog, nil)
		} else {
			l, err = ex.Uprobe(sym, prog, nil)
		}
		if err != nil {
			return fmt.Errorf("attach %s %s in %q: %w", lib.name, sym, lib.path, err)
		}
		s.links = append(s.links, l)
		return nil
	}
	if err := attach(lib.writeSymbol, s.objs.ProbeSslWrite, false); err != nil {
		return err
	}
	if err := attach(lib.readSymbol, s.objs.ProbeSslReadEnter, false); err != nil {
		return err
	}
	if err := attach(lib.readSymbol, s.objs.ProbeSslReadExit, true); err != nil {
		return err
	}
	return nil
}

// syncScope materializes the allowlist into the kernel maps. pid: and
// cgroup: entries are stable; exe: entries are re-resolved against /proc —
// newly started processes of an opted-in binary are added and exited ones
// removed (only tgids owned by exe: entries are ever removed, so explicit
// pid: opt-ins persist).
func (s *liveL7Source) syncScope() error {
	procRoot := s.cfg.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	tgids, cgroups, err := resolveScope(s.scope, procRoot)
	if err != nil {
		return err
	}
	for id := range cgroups {
		if err := s.objs.ScopeCgroups.Put(id, uint8(1)); err != nil {
			return fmt.Errorf("ebpf: program scope cgroup %d: %w", id, err)
		}
	}
	// Static pid: entries (always present in tgids) plus current exe: matches.
	static := map[uint32]struct{}{}
	for _, e := range s.scope {
		if e.Kind == scopePID {
			static[e.PID] = struct{}{}
		}
	}
	next := map[uint32]struct{}{}
	for tgid := range tgids {
		if err := s.objs.ScopeTgids.Put(tgid, uint8(1)); err != nil {
			return fmt.Errorf("ebpf: program scope tgid %d: %w", tgid, err)
		}
		if _, isStatic := static[tgid]; !isStatic {
			next[tgid] = struct{}{}
		}
	}
	// Exited exe-resolved processes leave scope (delete is idempotent).
	for tgid := range s.exePIDs {
		if _, still := next[tgid]; !still {
			if _, isStatic := static[tgid]; !isStatic {
				_ = s.objs.ScopeTgids.Delete(tgid)
			}
		}
	}
	s.exePIDs = next
	return nil
}

// hasExeEntries reports whether the allowlist needs periodic re-resolution.
func (s *liveL7Source) hasExeEntries() bool {
	for _, e := range s.scope {
		if e.Kind == scopeExe {
			return true
		}
	}
	return false
}

func (s *liveL7Source) L7Events(ctx context.Context) (<-chan L7Event, error) {
	ch := make(chan L7Event)
	if s.hasExeEntries() {
		// exe: allowlist entries track the BINARY, not a PID — re-resolve
		// while capture runs so restarts/new workers stay opted in.
		go func() {
			t := time.NewTicker(scopeRefreshInterval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					s.scopeRefresh.Refresh(s.syncScope) // transient /proc races retry next tick
				}
			}
		}()
	}
	go func() {
		defer close(ch)
		go func() {
			<-ctx.Done()
			_ = s.rd.Close()
		}()
		for {
			rec, err := s.rd.Read()
			if err != nil {
				return
			}
			// U-003/EBPF-002 boundary: decodeChunk redacts the ONLY copy of
			// the plaintext before anything downstream (parsers, buffers)
			// can retain it. rec.RawSample is kernel-owned and reused on
			// the next ring read; no other reference survives. The kernel
			// already withheld everything past the capture window.
			// FUZZ-006: recover per-record so a corrupt sample can never panic
			// the L7 decode loop and silently stop capture.
			ev, ok := s.decodeChunkSafely(rec.RawSample)
			if !ok {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case ch <- ev:
			}
		}
	}()
	return ch, nil
}

// decodeChunkSafely decodes one ring-buffer L7 sample, recovering from any
// panic (FUZZ-006). On a decode error or panic it counts a drop and returns
// ok=false so the read loop continues. The redaction boundary is unchanged:
// decodeChunk still redacts the only plaintext copy before this returns.
func (s *liveL7Source) decodeChunkSafely(sample []byte) (ev L7Event, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			s.drops.Add(1)
			ev, ok = L7Event{}, false
		}
	}()
	e, err := decodeChunkWithPolicy(sample, s.cfg.TenantID, s.cfg.L7CaptureRedaction, headerValuePolicy{
		identityFragments: s.cfg.L7CaptureIdentityHeaderFragments,
		hashAllValues:     s.cfg.L7CaptureHashAllHeaderValues,
	})
	if err != nil {
		s.drops.Add(1)
		return L7Event{}, false
	}
	return e, true
}

func (s *liveL7Source) DropStats() DropStats {
	return DropStats{
		DecodeFailures:       s.drops.Load(),
		L7RingBufferFull:     percpuCounter(s.objs.DropCounters, l7DropRingBufferFull),
		L7ActiveReadFailures: percpuCounter(s.objs.DropCounters, l7DropActiveReadFailures),
		L7ScopeSyncFailures:  s.L7ScopeSyncFailures(),
	}
}

func (s *liveL7Source) Drops() uint64 { return s.DropStats().Total() }

func (s *liveL7Source) L7ScopeSyncFailures() uint64 {
	if s.scopeRefresh == nil {
		return 0
	}
	return s.scopeRefresh.Failures()
}

func (s *liveL7Source) L7ScopeSyncDegraded() bool {
	return s.scopeRefresh != nil && s.scopeRefresh.Degraded()
}

func (s *liveL7Source) L7ScopeSyncLastError() string {
	if s.scopeRefresh == nil {
		return ""
	}
	return s.scopeRefresh.LastError()
}

func (s *liveL7Source) Close() error {
	if s.rd != nil {
		_ = s.rd.Close()
	}
	for _, l := range s.links {
		_ = l.Close()
	}
	return s.objs.Close()
}

// tlsProbeLibraries are the shared TLS objects to attach to: the
// PROBECTL_EBPF_LIBSSL override for OpenSSL-compatible stacks, then multi-arch
// discovery (ldconfig cache + per-arch candidates — U-015/EBPF-001; see
// libssl.go) for OpenSSL-compatible libssl and GnuTLS.
func tlsProbeLibraries() ([]tlsProbeLibrary, error) {
	return discoverTLSProbeLibrariesDefault(os.Getenv("PROBECTL_EBPF_LIBSSL"))
}
