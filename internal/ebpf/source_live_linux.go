// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build linux && ebpf

package ebpf

//go:generate bash gen_bpf.sh l4flow

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const l4DropRingBufferFull = uint32(0)

// liveSource is the CO-RE eBPF flow source: it loads bpf/l4flow.bpf.c, attaches
// it to the inet_sock_set_state tracepoint (observe-only), and decodes
// ring-buffer records into Flows, including IPv4/IPv6 addresses and TCP
// byte/packet counters when the kernel exposes them. Compiled only under -tags
// ebpf; it needs a BTF kernel (>= 5.8) and CAP_BPF (or root). The
// bpf2go-generated symbols (loadL4flowObjects / l4flowObjects) come from
// `go generate` (see the directive above) — run it on a Linux host with clang
// before building with -tags ebpf.
type liveSource struct {
	cfg   *Config
	objs  l4flowObjects
	tp    link.Link
	rd    *ringbuf.Reader
	drops atomic.Uint64
	// listenersSeeded reports whether the task_file iterator recorded the
	// listeners that predate the agent (ING-24); false on kernels without it.
	listenersSeeded bool
}

// seedListenersProgram is the l4flow iterator that records pre-existing
// listening sockets with their owning task (ING-24).
const seedListenersProgram = "seed_listeners"

// loadL4Collection loads l4flow. The listener-seeding iterator needs
// bpf_sock_from_file (kernel >= 5.11); on an older kernel the collection is
// loaded without it, so the documented >= 5.8 floor still captures flows and
// only a listener that predates the agent goes unattributed.
func loadL4Collection(spec *cebpf.CollectionSpec, objs *l4flowObjects) error {
	err := spec.LoadAndAssign(objs, nil)
	if err == nil {
		return nil
	}
	if _, ok := spec.Programs[seedListenersProgram]; !ok {
		return err
	}
	trimmed := spec.Copy()
	delete(trimmed.Programs, seedListenersProgram)
	var partial struct {
		l4flowMaps
		HandleSetState *cebpf.Program `ebpf:"handle_set_state"`
	}
	if err2 := trimmed.LoadAndAssign(&partial, nil); err2 != nil {
		return err // the full-collection error is the informative one
	}
	objs.l4flowMaps = partial.l4flowMaps
	objs.HandleSetState = partial.HandleSetState
	return nil
}

// seedListeners runs the listener iterator to completion once. Its only effect
// is map writes inside the kernel; a missing program or a refused iterator is
// a degraded start, never a failed one.
func seedListeners(prog *cebpf.Program) bool {
	if prog == nil {
		return false
	}
	it, err := link.AttachIter(link.IterOptions{Program: prog})
	if err != nil {
		return false
	}
	defer it.Close()
	rd, err := it.Open()
	if err != nil {
		return false
	}
	defer rd.Close()
	_, err = io.Copy(io.Discard, rd)
	return err == nil
}

// ListenersSeeded reports whether pre-existing listeners were attributed.
func (s *liveSource) ListenersSeeded() bool { return s.listenersSeeded }

// newLiveSource loads and attaches the eBPF program. This is the only place that
// calls the bpf() syscall, and it loads only an observation (tracepoint) program.
func newLiveSource(cfg *Config) (Source, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpf: remove memlock (need CAP_BPF/root): %w", err)
	}
	s := &liveSource{cfg: cfg}
	// U-014: refuse an embedded object that mismatches the same-build digest
	// manifest (swap/corruption/stale generator) before any kernel load.
	// Artifact tampering is the cosign release signature's domain.
	if err := verifyObjectDigest("l4flow", _L4flowBytes, bpfObjectDigests["l4flow"]); err != nil {
		return nil, err
	}
	// U-050: size the kernel ring buffer from the config (rounded to a valid
	// power-of-two page multiple) instead of the compiled-in default.
	spec, err := loadL4flow()
	if err != nil {
		return nil, fmt.Errorf("ebpf: load collection spec: %w", err)
	}
	applyL4RingBufferSpec(spec, cfg)
	if err := loadL4Collection(spec, &s.objs); err != nil {
		// U-075: a kernel-lockdown confidentiality failure is explained, not
		// surfaced as a bare EPERM.
		return nil, explainBPFLoadError(fmt.Errorf("ebpf: load objects (need a BTF kernel + CAP_BPF): %w", err))
	}
	tp, err := link.Tracepoint("sock", "inet_sock_set_state", s.objs.HandleSetState, nil)
	if err != nil {
		_ = s.objs.Close()
		if !traceFSVisible() {
			// DPR-054: say what to mount, not just that nothing was mounted.
			return nil, fmt.Errorf("ebpf: attach tracepoint: %w — %s", err, traceFSReason)
		}
		return nil, fmt.Errorf("ebpf: attach tracepoint: %w", err)
	}
	s.tp = tp
	// ING-24: listeners opened before the agent are recorded once, AFTER the
	// tracepoint is live, so a listen() racing the start is caught by one or
	// the other. A kernel without the iterator keeps the tracepoint-only view.
	s.listenersSeeded = seedListeners(s.objs.SeedListeners)
	rd, err := ringbuf.NewReader(s.objs.Events)
	if err != nil {
		_ = tp.Close()
		_ = s.objs.Close()
		return nil, fmt.Errorf("ebpf: open ring buffer: %w", err)
	}
	s.rd = rd
	return s, nil
}

// Flows decodes ring-buffer records into Flows until ctx is canceled.
func (s *liveSource) Flows(ctx context.Context) (<-chan Flow, error) {
	ch := make(chan Flow)
	go func() {
		defer close(ch)
		go func() {
			<-ctx.Done()
			_ = s.rd.Close() // unblock Read
		}()
		for {
			rec, err := s.rd.Read()
			if err != nil {
				return // reader closed (ctx canceled) or fatal
			}
			// FUZZ-006: a corrupt/short ring sample must never panic the decode
			// loop (which would silently stop flow capture). Recover per-record,
			// count a drop, and keep reading.
			flow, ok := s.decodeFlowSafely(rec.RawSample)
			if !ok {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case ch <- flow:
			}
		}
	}()
	return ch, nil
}

// decodeFlowSafely decodes one ring-buffer sample into a Flow, recovering from
// any panic (FUZZ-006). On a decode error or panic it counts a drop and returns
// ok=false so the read loop simply continues.
func (s *liveSource) decodeFlowSafely(sample []byte) (flow Flow, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			s.drops.Add(1)
			flow, ok = Flow{}, false
		}
	}()
	flow, err := decodeL4FlowSample(sample, s.cfg)
	if err != nil {
		s.drops.Add(1)
		return Flow{}, false
	}
	return flow, true
}

// explainBPFLoadError wraps a bpf() load failure with a clear, structured
// degradation message when the cause is kernel lockdown confidentiality mode
// (U-075) — instead of surfacing a bare EPERM/"operation not permitted" that
// looks like a missing capability. It lives in this -tags ebpf file because
// the load path is its only consumer (the untagged build would flag it
// unused).
func explainBPFLoadError(err error) error {
	if err == nil {
		return nil
	}
	if lockdownBlocksBPF(lockdownMode()) {
		return fmt.Errorf("ebpf: kernel lockdown is in CONFIDENTIALITY mode, which blocks bpf() even with CAP_BPF — the eBPF agent cannot load programs here; boot without lockdown=confidentiality or use integrity mode (U-075): %w", err)
	}
	return err
}

// DropStats returns cumulative L4 source loss, including kernel-side ring-buffer
// reserve failures that userspace cannot infer from the reader.
func (s *liveSource) DropStats() DropStats {
	return DropStats{
		DecodeFailures:   s.drops.Load(),
		L4RingBufferFull: percpuCounter(s.objs.DropCounters, l4DropRingBufferFull),
	}
}

// Drops returns cumulative dropped records.
func (s *liveSource) Drops() uint64 { return s.DropStats().Total() }

// FilteredNonIPv4 returns the cumulative count of flows dropped in-kernel for
// an unsupported address family — summed across CPUs from the percpu `filtered`
// map. The method keeps the legacy telemetry name; IPv6 is captured now.
func (s *liveSource) FilteredNonIPv4() uint64 {
	if s.objs.Filtered == nil {
		return 0
	}
	var perCPU []uint64
	if err := s.objs.Filtered.Lookup(uint32(0), &perCPU); err != nil {
		return 0
	}
	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return sum
}

func percpuCounter(m *cebpf.Map, key uint32) uint64 {
	if m == nil {
		return 0
	}
	var perCPU []uint64
	if err := m.Lookup(key, &perCPU); err != nil {
		return 0
	}
	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return sum
}

// Close detaches the program and releases the ring buffer.
func (s *liveSource) Close() error {
	if s.rd != nil {
		_ = s.rd.Close()
	}
	if s.tp != nil {
		_ = s.tp.Close()
	}
	return s.objs.Close()
}
