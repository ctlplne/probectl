//go:build linux && ebpf

package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -tags ebpf l4flow ./bpf/l4flow.bpf.c -- -I./bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync/atomic"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// liveSource is the CO-RE eBPF flow source: it loads bpf/l4flow.bpf.c, attaches
// it to the inet_sock_set_state tracepoint (observe-only), and decodes
// ring-buffer records into Flows. Compiled only under -tags ebpf; it needs a BTF
// kernel (>= 5.8) and CAP_BPF (or root). The bpf2go-generated symbols
// (loadL4flowObjects / l4flowObjects) come from `go generate` (see the directive
// above) — run it on a Linux host with clang before building with -tags ebpf.
type liveSource struct {
	cfg   *Config
	objs  l4flowObjects
	tp    link.Link
	rd    *ringbuf.Reader
	drops atomic.Uint64
}

// l4eventC mirrors struct l4_event in bpf/l4flow.bpf.c (36 bytes, little-endian).
type l4eventC struct {
	PID      uint32
	Comm     [16]byte
	Saddr    [4]byte
	Daddr    [4]byte
	Sport    uint16
	Dport    uint16
	Family   uint16
	NewState uint8
	Pad      uint8
}

// newLiveSource loads and attaches the eBPF program. This is the only place that
// calls the bpf() syscall, and it loads only an observation (tracepoint) program.
func newLiveSource(cfg *Config) (Source, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpf: remove memlock (need CAP_BPF/root): %w", err)
	}
	s := &liveSource{cfg: cfg}
	// U-014: refuse a tampered/stale embedded object before any kernel load.
	if err := VerifyObjectDigest("l4flow", _L4flowBytes, bpfObjectDigests["l4flow"]); err != nil {
		return nil, err
	}
	// U-050: size the kernel ring buffer from the config (rounded to a valid
	// power-of-two page multiple) instead of the compiled-in default.
	spec, err := loadL4flow()
	if err != nil {
		return nil, fmt.Errorf("ebpf: load collection spec: %w", err)
	}
	if m, ok := spec.Maps["events"]; ok {
		m.MaxEntries = ringBufferBytes(cfg.RingBufferBytes)
	}
	if err := spec.LoadAndAssign(&s.objs, nil); err != nil {
		// U-075: a kernel-lockdown confidentiality failure is explained, not
		// surfaced as a bare EPERM.
		return nil, explainBPFLoadError(fmt.Errorf("ebpf: load objects (need a BTF kernel + CAP_BPF): %w", err))
	}
	tp, err := link.Tracepoint("sock", "inet_sock_set_state", s.objs.HandleSetState, nil)
	if err != nil {
		_ = s.objs.Close()
		return nil, fmt.Errorf("ebpf: attach tracepoint: %w", err)
	}
	s.tp = tp
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
			var e l4eventC
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
				s.drops.Add(1)
				continue
			}
			select {
			case <-ctx.Done():
				return
			case ch <- e.toFlow(s.cfg):
			}
		}
	}()
	return ch, nil
}

func (e l4eventC) toFlow(cfg *Config) Flow {
	return Flow{
		TenantID:    cfg.TenantID,
		AgentID:     cfg.Host,
		Host:        cfg.Host,
		Source:      Endpoint{Address: netip.AddrFrom4(e.Saddr).String(), Port: uint32(e.Sport), PID: e.PID, Process: nullTerm(e.Comm[:])},
		Destination: Endpoint{Address: netip.AddrFrom4(e.Daddr).String(), Port: uint32(e.Dport)},
		Transport:   TransportTCP,
		NetworkType: NetworkIPv4,
		Direction:   DirectionEgress,
		State:       StateEstablished,
	}
}

// Drops returns cumulative dropped records (decode failures + ring-buffer-full).
func (s *liveSource) Drops() uint64 { return s.drops.Load() }

// FilteredNonIPv4 returns the cumulative count of flows dropped in-kernel for
// being non-IPv4 (U-073) — summed across CPUs from the percpu `filtered` map.
// The agent folds this into its filtered_non_ipv4_total telemetry so the
// IPv4-only capture limitation is measurable, never silent.
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

func nullTerm(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
