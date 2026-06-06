//go:build linux && ebpf

package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -tags ebpf sslsniff ./bpf/sslsniff.bpf.c -- -I./bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/imfeelingtheagi/probectl/internal/ebpf/l7"
)

// liveL7Source captures TLS plaintext via uprobes on the SSL library's read/
// write functions. OpenSSL and BoringSSL share the SSL_* API; GnuTLS uses
// gnutls_record_send/recv (attach the same way). SSL_read is captured at the
// uretprobe because the buffer is filled on return. Built only under -tags ebpf.
//
// A captured chunk is keyed to a connection by the SSL* pointer. Resolving the
// full 5-tuple (and thus the precise service edge) requires correlating the
// SSL/fd to its socket via a kprobe — the documented productionization step
// (docs/ebpf-agent.md). Go's crypto/tls does NOT use libssl and needs the
// separate ret-offset + goroutine-tracking strategy (docs/ebpf-feasibility.md §7).
type liveL7Source struct {
	objs  sslsniffObjects
	links []link.Link
	rd    *ringbuf.Reader
	cfg   *Config
	drops atomic.Uint64
}

// sslChunk mirrors struct tls_chunk in bpf/sslsniff.bpf.c.
type sslChunk struct {
	PID    uint32
	TID    uint32
	Conn   uint64
	IsRead uint8
	Pad    [3]byte
	Len    uint32
	Data   [4096]byte
}

func newLiveL7Source(cfg *Config) (L7Source, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpf: remove memlock: %w", err)
	}
	s := &liveL7Source{cfg: cfg}
	// U-014: the embedded object must match the build-time manifest before
	// the kernel ever sees it; a tampered/stale object refuses to load.
	if err := VerifyObjectDigest("sslsniff", _SslsniffBytes, bpfObjectDigests["sslsniff"]); err != nil {
		return nil, err
	}
	if err := loadSslsniffObjects(&s.objs, nil); err != nil {
		return nil, fmt.Errorf("ebpf: load sslsniff objects (need a BTF kernel + CAP_BPF): %w", err)
	}

	libssl, err := opensslPath()
	if err != nil {
		_ = s.objs.Close()
		return nil, fmt.Errorf("ebpf: %w", err)
	}
	ex, err := link.OpenExecutable(libssl)
	if err != nil {
		_ = s.objs.Close()
		return nil, fmt.Errorf("ebpf: open libssl %q: %w", libssl, err)
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
			return fmt.Errorf("attach %s: %w", sym, err)
		}
		s.links = append(s.links, l)
		return nil
	}
	if err := attach("SSL_write", s.objs.ProbeSslWrite, false); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("ebpf: %w", err)
	}
	if err := attach("SSL_read", s.objs.ProbeSslReadEnter, false); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("ebpf: %w", err)
	}
	if err := attach("SSL_read", s.objs.ProbeSslReadExit, true); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("ebpf: %w", err)
	}

	rd, err := ringbuf.NewReader(s.objs.TlsChunks)
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("ebpf: open ring buffer: %w", err)
	}
	s.rd = rd
	return s, nil
}

func (s *liveL7Source) L7Events(ctx context.Context) (<-chan L7Event, error) {
	ch := make(chan L7Event)
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
			var c sslChunk
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &c); err != nil {
				s.drops.Add(1)
				continue
			}
			kind := l7.Request
			if c.IsRead == 1 {
				kind = l7.Response
			}
			n := c.Len
			if n > uint32(len(c.Data)) {
				n = uint32(len(c.Data))
			}
			// U-003 redaction boundary: the ONLY copy of the plaintext is
			// redacted in place before anything downstream (parsers,
			// buffers) can retain it. rec.RawSample is kernel-owned and
			// reused on the next ring read; no other reference survives.
			payload := RedactPayload(append([]byte(nil), c.Data[:n]...), s.cfg.L7CaptureRedaction)
			ev := L7Event{
				ConnID:      c.Conn,
				TenantID:    s.cfg.TenantID,
				Encrypted:   true,
				Source:      Endpoint{PID: c.PID}, // 5-tuple correlation is the productionization step
				Destination: Endpoint{},
				Transport:   TransportTCP,
				Data: l7.DataEvent{
					Kind:    kind,
					Time:    time.Now(),
					Payload: payload,
				},
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

func (s *liveL7Source) Drops() uint64 { return s.drops.Load() }

func (s *liveL7Source) Close() error {
	if s.rd != nil {
		_ = s.rd.Close()
	}
	for _, l := range s.links {
		_ = l.Close()
	}
	return s.objs.Close()
}

// opensslPath is the libssl to attach to: the PROBECTL_EBPF_LIBSSL override,
// else multi-arch discovery (ldconfig cache + per-arch candidates — U-015; see
// libssl.go). Extend to discover BoringSSL / GnuTLS / per-process paths.
func opensslPath() (string, error) {
	if p := os.Getenv("PROBECTL_EBPF_LIBSSL"); p != "" {
		return p, nil
	}
	return discoverLibsslDefault()
}
