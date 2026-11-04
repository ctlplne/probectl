// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const BodyChunkBytes = 64 << 10

var (
	ErrBodyStageLimit = errors.New("report body staging budget exceeded")
	ErrBodyStageScope = errors.New("report body staging tenant scope is unavailable")
	ErrBodyStageState = errors.New("report body staging state is unavailable")
)

type BodyStageLimits struct{ Bytes, MemoryBytes int64 }
type BodyStageReceipt struct {
	Bytes, AllocatedBytes int64
	SHA256                string
}

func DefaultBodyStageLimits() BodyStageLimits {
	maximum := DefaultCSVLimits().Bytes
	return BodyStageLimits{Bytes: maximum, MemoryBytes: maximum + (maximum/BodyChunkBytes)*64 + 256<<10}
}

// BodyStage owns temporary renderer bytes in this request only. It is not an
// artifact store, cache, source grant or publication receipt. Close invalidates
// readers and clears every buffer, including after a failed render/hash.
type BodyStage struct {
	mu        sync.Mutex
	ctx       context.Context
	tenant    string
	limits    BodyStageLimits
	chunks    [][]byte
	size      int64
	allocated int64
	state     string
	err       error
	reading   bool
	receipt   BodyStageReceipt
}

func NewBodyStage(ctx context.Context, tenant string, limits BodyStageLimits) (*BodyStage, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || tenant == "" || bound.String() != tenant {
		return nil, ErrBodyStageScope
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limits.Bytes <= 0 || limits.Bytes > DefaultCSVLimits().Bytes || limits.MemoryBytes <= 0 {
		return nil, ErrBodyStageLimit
	}
	count := (limits.Bytes + BodyChunkBytes - 1) / BodyChunkBytes
	// Capacity metadata, one reader and streaming hash scratch are reserved up
	// front. Fixed data buffers are charged before allocation, including slack.
	base := int64(128<<10) + count*64 + int64(len(tenant))*2
	if base > limits.MemoryBytes {
		return nil, ErrBodyStageLimit
	}
	return &BodyStage{ctx: ctx, tenant: strings.Clone(tenant), limits: limits, chunks: make([][]byte, 0, int(count)), allocated: base, state: "writing"}, nil
}

func (s *BodyStage) fail(err error) error {
	if s.err == nil {
		s.err = err
	}
	return s.err
}

func (s *BodyStage) Write(value []byte) (int, error) {
	if s == nil {
		return 0, ErrBodyStageState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return 0, s.err
	}
	if s.state != "writing" {
		return 0, s.fail(ErrBodyStageState)
	}
	if err := s.ctx.Err(); err != nil {
		return 0, s.fail(err)
	}
	if int64(len(value)) > s.limits.Bytes-s.size {
		return 0, s.fail(ErrBodyStageLimit)
	}
	end := s.size + int64(len(value))
	needed := (end + BodyChunkBytes - 1) / BodyChunkBytes
	allocation := (needed - int64(len(s.chunks))) * BodyChunkBytes
	if allocation > s.limits.MemoryBytes-s.allocated {
		return 0, s.fail(ErrBodyStageLimit)
	}
	for int64(len(s.chunks)) < needed {
		s.allocated += BodyChunkBytes
		s.chunks = append(s.chunks, make([]byte, BodyChunkBytes))
	}
	for offset := 0; offset < len(value); {
		index, inside := int(s.size/BodyChunkBytes), int(s.size%BodyChunkBytes)
		copied := copy(s.chunks[index][inside:], value[offset:])
		s.size += int64(copied)
		offset += copied
	}
	return len(value), nil
}

func (s *BodyStage) Seal() (BodyStageReceipt, error) {
	if s == nil {
		return BodyStageReceipt{}, ErrBodyStageState
	}
	s.mu.Lock()
	if s.err != nil || s.state != "writing" || s.size == 0 {
		err := s.err
		if err == nil {
			err = s.fail(ErrBodyStageState)
		}
		s.mu.Unlock()
		return BodyStageReceipt{}, err
	}
	s.state = "sealing"
	s.mu.Unlock()
	digest, err := crypto.HashReader(&bodyStageReader{stage: s, ctx: s.ctx, sealing: true})
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		return BodyStageReceipt{}, s.fail(err)
	}
	if s.state != "sealing" {
		return BodyStageReceipt{}, ErrBodyStageState
	}
	if err := s.ctx.Err(); err != nil {
		return BodyStageReceipt{}, s.fail(err)
	}
	if len(digest) != 32 {
		return BodyStageReceipt{}, s.fail(ErrBodyStageState)
	}
	s.receipt = BodyStageReceipt{Bytes: s.size, AllocatedBytes: s.allocated, SHA256: hex.EncodeToString(digest)}
	s.state = "ready"
	return s.receipt, nil
}

// Open permits one active reader, so callers cannot allocate an unbounded set
// of staging cursors. A closed reader may be replaced for a validation pass.
func (s *BodyStage) Open(ctx context.Context) (io.ReadCloser, error) {
	if s == nil {
		return nil, ErrBodyStageState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != s.tenant {
		return nil, ErrBodyStageScope
	}
	if s.state != "ready" || s.err != nil || s.reading {
		return nil, ErrBodyStageState
	}
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.reading = true
	return &bodyStageReader{stage: s, ctx: ctx}, nil
}

func (s *BodyStage) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, chunk := range s.chunks {
		crypto.Zeroize(chunk)
	}
	s.chunks, s.receipt, s.allocated, s.size = nil, BodyStageReceipt{}, 0, 0
	s.state = "closed"
	return nil
}

// StageBody exposes a body only when rendering and sealing both succeed. The
// callback must propagate its renderer's receipt/error and source failures.
func StageBody(ctx context.Context, tenant string, limits BodyStageLimits, render func(io.Writer) error) (*BodyStage, BodyStageReceipt, error) {
	if render == nil {
		return nil, BodyStageReceipt{}, ErrBodyStageState
	}
	stage, err := NewBodyStage(ctx, tenant, limits)
	if err != nil {
		return nil, BodyStageReceipt{}, err
	}
	if err := render(stage); err != nil {
		_ = stage.Close()
		return nil, BodyStageReceipt{}, err
	}
	receipt, err := stage.Seal()
	if err != nil {
		_ = stage.Close()
		return nil, BodyStageReceipt{}, err
	}
	return stage, receipt, nil
}

type bodyStageReader struct {
	stage   *BodyStage
	ctx     context.Context
	offset  int64
	closed  bool
	sealing bool
}

func (r *bodyStageReader) Read(target []byte) (int, error) {
	s := r.stage
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.closed || s.err != nil || s.state != "ready" && !(r.sealing && s.state == "sealing") {
		return 0, ErrBodyStageState
	}
	if err := s.ctx.Err(); err != nil {
		return 0, err
	}
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(target) == 0 {
		return 0, nil
	}
	if r.offset == s.size {
		return 0, io.EOF
	}
	index, inside := int(r.offset/BodyChunkBytes), int(r.offset%BodyChunkBytes)
	available := min(int64(BodyChunkBytes-inside), s.size-r.offset)
	count := copy(target, s.chunks[index][inside:inside+int(available)])
	r.offset += int64(count)
	return count, nil
}

func (r *bodyStageReader) Close() error {
	r.stage.mu.Lock()
	defer r.stage.mu.Unlock()
	if !r.closed && !r.sealing {
		r.stage.reading = false
	}
	r.closed = true
	return nil
}
