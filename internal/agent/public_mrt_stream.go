// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

// PublicMRTOptions admits one complete original record at a time. There is no
// file-row or file-byte ceiling: persistent source state remains tenant-budgeted
// at the control plane. Transport policy must admit the whole protobuf frame.
type PublicMRTOptions struct {
	ConfiguredRef                       string
	RecordBytes, MemoryBytes, WorkUnits int64
	RPCTimeout, RetryDelay              time.Duration
	RetryAttempts                       int
}

func DefaultPublicMRTOptions(configuredRef string) PublicMRTOptions {
	return PublicMRTOptions{ConfiguredRef: configuredRef, RecordBytes: (4 << 20) - 4096, MemoryBytes: 512 << 20, WorkUnits: 2 << 30, RPCTimeout: 30 * time.Second, RetryDelay: 250 * time.Millisecond, RetryAttempts: 2}
}

type PublicMRTImport struct {
	SnapshotID     string
	Records, Bytes int64
}

// ImportPublicMRT streams original TABLE_DUMP_V2 bytes. A clean whole-reader
// EOF alone publishes the source; decompression/checksum errors, unknown or
// replaced peer tables, partial records and failed RPCs retire this attempt.
// A retry keeps the exact nonce, sequence, capture clock and original bytes.
func (c *EvidenceClient) ImportPublicMRT(ctx context.Context, reader io.Reader, options PublicMRTOptions) (out PublicMRTImport, err error) {
	if c == nil || reader == nil || options.ConfiguredRef == "" || options.RecordBytes < 12 || options.RecordBytes > math.MaxInt32-4096 || options.MemoryBytes <= 4096 || options.WorkUnits <= 4096 || options.RPCTimeout <= 0 || options.RetryAttempts <= 0 || options.RetryDelay < 0 {
		return out, ErrEvidenceBatchInvalid
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	out.SnapshotID, err = crypto.UUIDv4()
	if err != nil {
		return out, err
	}
	sequence := int64(1)
	reset := func() error {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), options.RPCTimeout)
		defer cancel()
		_, resetErr := c.SubmitPublicRoutingMessage(cleanup, &agentv1.PublicRoutingMessage{ConfiguredRef: options.ConfiguredRef, SnapshotId: out.SnapshotID, Sequence: sequence, ObservedUnixNanos: time.Now().UnixNano(), SourceReset: true})
		return resetErr
	}
	first, readErr := readPublicMRTRecord(ctx, reader, options.RecordBytes)
	stage := &agentv1.PublicRoutingPeerTable{ConfiguredRef: options.ConfiguredRef, ObservationId: out.SnapshotID, ObservedUnixNanos: time.Now().UnixNano(), SourceRecord: first}
	receipt, stageErr := publicMRTRetry(ctx, options, func(call context.Context) (*agentv1.PublicRoutingStagingReceipt, error) {
		return c.StagePublicRoutingSource(call, stage)
	})
	if stageErr != nil {
		// A known-source refusal already committed retirement. An ambiguous
		// lost stage receipt still needs an explicit attempt reset.
		if receipt == nil || receipt.Status != "invalidated" {
			stageErr = errors.Join(stageErr, reset())
		}
		return out, errors.Join(readErr, stageErr)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, reset())
		}
	}()
	if readErr != nil {
		return out, readErr
	}
	budget := bgp.UpdateFrameBudget{MemoryBytes: options.MemoryBytes, WorkUnits: options.WorkUnits}
	peers, err := bgp.DecodeMRTPeerIndex(ctx, first, budget)
	if err != nil {
		return out, err
	}
	out.Records, out.Bytes = 1, int64(len(first))
	for {
		raw, readErr := readPublicMRTRecord(ctx, reader, options.RecordBytes)
		complete := errors.Is(readErr, io.EOF) && len(raw) == 0
		if readErr != nil && !complete {
			return out, readErr
		}
		if !complete {
			if _, err := bgp.DecodeMRTRIB(ctx, raw, len(peers.Peers), budget); err != nil {
				return out, err
			}
		}
		message := &agentv1.PublicRoutingMessage{ConfiguredRef: options.ConfiguredRef, SnapshotId: out.SnapshotID, Sequence: sequence, ObservedUnixNanos: time.Now().UnixNano(), Record: raw, Complete: complete}
		if _, err := publicMRTRetry(ctx, options, func(call context.Context) (*agentv1.PublicRoutingMessageReceipt, error) {
			return c.SubmitPublicRoutingMessage(call, message)
		}); err != nil {
			return out, err
		}
		if complete {
			return out, nil
		}
		if out.Bytes > math.MaxInt64-int64(len(raw)) || sequence >= math.MaxInt64-2 {
			return out, ErrEvidenceBatchInvalid
		}
		out.Records++
		out.Bytes += int64(len(raw))
		sequence++
	}
}

func readPublicMRTRecord(ctx context.Context, reader io.Reader, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	header := make([]byte, 12)
	n, err := io.ReadFull(reader, header)
	if err != nil {
		return header[:n], err
	}
	size := int64(binary.BigEndian.Uint32(header[8:12])) + 12
	if size > limit {
		return header, bgp.ErrMRTBudget
	}
	raw := make([]byte, int(size))
	copy(raw, header)
	n, err = io.ReadFull(reader, raw[12:])
	return raw[:12+n], err
}

func publicMRTRetry[T any](ctx context.Context, options PublicMRTOptions, call func(context.Context) (T, error)) (T, error) {
	var response T
	var err error
	for attempt := 0; attempt < options.RetryAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return response, err
		}
		callCtx, cancel := context.WithTimeout(ctx, options.RPCTimeout)
		response, err = call(callCtx)
		cancel()
		if err == nil || status.Code(err) != codes.Unavailable && status.Code(err) != codes.DeadlineExceeded || attempt == options.RetryAttempts-1 {
			return response, err
		}
		timer := time.NewTimer(options.RetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return response, ctx.Err()
		case <-timer.C:
		}
	}
	return response, err
}
