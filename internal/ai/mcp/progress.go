// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"io"
)

type progressContextKey struct{}
type progressEmitter func(int) error

func withProgressEmitter(ctx context.Context, emit progressEmitter) context.Context {
	return context.WithValue(ctx, progressContextKey{}, emit)
}

func reportProgress(ctx context.Context, stage int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if emit, ok := ctx.Value(progressContextKey{}).(progressEmitter); ok {
		return emit(stage)
	}
	return nil
}

// Fixed stages describe service transitions, not fabricated percentages or
// backend data. The caller's bounded correlation token is the only echoed input.
func progressMessage(token json.RawMessage, stage int) ([]byte, error) {
	message := "Processing request"
	if stage == 1 {
		message = "Preparing response"
	}
	return marshalBoundedJSON(map[string]any{"jsonrpc": jsonRPCVersion, "method": "notifications/progress", "params": map[string]any{"progressToken": token, "progress": stage, "message": message}}, maxMCPToolResultBytes, false)
}

// Write framing separately so a large admitted result does not allocate a
// second full-sized copy merely to prepend data: and append its terminator.
func writeSSE(w io.Writer, payload []byte) error {
	for _, part := range [][]byte{[]byte("data: "), payload, []byte("\n\n")} {
		n, err := w.Write(part)
		if err != nil {
			return err
		}
		if n != len(part) {
			return io.ErrShortWrite
		}
	}
	return nil
}
