// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import "errors"

// StdioLimits bounds internal work per modern stream, independently of tool
// query reach. Only the operator can set these values at construction.
type StdioLimits struct {
	Workers int
	Queued  int
}

// DefaultStdioLimits permits cancellation while two requests execute and eight
// wait. A full queue refuses new requests without blocking the input reader.
func DefaultStdioLimits() StdioLimits { return StdioLimits{Workers: 2, Queued: 8} }

func (b StdioLimits) Validate() error {
	// One output channel has two 40-byte entries per worker; WaitGroup also tracks
	// one writer. The control queue stores 24-byte slice headers on 64-bit
	// hosts (this conservative divisor is safe on 32-bit hosts as well).
	// Capacity is operator policy, bounded here only by representation.
	maxInt := int(^uint(0) >> 1)
	if b.Workers < 1 || b.Workers > min(maxInt/80, 1<<31-2) || b.Queued < 1 || b.Queued > maxInt/24 {
		return errors.New("mcp: stdio workers and queued requests must be positive and counter/channel-size safe")
	}
	return nil
}

// WithStdioLimits copies deployment policy; invalid values refuse the transport
// before reading any input or resolving credentials.
func WithStdioLimits(b StdioLimits) Option { return func(s *Server) { s.stdioLimits = b } }
