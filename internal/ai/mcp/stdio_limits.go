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
	if b.Workers < 1 || b.Workers > 10000 || b.Queued < 1 || b.Queued > 10000 {
		return errors.New("mcp: stdio workers and queued requests must each be between 1 and 10000")
	}
	return nil
}

// WithStdioLimits copies deployment policy; invalid values refuse the transport
// before reading any input or resolving credentials.
func WithStdioLimits(b StdioLimits) Option { return func(s *Server) { s.stdioLimits = b } }
