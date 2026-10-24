// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"github.com/ctlplne/probectl/internal/ebpf/l7"
	"github.com/ctlplne/probectl/internal/l7redact"
)

// minimizeCall applies the shared D-43 persistence rule (l7redact.Minimize, the
// same function the control-plane ingest strip runs) to one parsed call, before
// it is rolled up or published. Under "metadata" only method, the templated
// route, status, latency, byte counts and protocol survive; under every mode a
// query string never does.
func minimizeCall(c l7.Call, mode string) l7.Call {
	m, _ := l7redact.Minimize(l7redact.Call{
		Protocol: c.Protocol, Method: c.Method, Resource: c.Resource, Status: c.Status,
	}, mode)
	c.Protocol, c.Method, c.Resource, c.Status = m.Protocol, m.Method, m.Resource, m.Status
	return c
}

// captureHeaderPolicy is the deployment's header-value policy for the capture
// boundary, shared by the live source and the fixture replay.
func captureHeaderPolicy(cfg *Config) headerValuePolicy {
	return headerValuePolicy{
		identityFragments: cfg.L7CaptureIdentityHeaderFragments,
		hashAllValues:     cfg.L7CaptureHashAllHeaderValues,
	}
}

// applyBoundary runs every recorded payload through the same capture boundary a
// live chunk crosses (the per-stream redactor, DPR-340), so a fixture replay
// exercises the redaction mode exactly as live capture would. The recording is
// not live capture and stays exempt from the consent gate; it is not exempt from
// redaction.
func (s *FixtureL7Source) applyBoundary(mode string, policy headerValuePolicy) {
	streams := newStreamRedactor()
	for i := range s.events {
		e := &s.events[i]
		key := streamKey{conn: e.ConnID, read: e.Data.Kind == l7.Response}
		if e.Data.Size == 0 {
			e.Data.Size = len(e.Data.Payload)
		}
		e.Data.Payload = streams.redact(key, append([]byte(nil), e.Data.Payload...), mode, policy)
	}
}
