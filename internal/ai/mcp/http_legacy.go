// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"net/http"

	"github.com/ctlplne/probectl/internal/auth"
)

// Legacy HTTP uses temporary per-request context and no server sessions. Only
// live work is tracked for best-effort cancellation on the handling process.
func (s *Server) serveLegacyHTTP(w http.ResponseWriter, r *http.Request, authn Authenticator, p *auth.Principal, bearer string, raw []byte, req rpcRequest) {
	if notification, key := stdioNotification(raw); notification {
		if key != "" {
			s.legacyHTTP.cancelRequest(p, bearer, key)
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	job, failure := s.legacyHTTP.begin(r.Context(), p, bearer, req, s.httpWorkBudget)
	if failure != nil {
		w.Header().Set("Content-Type", "application/json")
		status := http.StatusBadRequest
		if failure.Error.Code == codeRateLimited {
			status = http.StatusTooManyRequests
			w.Header().Set("Retry-After", "1")
		}
		w.WriteHeader(status)
		_, _ = w.Write(marshal(s.prepareResponse(req, failure)))
		return
	}
	defer job.finish()
	if deadline, ok := job.ctx.Deadline(); ok {
		_ = http.NewResponseController(w).SetWriteDeadline(deadline.Add(httpResponseCloseGrace))
	}
	p = principalSnapshot(p)
	ctx := withPublicationGuard(job.ctx, func(ctx context.Context) error {
		current, err := authn.Authenticate(ctx, bearer)
		if err != nil || !sameAuthority(p, current) {
			return ErrForbidden
		}
		return ctx.Err()
	})
	streaming, disconnected := req.Method == "tools/call", false
	if streaming {
		req.protocol.frameReserve = 8
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		disconnected = http.NewResponseController(w).Flush() != nil
	}
	if streaming && len(req.protocol.progress) > 0 {
		ctx = withProgressEmitter(ctx, func(stage int) error {
			if !job.commit(false) {
				return job.ctx.Err()
			}
			if disconnected || r.Context().Err() != nil {
				return nil // disconnect is not legacy cancellation
			}
			message, err := progressMessage(req.protocol.progress, stage)
			if err != nil {
				return err
			}
			if err := writeSSE(w, message); err != nil {
				disconnected = true
				return nil
			}
			disconnected = http.NewResponseController(w).Flush() != nil
			return nil
		})
	}
	response := s.handleRequest(ctx, p, req, raw)
	if response == nil || disconnected || r.Context().Err() != nil || !job.commit(true) {
		return
	}
	if streaming {
		_ = writeSSE(w, response)
		_ = http.NewResponseController(w).Flush()
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(response)
}
