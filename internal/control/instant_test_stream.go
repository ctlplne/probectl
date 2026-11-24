// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
)

func (s *Server) handleGetInstantTestRun(w http.ResponseWriter, r *http.Request) error {
	view, err := s.readInstantRun(r.Context(), auth.PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, view)
	return nil
}

func (s *Server) handleStreamInstantTestRun(w http.ResponseWriter, r *http.Request) error {
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.TenantID == "" || s.fairnessGate == nil {
		return apierror.Unavailable("instant test streaming is unavailable")
	}
	release, err := s.fairnessGate.BeginQuery(r.Context(), actor.TenantID)
	if err != nil {
		return apierror.RateLimited("too many active result streams")
	}
	defer release()
	view, err := s.readInstantRun(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	extendWriteDeadline(w, 18*time.Second)
	controller := http.NewResponseController(w)
	if _, err := fmt.Fprint(w, ": ready\n\n"); err != nil {
		return nil
	}
	if err := controller.Flush(); err != nil {
		return nil
	}
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	cursor := r.Header.Get("Last-Event-ID")
	for {
		payload, err := json.Marshal(view)
		if err != nil {
			return nil
		}
		version := hex.EncodeToString(crypto.Hash(payload))
		if version != cursor {
			if _, err := fmt.Fprintf(w, "id: %s\nevent: run\ndata: %s\n\n", version, payload); err != nil {
				return nil
			}
			if err := controller.Flush(); err != nil {
				return nil
			}
			cursor = version
		}
		terminal := true
		for _, agent := range view.Agents {
			if agent.State == "queued" || agent.State == "leased" {
				terminal = false
				break
			}
		}
		if terminal {
			return nil
		}
		select {
		case <-r.Context().Done():
			return nil
		case <-timer.C:
			return nil
		case <-ticker.C:
		}
		current := s.resolvePrincipal(r)
		if current == nil || current.TenantID != actor.TenantID || current.UserID != actor.UserID {
			return nil
		}
		view, err = s.readInstantRun(r.Context(), current, view.ID)
		if err != nil {
			return nil
		}
	}
}
