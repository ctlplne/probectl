// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
)

func (s *Server) readNativeInstantTestStatus(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (json.RawMessage, error) {
	var args struct {
		RunID string `json:"run_id"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&args) != nil || d.Decode(new(any)) != io.EOF || !canonicalInstantResource(args.RunID) {
		return nil, apierror.Validation("a single instant test run ID is required")
	}
	if err := mcp.CheckOriginatingCredential(ctx); err != nil {
		return nil, err
	}
	view, err := s.readInstantRun(ctx, actor, args.RunID)
	if err != nil {
		return nil, err
	}
	if err := mcp.CheckOriginatingCredential(ctx); err != nil {
		return nil, err
	}
	// Scope checks precede the typed identifier projection for the redactor.
	type agentView struct {
		ID     mcp.NativeRoleUUID `json:"agent_id"`
		State  string             `json:"state"`
		Result json.RawMessage    `json:"result,omitempty"`
	}
	out := struct {
		ID            mcp.NativeRoleUUID `json:"id"`
		TestID        mcp.NativeRoleUUID `json:"test_id"`
		CreatedAt     time.Time          `json:"created_at"`
		DispatchUntil time.Time          `json:"dispatch_until"`
		Agents        []agentView        `json:"agents"`
	}{
		ID: mcp.NativeRoleUUID(view.ID), TestID: mcp.NativeRoleUUID(view.TestID),
		CreatedAt: view.CreatedAt, DispatchUntil: view.DispatchUntil, Agents: make([]agentView, 0, len(view.Agents)),
	}
	for _, agent := range view.Agents {
		out.Agents = append(out.Agents, agentView{mcp.NativeRoleUUID(agent.AgentID), agent.State, agent.Result})
	}
	return json.Marshal(out)
}
