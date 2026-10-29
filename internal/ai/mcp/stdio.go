// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/ctlplne/probectl/internal/auth"
)

// ServeStdio runs the MCP server over a newline-delimited JSON-RPC stream — the
// stdio transport, used by local clients (e.g. Claude Desktop spawns the binary).
// This entry point is for trusted in-process callers supplying a fixed
// principal. Credential-bearing commands use ServeAuthenticatedStdio so token,
// user, lifecycle and permission changes are checked on every input frame.
// It returns when input reaches EOF or cancellation is observed.
//
// Note: logs MUST go to stderr in this mode — stdout is the JSON-RPC channel.
func (s *Server) ServeStdio(ctx context.Context, r io.Reader, w io.Writer, p *auth.Principal, refresh ...func(context.Context) (*auth.Principal, error)) error {
	if len(refresh) == 0 {
		return s.serveStdio(ctx, r, w, p, nil)
	}
	if len(refresh) != 1 || refresh[0] == nil || p == nil || p.TenantID == "" || p.UserID == "" {
		return errors.New("authenticated stdio requires tenant/user and credential refresh")
	}
	return s.serveStdio(ctx, r, w, p, refresh[0])
}

// ServeAuthenticatedStdio rechecks the credential on every input frame and
// binds the stream to its original tenant/user. Refresh is a trusted transport
// closure over the credential, never client-supplied principal metadata.
func (s *Server) ServeAuthenticatedStdio(ctx context.Context, r io.Reader, w io.Writer, p *auth.Principal, refresh func(context.Context) (*auth.Principal, error)) error {
	if refresh == nil || p == nil || p.TenantID == "" || p.UserID == "" {
		return errors.New("authenticated stdio requires tenant/user and credential refresh")
	}
	return s.ServeStdio(ctx, r, w, p, refresh)
}
func (s *Server) serveStdio(ctx context.Context, r io.Reader, w io.Writer, initial *auth.Principal, refresh func(context.Context) (*auth.Principal, error)) error {
	tenant, user := "", ""
	if initial != nil {
		tenant, user = initial.TenantID, initial.UserID
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		principal := initial
		var resp []byte
		if refresh != nil {
			current, err := refresh(ctx)
			if err != nil || current == nil || current.TenantID != tenant || current.UserID != user {
				// Preserve only a valid bounded request ID; failed authentication cannot
				// publish discovery or tool data and never falls back to old grants.
				var req rpcRequest
				switch {
				case json.Unmarshal(line, &req) != nil:
					resp = marshal(errorResponse(nil, codeParse, "parse error"))
				case len(req.ID) > maxMCPRequestIDBytes:
					resp = marshal(errorResponse(nil, codeInvalidRequest, "request id exceeds size limit"))
				case len(req.ID) > 0:
					code, message := codeUnauthorized, "credential is invalid or no longer authorized"
					if errors.Is(err, ErrForbidden) {
						code, message = codeForbidden, "credential is forbidden by current policy"
					}
					resp = marshal(errorResponse(req.ID, code, message))
				}
				if resp != nil {
					if _, err := w.Write(append(resp, '\n')); err != nil {
						return err
					}
				}
				continue
			}
			principal = current
		}
		resp = s.Handle(ctx, principal, line)
		if resp == nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := w.Write(append(resp, '\n')); err != nil {
			return err
		}
	}
	return scanner.Err()
}
