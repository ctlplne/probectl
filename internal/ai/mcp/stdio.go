package mcp

import (
	"bufio"
	"bytes"
	"context"
	"io"

	"github.com/imfeelingtheagi/probectl/internal/auth"
)

// ServeStdio runs the MCP server over a newline-delimited JSON-RPC stream — the
// stdio transport, used by local clients (e.g. Claude Desktop spawns the binary).
// The principal is resolved once by the caller (the binary authenticates the
// token before calling this), since a stdio session is local and bound to one
// tenant. It returns when the input reaches EOF or the context is canceled.
//
// Note: logs MUST go to stderr in this mode — stdout is the JSON-RPC channel.
func (s *Server) ServeStdio(ctx context.Context, r io.Reader, w io.Writer, p *auth.Principal) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		resp := s.Handle(ctx, p, line)
		if resp == nil {
			continue // a notification — no reply
		}
		if _, err := w.Write(append(resp, '\n')); err != nil {
			return err
		}
	}
	return scanner.Err()
}
