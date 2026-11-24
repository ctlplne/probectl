// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package completeness

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
)

// The SSE path uses the authenticated client and streams only a verified
// event-stream response. Require the command and transport, including the
// shared identity writer, before accepting the CLI delivery claim.
func (v *Validator) validateInstantTestEventsSpine() error {
	sources := []struct {
		path   string
		bodies map[string]string
	}{
		{"internal/cli/instant_test_events.go", map[string]string{"testRunEvents": instantTestEventsCommandSpine, "readInstantTestEvents": instantTestEventsReadSpine}},
		{"internal/cli/cli.go", map[string]string{"setRequestIdentity": instantTestEventsIdentitySpine}},
	}
	for _, source := range sources {
		path, err := v.resolveWithinRoot(source.path)
		if err != nil {
			return fmt.Errorf("parse CLI instant test events: %w", err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return fmt.Errorf("parse CLI instant test events: %w", err)
		}
		seen := make(map[string]bool, len(source.bodies))
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			name := fn.Name.Name
			body, tracked := source.bodies[name]
			if !tracked {
				continue
			}
			if seen[name] || fn.Body == nil || !instantTestEventsReceiverMatches(fn) || !cliBodyMatches(fn.Body, body) {
				return fmt.Errorf("parse CLI instant test events: %s must preserve its authenticated request spine", name)
			}
			seen[name] = true
		}
		if len(seen) != len(source.bodies) {
			return fmt.Errorf("parse CLI instant test events: %s is missing the trusted command or client method", source.path)
		}
	}
	return nil
}

func instantTestEventsReceiverMatches(fn *ast.FuncDecl) bool {
	if fn.Name.Name == "testRunEvents" {
		return fn.Recv == nil
	}
	if fn.Recv == nil || len(fn.Recv.List) != 1 {
		return false
	}
	receiver := fn.Recv.List[0]
	pointer, ok := receiver.Type.(*ast.StarExpr)
	return ok && isIdentifier(pointer.X, "client") && len(receiver.Names) == 1 && receiver.Names[0].Name == "c"
}

const instantTestEventsDispatchSpine = `{
	return testRunEvents(c, args[1:], stdout, stderr)
}`

const instantTestEventsCommandSpine = `{
	if wantsHelp(args) {
		fmt.Fprintln(stdout, "Usage: probectl test run-events <id> [--last-event-id <cursor>]")
		return 0
	}
	if len(args) == 0 {
		fmt.Fprintln(stderr, "test run-events: missing <id>")
		return 2
	}
	fs := flag.NewFlagSet("test run-events", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cursor := fs.String("last-event-id", "", "resume after this event ID")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return 2
	}
	if *cursor != "" {
		raw, err := hex.DecodeString(*cursor)
		if err != nil || len(raw) != 32 {
			fmt.Fprintln(stderr, "test run-events: invalid event ID")
			return 2
		}
	}
	path := "/v1/test-runs/" + url.PathEscape(args[0]) + "/events"
	if err := c.readInstantTestEvents(path, *cursor, stdout); err != nil {
		return fail(stderr, err)
	}
	return 0
}`

const instantTestEventsReadSpine = `{
	target, err := resolveAPIURL(c.cfg.BaseURL, path)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, target.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	if cursor != "" {
		req.Header.Set("Last-Event-ID", cursor)
	}
	c.setRequestIdentity(req)
	hc := c.requestHTTPClient(target, false)
	hc.Timeout = 20 * time.Second
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, readErr := readBufferedResponse(resp, maxBufferedErrorResponseBody)
		if readErr != nil {
			return readErr
		}
		if ok, apiErr := formatAPIError(data, c.cfg.Locale); ok {
			return apiErr
		}
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "text/event-stream" {
		return fmt.Errorf("expected a test run event stream")
	}
	_, err = io.Copy(stdout, resp.Body)
	return err
}`

const instantTestEventsIdentitySpine = `{
	if c.cfg.SessionCookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: c.cfg.SessionCookie})
	} else if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	if c.cfg.Tenant != "" {
		req.Header.Set("X-Probectl-Tenant", c.cfg.Tenant)
	}
}`
