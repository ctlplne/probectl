// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"time"
)

func testRunEvents(c *client, args []string, stdout, stderr io.Writer) int {
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
}

func (c *client) readInstantTestEvents(path, cursor string, stdout io.Writer) error {
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
}
