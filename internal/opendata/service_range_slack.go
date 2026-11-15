// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"

	"golang.org/x/net/html"
)

const slackHuddlesRangeURL = "https://slack.com/help/articles/36284146785427-Guide-to-network-and-system-configuration-for-Slack-huddles"

// Slack publishes Chime media network paths, not an exclusive Slack address
// allocation. Keep this scoped document and its matches as dependency evidence.
func parseSlackHuddlesServiceRanges(ctx context.Context, raw []byte, dataset *serviceRangeDataset, remaining *int64) error {
	tokens := html.NewTokenizer(bytes.NewReader(raw))
	var heading, paths strings.Builder
	var headingTag string
	section, closedBody, closedHTML := false, false, false
	sections, listDepth, ignored := 0, 0, 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		kind := tokens.Next()
		if kind == html.ErrorToken {
			if !errors.Is(tokens.Err(), io.EOF) || !closedBody || !closedHTML || listDepth != 0 || sections != 1 {
				return serviceRangeDecodeError("Slack Huddles complete network document")
			}
			break
		}
		token := tokens.Token()
		switch kind {
		case html.StartTagToken:
			switch token.Data {
			case "script", "style", "template", "noscript":
				ignored++
			}
			if ignored > 0 {
				continue
			}
			if len(token.Data) == 2 && token.Data[0] == 'h' && token.Data[1] >= '1' && token.Data[1] <= '6' {
				if token.Data[1] <= '3' {
					section = false
				}
				headingTag = token.Data
				heading.Reset()
			}
			if section && (token.Data == "ul" || token.Data == "ol") {
				listDepth++
			}
		case html.EndTagToken:
			switch token.Data {
			case "script", "style", "template", "noscript":
				if ignored > 0 {
					ignored--
				}
				continue
			}
			if ignored > 0 {
				continue
			}
			if token.Data == headingTag {
				if strings.Join(strings.Fields(heading.String()), " ") == "Huddles network paths" {
					section = true
					sections++
				}
				headingTag = ""
			}
			if section && (token.Data == "ul" || token.Data == "ol") {
				listDepth--
				if listDepth < 0 {
					return serviceRangeDecodeError("Slack Huddles network list")
				}
			}
			closedBody = closedBody || token.Data == "body"
			closedHTML = closedHTML || token.Data == "html"
		case html.TextToken:
			if ignored > 0 {
				continue
			}
			if headingTag != "" {
				heading.WriteString(token.Data)
			}
			if section && listDepth > 0 {
				paths.WriteByte(' ')
				paths.WriteString(token.Data)
			}
		}
	}
	dataset.status.Version = "sha256:" + dataset.status.Digest
	dataset.status.TermsURL = slackHuddlesRangeURL
	prefixes := 0
	for field := range strings.FieldsSeq(paths.String()) {
		field = strings.Trim(field, ",;()[]")
		if !strings.Contains(field, "/") || strings.HasPrefix(field, "UDP/") || strings.HasPrefix(field, "TCP/") || strings.HasPrefix(field, "https://") {
			continue
		}
		if err := dataset.add(ctx, field, "Slack Huddles network dependency", "", remaining); err != nil {
			return err
		}
		prefixes++
	}
	if prefixes == 0 {
		return serviceRangeDecodeError("Slack Huddles published prefixes")
	}
	return nil
}
