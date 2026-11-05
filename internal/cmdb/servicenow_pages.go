// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cmdb

import (
	"mime"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// Link URLs may contain literal commas. Only commas outside angle brackets and
// quoted parameters separate links; no parsed URL is used for a request.
func serviceNowNextLink(headers []string) (string, error) {
	next := ""
	for _, header := range headers {
		for remaining := strings.TrimSpace(header); remaining != ""; {
			if remaining[0] != '<' {
				return "", ErrLookupIncomplete
			}
			end := strings.IndexByte(remaining, '>')
			if end < 1 {
				return "", ErrLookupIncomplete
			}
			target, rest := remaining[1:end], remaining[end+1:]
			cut := len(rest)
			quoted, escaped := false, false
			for i := range rest {
				if escaped {
					escaped = false
					continue
				}
				if quoted && rest[i] == '\\' {
					escaped = true
					continue
				}
				if rest[i] == '"' {
					quoted = !quoted
				} else if !quoted && rest[i] == ',' {
					cut = i
					break
				}
			}
			if quoted || escaped {
				return "", ErrLookupIncomplete
			}
			_, parameters, err := mime.ParseMediaType("application/link" + rest[:cut])
			if err != nil {
				return "", ErrLookupIncomplete
			}
			if slices.Contains(strings.Fields(strings.ToLower(parameters["rel"])), "next") {
				if next != "" || target == "" {
					return "", ErrLookupIncomplete
				}
				next = target
			}
			remaining = ""
			if cut < len(rest) {
				remaining = strings.TrimSpace(rest[cut+1:])
				if remaining == "" {
					return "", ErrLookupIncomplete
				}
			}
		}
	}
	return next, nil
}

func serviceNowNextOffset(endpoint string, original url.Values, raw string) (int64, error) {
	base, err := url.Parse(endpoint)
	if err != nil {
		return 0, ErrLookupIncomplete
	}
	next, err := url.Parse(raw)
	if err != nil || raw == "" || next.User != nil || next.Fragment != "" {
		return 0, ErrLookupIncomplete
	}
	next = base.ResolveReference(next)
	if next.Scheme != base.Scheme || next.Host != base.Host || next.Path != base.Path {
		return 0, ErrLookupIncomplete
	}
	values, err := url.ParseQuery(next.RawQuery)
	if err != nil || len(values["sysparm_offset"]) != 1 || len(values["sysparm_limit"]) != 1 {
		return 0, ErrLookupIncomplete
	}
	offset, err := strconv.ParseInt(values.Get("sysparm_offset"), 10, 64)
	if err != nil || offset < 0 {
		return 0, ErrLookupIncomplete
	}
	limit, err := strconv.ParseInt(values.Get("sysparm_limit"), 10, 64)
	if err != nil || limit <= 0 {
		return 0, ErrLookupIncomplete
	}
	for key, value := range values {
		if key == "sysparm_offset" || key == "sysparm_limit" {
			continue
		}
		if !slices.Equal(value, original[key]) {
			return 0, ErrLookupIncomplete
		}
	}
	return offset, nil
}
