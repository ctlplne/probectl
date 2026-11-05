// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cmdb

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strconv"
)

// Page size controls request granularity, never the complete lookup cardinality.
const cmdbPageSize = 100

func readNetBoxPages[T any](ctx context.Context, n *NetBox, path string, query url.Values, output *[]T) error {
	query.Set("limit", strconv.Itoa(cmdbPageSize))
	query.Set("ordering", "id")
	var rows []T
	var offset, lastID int64
	total := int64(-1)
	for {
		query.Set("offset", strconv.FormatInt(offset, 10))
		var page struct {
			Count   *int64            `json:"count"`
			Next    string            `json:"next"`
			Results []json.RawMessage `json:"results"`
		}
		if err := n.get(ctx, path+"?"+query.Encode(), &page); err != nil {
			return err
		}
		if page.Count == nil || *page.Count < 0 || page.Results == nil || (total >= 0 && *page.Count != total) {
			return ErrTenantBinding
		}
		total = *page.Count
		if int64(len(page.Results)) > total-offset || (len(page.Results) == 0 && offset < total) {
			return ErrTenantBinding
		}
		for _, raw := range page.Results {
			var identity struct {
				ID int64 `json:"id"`
			}
			if json.Unmarshal(raw, &identity) != nil || identity.ID <= lastID {
				return ErrTenantBinding
			}
			lastID = identity.ID
			if err := lookupMemory(ctx, n, 2048); err != nil {
				return err
			}
			var row T
			if json.Unmarshal(raw, &row) != nil {
				return ErrTenantBinding
			}
			rows = append(rows, row)
		}
		offset += int64(len(page.Results))
		if offset == total {
			if page.Next != "" {
				return ErrTenantBinding
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			*output = rows
			return nil
		}
		if !netBoxNextPage(n.base+path, query, page.Next, offset) {
			return ErrTenantBinding
		}
	}
}

// Next is only checked as source metadata. Every request is reconstructed from
// the fixed endpoint, original tenant/key filters and locally counted offset.
// It can never redirect the integration credential to a source-provided URL.
func netBoxNextPage(endpoint string, query url.Values, raw string, offset int64) bool {
	base, err := url.Parse(endpoint)
	if err != nil || raw == "" {
		return false
	}
	next, err := url.Parse(raw)
	if err != nil || next.User != nil || next.Fragment != "" {
		return false
	}
	next = base.ResolveReference(next)
	if next.Scheme != base.Scheme || next.Host != base.Host || next.Path != base.Path {
		return false
	}
	values, err := url.ParseQuery(next.RawQuery)
	if err != nil || len(values["offset"]) != 1 || len(values["limit"]) != 1 || values.Get("offset") != strconv.FormatInt(offset, 10) {
		return false
	}
	limit, err := strconv.ParseInt(values.Get("limit"), 10, 64)
	if err != nil || limit <= 0 {
		return false
	}
	for key, original := range query {
		if key != "offset" && key != "limit" && !slices.Equal(values[key], original) {
			return false
		}
	}
	for key := range values {
		if _, present := query[key]; !present {
			return false
		}
	}
	return true
}
