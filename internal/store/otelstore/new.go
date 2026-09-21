// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package otelstore

import (
	"errors"
	"fmt"
	"net/http"
)

// NewWithClient selects the Store backend with an optional hardened ClickHouse
// HTTP client: "" or "memory" for the in-process store (lightweight mode), or
// "clickhouse" for production.
func NewWithClient(mode, url string, retentionDays int, client *http.Client) (Store, error) {
	switch mode {
	case "", "memory":
		return NewMemory(), nil
	case "clickhouse":
		if url == "" {
			return nil, errors.New("otelstore: clickhouse mode requires PROBECTL_OTELSTORE_URL")
		}
		return NewClickHouseWithClient(url, retentionDays, client)
	default:
		return nil, fmt.Errorf("otelstore: unknown mode %q (want memory|clickhouse)", mode)
	}
}
