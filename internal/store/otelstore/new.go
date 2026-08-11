// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
