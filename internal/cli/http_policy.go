// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

type cliHTTPPolicy struct {
	requestTimeout, downloadTimeout time.Duration
	responseBytes                   int64
}

// Raw flag/environment values are resolved only before network IO. Offline
// help and version remain usable with an unavailable server or bad config.
func (c Config) httpPolicy() (cliHTTPPolicy, error) {
	p := cliHTTPPolicy{downloadTimeout: downloadTimeout, responseBytes: maxBufferedResponseBody}
	for _, value := range []struct {
		raw, key string
		target   *time.Duration
	}{
		{c.RequestTimeout, "PROBECTL_CLI_REQUEST_TIMEOUT/--request-timeout", &p.requestTimeout},
		{c.DownloadTimeout, "PROBECTL_CLI_DOWNLOAD_TIMEOUT/--download-timeout", &p.downloadTimeout},
	} {
		if value.raw == "" {
			continue
		}
		duration, err := time.ParseDuration(value.raw)
		if err != nil || duration <= 0 {
			return cliHTTPPolicy{}, fmt.Errorf("%s must be a positive finite duration", value.key)
		}
		*value.target = duration
	}
	if c.MaxResponseBytes != "" {
		bytes, err := strconv.ParseInt(c.MaxResponseBytes, 10, 64)
		if err != nil || bytes <= 0 || bytes >= int64(^uint(0)>>1) {
			return cliHTTPPolicy{}, errors.New("PROBECTL_CLI_MAX_RESPONSE_BYTES/--max-response-bytes must be a positive sentinel-safe byte count")
		}
		p.responseBytes = bytes
	}
	return p, nil
}

func (p cliHTTPPolicy) requestBudget(method, path string) time.Duration {
	if p.requestTimeout > 0 {
		return p.requestTimeout
	}
	return requestBudget(method, path)
}
