// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package sdk

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/ctlplne/probectl/pkg/transport"
)

// DownloadDashboardReportArtifactTo streams a complete artifact without the
// buffered JSON/byte-call allowance. maximum is explicit finite output
// admission, not a truncation option. The caller owns staging and must discard
// its output on any error, including cancellation or an oversized response.
func (c *Client) DownloadDashboardReportArtifactTo(ctx context.Context, input DownloadDashboardReportArtifactRequest, target io.Writer, maximum int64) (int64, error) {
	if c == nil || target == nil || input.Id == "" || maximum <= 0 || maximum == int64(^uint64(0)>>1) {
		return 0, errors.New("probectl SDK: complete artifact identity, output and positive sentinel-safe admission are required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/dashboard-report-artifacts/"+url.PathEscape(input.Id), nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Accept", "application/octet-stream")
	if c.UserAgent != "" {
		request.Header.Set("User-Agent", c.UserAgent)
	}
	if c.Token != "" {
		request.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if c.Tenant != "" {
		request.Header.Set("X-Probectl-Tenant", c.Tenant)
	}
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		body, err := transport.ReadLimited(response.Body, MaxErrorResponseBodyBytes)
		if err != nil {
			return 0, err
		}
		return 0, decodeError(response.StatusCode, body)
	}
	if response.ContentLength > maximum {
		return 0, transport.ErrTooLarge
	}
	written, err := io.Copy(target, io.LimitReader(response.Body, maximum))
	if err != nil {
		return written, err
	}
	var sentinel [1]byte
	count, err := io.ReadFull(response.Body, sentinel[:])
	if count != 0 {
		return written, transport.ErrTooLarge
	}
	if err != io.EOF {
		if err == nil {
			err = io.ErrNoProgress
		}
		return written, err
	}
	if written == 0 || response.ContentLength >= 0 && response.ContentLength != written {
		return written, io.ErrUnexpectedEOF
	}
	return written, ctx.Err()
}
