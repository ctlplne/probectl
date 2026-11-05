// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
)

// Stage and verify before writing stdout: a broken/truncated response cannot
// look like a successful CSV, and the generic32MiB JSON cap does not reduce the
// server's50k row reach. Disk IO is bounded by --max-bytes, memory by io.Copy.
func (c *client) downloadFlowCSV(path string, maxBytes int64, output io.Writer) error {
	policy, err := c.cfg.httpPolicy()
	if err != nil {
		return err
	}
	target, err := resolveAPIURL(c.cfg.BaseURL, path)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, target.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/csv")
	if c.cfg.SessionCookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: c.cfg.SessionCookie})
	} else if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	if c.cfg.Tenant != "" {
		req.Header.Set("X-Probectl-Tenant", c.cfg.Tenant)
	}
	hc := c.requestHTTPClient(target, false)
	hc.Timeout = policy.downloadTimeout
	response, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("CSV request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		body, err := readBufferedResponse(response, policy.responseBytes)
		if err != nil {
			return err
		}
		if ok, err := formatAPIError(body, c.cfg.Locale); ok {
			return err
		}
		return fmt.Errorf("CSV response status %d", response.StatusCode)
	}
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "text/csv" || !isDownload(response) {
		return errors.New("CSV export response type is invalid")
	}
	expected, err := hex.DecodeString(response.Header.Get("X-Probectl-SHA256"))
	if err != nil || len(expected) != 32 {
		return errors.New("CSV export digest is missing or invalid")
	}
	if response.ContentLength < 0 || response.ContentLength > maxBytes {
		return errors.New("CSV export exceeds --max-bytes or has no declared length")
	}
	file, err := os.CreateTemp("", "probectl-flow-csv-download-*")
	if err != nil {
		return err
	}
	defer func() { _ = file.Close(); _ = os.Remove(file.Name()) }()
	n, err := io.Copy(file, io.LimitReader(response.Body, maxBytes))
	if err != nil {
		return fmt.Errorf("CSV download incomplete: %w", err)
	}
	if n != response.ContentLength {
		return errors.New("CSV download length mismatch")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	digest, err := crypto.HashReader(file)
	if err != nil {
		return err
	}
	if !crypto.ConstantTimeEqual(digest, expected) {
		return errors.New("CSV download digest mismatch")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err = io.Copy(output, file)
	return err
}
