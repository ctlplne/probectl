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

// The native CSV path uses a staged verified download instead of JSON do().
// Seal that delegate too so a static CLI claim cannot hide a default client,
// wrong origin,unbounded allocation or output released before verification.
func (v *Validator) validateFlowCSVSpine() error {
	path, err := v.resolveWithinRoot("internal/cli/flow_csv_download.go")
	if err != nil {
		return fmt.Errorf("generic CLI dispatcher: verified CSV download source: %w", err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return fmt.Errorf("generic CLI dispatcher: verified CSV download source: %w", err)
	}
	found := 0
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "downloadFlowCSV" {
			continue
		}
		found++
		if fn.Recv == nil || len(fn.Recv.List) != 1 || len(fn.Recv.List[0].Names) != 1 || fn.Recv.List[0].Names[0].Name != "c" || fn.Body == nil {
			return fmt.Errorf("generic CLI dispatcher: verified CSV download must be the authenticated client method")
		}
		pointer, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok || !isIdentifier(pointer.X, "client") || !cliBodyMatches(fn.Body, downloadFlowCSVSpine) {
			return fmt.Errorf("generic CLI dispatcher: verified CSV download must preserve authenticated,bounded,verified-before-output delivery")
		}
	}
	if found != 1 {
		return fmt.Errorf("generic CLI dispatcher: verified CSV download must have one active client method")
	}
	return nil
}

const downloadFlowCSVSpine = `{
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
	hc.Timeout = downloadTimeout
	response, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("CSV request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		body, err := readBufferedResponse(response)
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
	defer func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}()
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
}`
