// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/ctlplne/probectl/internal/store/chclient"
)

// RetainedExporter is separate from raw export: records can exist in both
// physical sources and the retained coverage marker must survive portability.
type RetainedExporter interface {
	ExportRetainedTenant(context.Context, string, io.Writer) (int64, error)
	ExportRetainedSubject(context.Context, string, string, io.Writer) (int64, error)
}

// RetainedExporterOf preserves optional capability through lifecycle fences.
func RetainedExporterOf(store Store) (RetainedExporter, bool) {
	for {
		switch current := store.(type) {
		case *writeFencedStore:
			store = current.next
		case *subjectDeletingWriteFencedStore:
			store = current.next
		default:
			result, ok := store.(RetainedExporter)
			return result, ok
		}
	}
}

func (c *ClickHouse) ExportRetainedTenant(ctx context.Context, tenant string, w io.Writer) (int64, error) {
	return c.exportRetained(ctx, tenant, "", w)
}
func (c *ClickHouse) ExportRetainedSubject(ctx context.Context, tenant, subject string, w io.Writer) (int64, error) {
	if strings.TrimSpace(subject) == "" {
		return 0, errors.New("retained flow export requires a subject")
	}
	return c.exportRetained(ctx, tenant, subject, w)
}

func (c *ClickHouse) exportRetained(ctx context.Context, tenant, subject string, w io.Writer) (int64, error) {
	if strings.TrimSpace(tenant) == "" {
		return 0, ErrNoTenant
	}
	target, err := c.route(ctx, tenant)
	if err != nil {
		return 0, err
	}
	lane, err := c.readLane(target, tenant)
	if err != nil {
		return 0, err
	}
	if !lane.Reader {
		return 0, chclient.ErrReaderRequired
	}
	table, err := rollupTableFor(target)
	if err != nil {
		return 0, err
	}
	predicate := "tenant_id={tenant:String}"
	params := chParams{"tenant": tenant}
	if subject != "" {
		predicate = flowRollupSubjectPredicate()
		params["subject"] = subject
	}
	sql := "SELECT * FROM " + table + " FINAL WHERE " + predicate + " ORDER BY bucket,row_id FORMAT JSONEachRow"
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	if err := form.WriteField("query", sql); err != nil {
		return 0, err
	}
	keys := []string{}
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := form.WriteField("param_"+key, params[key]); err != nil {
			return 0, err
		}
	}
	if err := form.Close(); err != nil {
		return 0, err
	}
	endpoint := c.laneBase(lane, target.BaseURL) + "/?" + tenantSettingName + "=" + url.QueryEscape(tenant)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", form.FormDataContentType())
	response, err := lane.Conn.Do(lane.Key, req)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return 0, fmt.Errorf("retained flow export store status %d", response.StatusCode)
	}
	return chclient.CopyRows(w, response.Body)
}
