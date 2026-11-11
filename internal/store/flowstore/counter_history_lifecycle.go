// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/store/chclient"
)

func counterSubjectPredicate(tenant, subject string) (string, chParams, error) {
	if subject == "" || strings.TrimSpace(subject) != subject || !utf8.ValidString(subject) {
		return "", nil, ErrCounterHistoryInput
	}
	params := chParams{"tenant": tenant, "subject": subject}
	if pattern, ok := govern.SubjectNetworkPattern(subject); ok {
		params["network_subject"] = pattern
		params["network_exact"], _ = govern.SubjectNetworkExactPattern(subject)
		return `tenant_id={tenant:String} AND (match(agent_id,{network_exact:String}) OR match(source_ref,{network_subject:String}))`, params, nil
	}
	return `tenant_id={tenant:String} AND (lowerUTF8(agent_id)=lowerUTF8({subject:String}) OR lowerUTF8(source_ref)=lowerUTF8({subject:String}))`, params, nil
}

func counterSubjectsPredicate(tenant string, subjects []string) (string, chParams, error) {
	if len(subjects) == 0 {
		return "", nil, ErrCounterHistoryInput
	}
	params := chParams{"tenant": tenant}
	clauses := make([]string, len(subjects))
	for i, subject := range subjects {
		clause, values, err := counterSubjectPredicate(tenant, subject)
		if err != nil {
			return "", nil, err
		}
		for key, value := range values {
			if key == "tenant" {
				continue
			}
			name := "counter_subject_" + strconv.Itoa(i) + "_" + key
			clause = strings.ReplaceAll(clause, "{"+key+":", "{"+name+":")
			params[name] = value
		}
		clauses[i] = "(" + clause + ")"
	}
	return "(" + strings.Join(clauses, " OR ") + ")", params, nil
}

func (c *ClickHouse) counterLifecycleTarget(ctx context.Context, tenant string) (Target, string, error) {
	if err := validateCounterTenant(ctx, tenant); err != nil {
		return Target{}, "", err
	}
	if c == nil || c.conn == nil {
		return Target{}, "", ErrCounterHistoryUnavailable
	}
	target, err := c.route(ctx, tenant)
	if err != nil {
		return Target{}, "", err
	}
	table, err := counterHistoryTableFor(target)
	return target, table, err
}

// Both mutation values and export selectors are POST body fields. A source
// identity must never enter a request URL or an echoed backend error body.
func (c *ClickHouse) counterRequest(ctx context.Context, target Target, lane chclient.ReadLane, tenant, sql string, params chParams) (*http.Response, error) {
	fields := url.Values{"query": {sql}}
	for key, value := range params {
		fields.Set("param_"+key, value)
	}
	endpoint := c.laneBase(lane, target.BaseURL) + "/?" + tenantSettingName + "=" + url.QueryEscape(tenant)
	if !lane.Reader {
		endpoint += "&wait_end_of_query=1"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(fields.Encode()))
	if err != nil {
		return nil, ErrCounterHistoryUnavailable
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := lane.Conn.Do(lane.Key, request)
	if err != nil {
		return nil, ErrCounterHistoryUnavailable
	}
	if response.StatusCode/100 != 2 {
		_ = response.Body.Close()
		return nil, ErrCounterHistoryUnavailable
	}
	return response, nil
}

func (c *ClickHouse) counterControl(ctx context.Context, target Target, tenant, sql string, params chParams, count bool) (int64, error) {
	lane := chclient.ReadLane{Conn: c.conn, Key: target.BaseURL}
	if count {
		sql += " FORMAT JSONEachRow"
	}
	response, err := c.counterRequest(ctx, target, lane, tenant, sql, params)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if !count {
		body, err := chclient.ReadResponseBodyBounded(response.Body, 4096)
		if err != nil || len(bytes.TrimSpace(body)) != 0 {
			return 0, ErrCounterHistoryUnavailable
		}
		return 0, nil
	}
	body, err := chclient.ReadResponseBodyBounded(response.Body, 4096)
	if err != nil {
		return 0, ErrCounterHistoryUnavailable
	}
	rows, err := chclient.Decode(body)
	if err != nil || len(rows) != 1 || len(rows[0]) != 1 {
		return 0, ErrCounterHistoryUnavailable
	}
	literal, ok := rows[0]["n"].(string)
	value, err := strconv.ParseInt(literal, 10, 64)
	if !ok || err != nil || value < 0 || strconv.FormatInt(value, 10) != literal {
		return 0, ErrCounterHistoryUnavailable
	}
	return value, nil
}

func (c *ClickHouse) counterCount(ctx context.Context, target Target, tenant, table, predicate string, params chParams) (int64, error) {
	return c.counterControl(ctx, target, tenant, "SELECT toString(count()) AS n FROM "+table+" FINAL WHERE "+predicate, params, true)
}

func (c *ClickHouse) DeleteCounterTenant(ctx context.Context, tenant string) (int64, error) {
	target, table, err := c.counterLifecycleTarget(ctx, tenant)
	if err != nil {
		return -1, err
	}
	if target.Database != "" {
		// The existing flow eraser may already have dropped this same silo.
		// Verify actual database absence using control authority, never infer
		// a zero from a missing-table error or a filtered reader result.
		exists, err := c.counterControl(ctx, target, tenant, "SELECT toString(count()) AS n FROM system.databases WHERE name={database:String}", chParams{"database": target.Database}, true)
		if err != nil {
			return -1, err
		}
		if exists == 0 {
			return 0, nil
		}
		if exists != 1 {
			return -1, ErrCounterHistoryUnavailable
		}
	}
	params := chParams{"tenant": tenant}
	polls, err := counterPollTableFor(target)
	if err != nil {
		return -1, err
	}
	var remaining int64
	for _, name := range []string{polls, table} {
		if _, err := c.counterControl(ctx, target, tenant, "DELETE FROM "+name+" WHERE tenant_id={tenant:String} SETTINGS mutations_sync=2", params, false); err != nil {
			return -1, err
		}
		count, err := c.counterCount(ctx, target, tenant, name, "tenant_id={tenant:String}", params)
		if err != nil {
			return -1, err
		}
		remaining += count
	}
	return remaining, nil
}

func (c *ClickHouse) DeleteCounterSubject(ctx context.Context, tenant, subject string) (int64, int64, error) {
	return c.DeleteCounterSubjects(ctx, tenant, []string{subject})
}

func (c *ClickHouse) DeleteCounterSubjects(ctx context.Context, tenant string, subjects []string) (int64, int64, error) {
	target, table, err := c.counterLifecycleTarget(ctx, tenant)
	if err != nil {
		return 0, -1, err
	}
	predicate, params, err := counterSubjectsPredicate(tenant, subjects)
	if err != nil {
		return 0, -1, err
	}
	before, err := c.counterCount(ctx, target, tenant, table, predicate, params)
	if err != nil {
		return 0, -1, err
	}
	polls, err := counterPollTableFor(target)
	if err != nil {
		return 0, -1, err
	}
	for _, name := range []string{polls, table} {
		if _, err := c.counterControl(ctx, target, tenant, "DELETE FROM "+name+" WHERE "+predicate+" SETTINGS mutations_sync=2", params, false); err != nil {
			return 0, -1, err
		}
	}
	remaining, err := c.counterCount(ctx, target, tenant, table, predicate, params)
	if err != nil || remaining > before {
		if err == nil {
			err = ErrCounterHistoryUnavailable
		}
		return 0, -1, err
	}
	markers, err := c.counterCount(ctx, target, tenant, polls, predicate, params)
	if err != nil {
		return 0, -1, err
	}
	return before - remaining, remaining + markers, nil
}

func (c *ClickHouse) DeleteCountersBefore(ctx context.Context, tenant string, cutoff time.Time) error {
	if !counterClock(cutoff) {
		return ErrCounterHistoryInput
	}
	target, table, err := c.counterLifecycleTarget(ctx, tenant)
	if err != nil {
		return err
	}
	polls, err := counterPollTableFor(target)
	if err != nil {
		return err
	}
	params := chParams{"tenant": tenant, "cutoff": strconv.FormatInt(cutoff.UnixNano(), 10)}
	predicate := "tenant_id={tenant:String} AND poll_started_unix_nanos<{cutoff:Int64}"
	for _, name := range []string{polls, table} {
		if _, err := c.counterControl(ctx, target, tenant, "DELETE FROM "+name+" WHERE "+predicate+" SETTINGS mutations_sync=2", params, false); err != nil {
			return err
		}
		remaining, err := c.counterCount(ctx, target, tenant, name, predicate, params)
		if err != nil {
			return err
		}
		if remaining != 0 {
			return ErrCounterHistoryUnavailable
		}
	}
	return nil
}

func (c *ClickHouse) ExportCounterTenant(ctx context.Context, tenant string, w io.Writer) (int64, error) {
	return c.exportCounters(ctx, tenant, nil, w)
}
func (c *ClickHouse) ExportCounterSubject(ctx context.Context, tenant, subject string, w io.Writer) (int64, error) {
	return c.ExportCounterSubjects(ctx, tenant, []string{subject}, w)
}
func (c *ClickHouse) ExportCounterSubjects(ctx context.Context, tenant string, subjects []string, w io.Writer) (int64, error) {
	if len(subjects) == 0 {
		return 0, ErrCounterHistoryInput
	}
	return c.exportCounters(ctx, tenant, subjects, w)
}
func (c *ClickHouse) exportCounters(ctx context.Context, tenant string, subjects []string, w io.Writer) (int64, error) {
	if w == nil {
		return 0, ErrCounterHistoryInput
	}
	target, table, err := c.counterLifecycleTarget(ctx, tenant)
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
	predicate, params := "tenant_id={tenant:String}", chParams{"tenant": tenant}
	if len(subjects) > 0 {
		predicate, params, err = counterSubjectsPredicate(tenant, subjects)
		if err != nil {
			return 0, err
		}
	}
	committed, err := counterCommittedPredicate(target, false)
	if err != nil {
		return 0, err
	}
	response, err := c.counterRequest(ctx, target, lane, tenant, "SELECT "+counterReadColumns()+" FROM "+table+" FINAL WHERE "+predicate+" AND "+committed+" ORDER BY context_id,device_id,poll_started_unix_nanos,if_index,name,row_id SETTINGS "+counterReadColumnSetting+" FORMAT JSONEachRow", params)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	return scanCounterRows(ctx, response.Body, func(row CounterRow, line []byte) error {
		if row.TenantID != tenant {
			return ErrCounterHistoryInput
		}
		n, err := w.Write(line)
		if err != nil {
			return err
		}
		if n != len(line) {
			return io.ErrShortWrite
		}
		n, err = io.WriteString(w, "\n")
		if err != nil {
			return err
		}
		if n != 1 {
			return io.ErrShortWrite
		}
		return nil
	})
}

func scanCounterRows(ctx context.Context, source io.Reader, visit func(CounterRow, []byte) error) (int64, error) {
	// The admitted schema has three UUIDs, three 64-byte digests, source
	// fields of at most 128/1024 bytes, a 256-byte serial, six fixed metric
	// names and fixed-width decimal scalars. Even worst-case JSON escaping
	// fits inside this per-record workspace. There is no total row/body cap.
	scanner := bufio.NewScanner(source)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	var count int64
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		var raw map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
			return count, ErrCounterHistoryUnavailable
		}
		row, err := counterHistoryRow(raw)
		if err != nil {
			return count, err
		}
		if err := visit(row, scanner.Bytes()); err != nil {
			return count, err
		}
		count++
	}
	if err := ctx.Err(); err != nil {
		return count, err
	}
	if err := scanner.Err(); err != nil {
		return count, ErrCounterHistoryUnavailable
	}
	return count, nil
}
