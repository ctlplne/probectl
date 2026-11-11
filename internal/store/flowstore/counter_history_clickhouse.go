// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/store/chclient"
)

// JSONEachRow inserts use typed Go integers, never an intermediate float.
// Queries explicitly project every numeric column as decimal text so the
// generic HTTP decoder cannot round a uint64 word or a nanosecond clock.
type counterHistoryDocument struct {
	TenantID           string `json:"tenant_id"`
	ContextID          string `json:"context_id"`
	DeviceID           string `json:"device_id"`
	AgentID            string `json:"agent_id"`
	SourceRef          string `json:"source_ref"`
	SenderSerial       string `json:"sender_serial"`
	SourceAssigned     int64  `json:"source_assigned_unix_nanos"`
	AgentAssigned      int64  `json:"agent_assigned_unix_nanos"`
	CaptureKey         string `json:"capture_key"`
	RawDigest          string `json:"raw_digest"`
	Captured           int64  `json:"captured_unix_nanos"`
	Started            int64  `json:"poll_started_unix_nanos"`
	Completed          int64  `json:"poll_completed_unix_nanos"`
	Population         uint32 `json:"population"`
	IfIndex            uint32 `json:"if_index"`
	Name               string `json:"name"`
	Value              uint64 `json:"counter_value"`
	Width              uint32 `json:"counter_width"`
	UptimeTicks        uint32 `json:"uptime_ticks"`
	DiscontinuityTicks uint32 `json:"discontinuity_ticks"`
	UptimeKnown        uint8  `json:"uptime_known"`
	DiscontinuityKnown uint8  `json:"discontinuity_known"`
	RowID              string `json:"row_id"`
}

func counterDocument(row CounterRow) counterHistoryDocument {
	flag := func(known bool) uint8 {
		if known {
			return 1
		}
		return 0
	}
	return counterHistoryDocument{
		TenantID: row.TenantID, ContextID: row.ContextID, DeviceID: row.DeviceID, AgentID: row.AgentID, SourceRef: row.SourceRef, SenderSerial: row.SenderSerial,
		SourceAssigned: row.SourceAssignedAt.UnixNano(), AgentAssigned: row.AgentAssignedAt.UnixNano(),
		CaptureKey: hex.EncodeToString(row.CaptureKey[:]), RawDigest: hex.EncodeToString(row.RawDigest[:]), Captured: row.CapturedAt.UnixNano(),
		Started: row.PollStartedAt.UnixNano(), Completed: row.PollCompletedAt.UnixNano(), Population: row.Population,
		IfIndex: row.IfIndex, Name: row.Name, Value: row.Value, Width: row.Width, UptimeTicks: row.UptimeTicks, DiscontinuityTicks: row.DiscontinuityTicks,
		UptimeKnown: flag(row.UptimeKnown), DiscontinuityKnown: flag(row.DiscontinuityKnown), RowID: counterRowID(row),
	}
}

// Portable exports use decimal strings for every integer. A JSON consumer
// cannot round the original uint64 words or nanosecond provenance clocks.
func counterPortableDocument(row CounterRow) map[string]any {
	doc := counterDocument(row)
	return map[string]any{
		"tenant_id": doc.TenantID, "context_id": doc.ContextID, "device_id": doc.DeviceID,
		"agent_id": doc.AgentID, "source_ref": doc.SourceRef, "sender_serial": doc.SenderSerial,
		"capture_key": doc.CaptureKey, "raw_digest": doc.RawDigest, "name": doc.Name, "row_id": doc.RowID,
		"source_assigned_unix_nanos": strconv.FormatInt(doc.SourceAssigned, 10),
		"agent_assigned_unix_nanos":  strconv.FormatInt(doc.AgentAssigned, 10),
		"captured_unix_nanos":        strconv.FormatInt(doc.Captured, 10),
		"poll_started_unix_nanos":    strconv.FormatInt(doc.Started, 10),
		"poll_completed_unix_nanos":  strconv.FormatInt(doc.Completed, 10),
		"population":                 strconv.FormatUint(uint64(doc.Population), 10), "if_index": strconv.FormatUint(uint64(doc.IfIndex), 10),
		"counter_value": strconv.FormatUint(doc.Value, 10), "counter_width": strconv.FormatUint(uint64(doc.Width), 10),
		"uptime_ticks": strconv.FormatUint(uint64(doc.UptimeTicks), 10), "discontinuity_ticks": strconv.FormatUint(uint64(doc.DiscontinuityTicks), 10),
		"uptime_known": strconv.FormatUint(uint64(doc.UptimeKnown), 10), "discontinuity_known": strconv.FormatUint(uint64(doc.DiscontinuityKnown), 10),
	}
}

func (c *ClickHouse) InsertCounterPoll(ctx context.Context, rows []CounterRow, budget CounterBudget) error {
	if err := validateCounterPoll(ctx, rows, budget); err != nil {
		return err
	}
	if c == nil || c.conn == nil {
		return ErrCounterHistoryUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, budget.Timeout)
	defer cancel()
	target, err := c.route(ctx, rows[0].TenantID)
	if err != nil {
		return err
	}
	table, err := counterHistoryTableFor(target)
	if err != nil {
		return err
	}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := encoder.Encode(counterDocument(row)); err != nil {
			return ErrCounterHistoryInput
		}
		if int64(body.Len()) > budget.MemoryBytes/4 || int64(body.Len()) > budget.WorkUnits/4 {
			return ErrCounterHistoryBudget
		}
	}
	if err := c.insertCounterBody(ctx, target, table, &body); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A backend diagnostic may contain original row values. Do not pass it
		// to a bus retry log or an outward error response.
		return ErrCounterHistoryUnavailable
	}
	first := rows[0]
	params := chParams{"tenant": first.TenantID, "capture": hex.EncodeToString(first.CaptureKey[:]), "population": strconv.FormatUint(uint64(first.Population), 10)}
	params["context"], params["device"], params["agent"], params["source"] = first.ContextID, first.DeviceID, first.AgentID, first.SourceRef
	params["source_at"], params["agent_at"], params["started"] = strconv.FormatInt(first.SourceAssignedAt.UnixNano(), 10), strconv.FormatInt(first.AgentAssignedAt.UnixNano(), 10), strconv.FormatInt(first.PollStartedAt.UnixNano(), 10)
	count, err := c.counterCount(ctx, target, first.TenantID, table, "tenant_id={tenant:String} AND context_id={context:String} AND device_id={device:String} AND agent_id={agent:String} AND source_ref={source:String} AND source_assigned_unix_nanos={source_at:Int64} AND agent_assigned_unix_nanos={agent_at:Int64} AND ts=fromUnixTimestamp64Nano({started:Int64}) AND capture_key={capture:String} AND population={population:UInt32}", params)
	if err != nil || count != int64(len(rows)) {
		return ErrCounterHistoryUnavailable
	}
	polls, err := counterPollTableFor(target)
	if err != nil {
		return err
	}
	marker, err := json.Marshal(map[string]any{
		"tenant_id": first.TenantID, "context_id": first.ContextID, "device_id": first.DeviceID,
		"agent_id": first.AgentID, "source_ref": first.SourceRef,
		"source_assigned_unix_nanos": first.SourceAssignedAt.UnixNano(), "agent_assigned_unix_nanos": first.AgentAssignedAt.UnixNano(),
		"capture_key": params["capture"], "poll_started_unix_nanos": first.PollStartedAt.UnixNano(), "population": first.Population,
	})
	if err != nil {
		return ErrCounterHistoryInput
	}
	return c.insertCounterBody(ctx, target, polls, bytes.NewReader(marker))
}

func (c *ClickHouse) insertCounterBody(ctx context.Context, target Target, table string, body io.Reader) error {
	// Wait for completion and consume the acknowledgement: ClickHouse may
	// report a late query exception in an otherwise successful HTTP response.
	sql := "INSERT INTO " + table + " SETTINGS async_insert=0,wait_for_async_insert=1 FORMAT JSONEachRow"
	endpoint := c.baseFor(target.BaseURL) + "/?wait_end_of_query=1&query=" + url.QueryEscape(sql)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return ErrCounterHistoryUnavailable
	}
	response, err := c.conn.Do(target.BaseURL, request)
	if err != nil {
		return ErrCounterHistoryUnavailable
	}
	defer response.Body.Close()
	ack, err := chclient.ReadResponseBodyBounded(response.Body, 4096)
	if err != nil || response.StatusCode/100 != 2 || len(bytes.TrimSpace(ack)) != 0 {
		return ErrCounterHistoryUnavailable
	}
	return nil
}

func counterReadColumns() string {
	columns := []string{"tenant_id", "context_id", "device_id", "agent_id", "source_ref", "sender_serial", "capture_key", "raw_digest", "name", "row_id"}
	for _, name := range []string{"source_assigned_unix_nanos", "agent_assigned_unix_nanos", "captured_unix_nanos", "poll_started_unix_nanos", "poll_completed_unix_nanos", "population", "if_index", "counter_value", "counter_width", "uptime_ticks", "discontinuity_ticks", "uptime_known", "discontinuity_known"} {
		columns = append(columns, "toString("+name+") AS "+name)
	}
	return strings.Join(columns, ",")
}

func counterSourcePredicate(query CounterQuery) (string, chParams, error) {
	params := chParams{"tenant": query.TenantID, "from": strconv.FormatInt(query.From.UnixNano(), 10), "to": strconv.FormatInt(query.To.UnixNano(), 10)}
	clauses := make([]string, 0, len(query.Sources))
	for i, selector := range query.Sources {
		prefix := "counter_source_" + strconv.Itoa(i)
		indexes, err := json.Marshal(selector.IfIndexes)
		if err != nil {
			return "", nil, ErrCounterHistoryInput
		}
		params[prefix+"_context"], params[prefix+"_device"] = selector.ContextID, selector.DeviceID
		params[prefix+"_agent"], params[prefix+"_ref"] = selector.AgentID, selector.SourceRef
		params[prefix+"_source_at"], params[prefix+"_agent_at"] = strconv.FormatInt(selector.SourceAssignedAt.UnixNano(), 10), strconv.FormatInt(selector.AgentAssignedAt.UnixNano(), 10)
		params[prefix+"_indexes"] = string(indexes)
		clauses = append(clauses, "(context_id={"+prefix+"_context:String} AND device_id={"+prefix+"_device:String} AND agent_id={"+prefix+"_agent:String} AND source_ref={"+prefix+"_ref:String} AND source_assigned_unix_nanos={"+prefix+"_source_at:Int64} AND agent_assigned_unix_nanos={"+prefix+"_agent_at:Int64} AND if_index IN {"+prefix+"_indexes:Array(UInt32)})")
	}
	return "tenant_id={tenant:String} AND ts>=fromUnixTimestamp64Nano({from:Int64}) AND ts<=fromUnixTimestamp64Nano({to:Int64}) AND poll_started_unix_nanos>={from:Int64} AND poll_started_unix_nanos<={to:Int64} AND (" + strings.Join(clauses, " OR ") + ")", params, nil
}

func counterExplorerBudget(budget CounterBudget) (ExplorerBudget, error) {
	if budget.MemoryBytes < 4096 || budget.WorkUnits < 1024 || budget.Timeout <= 0 {
		return ExplorerBudget{}, ErrCounterHistoryBudget
	}
	profile := DefaultExplorerBudget()
	profile.ExecutionLimit, profile.MemoryBytes = budget.Timeout, budget.MemoryBytes
	profile.ReadBytes, profile.ReadRows = budget.WorkUnits, int(min(budget.WorkUnits/1024, int64(int(^uint(0)>>1)-1)))
	profile.ResponseBytes = budget.MemoryBytes / 32
	profile.IntermediateGroups = profile.ReadRows
	if err := profile.Validate(); err != nil {
		return ExplorerBudget{}, ErrCounterHistoryBudget
	}
	return profile, nil
}

func (c *ClickHouse) CounterPoints(ctx context.Context, query CounterQuery) ([]CounterRow, error) {
	remaining := query.Budget.MemoryBytes / 2
	var rows []CounterRow
	err := c.WalkCounterPoints(ctx, query, func(row CounterRow) error {
		charge := counterRowCharge(row)
		if charge <= 0 || charge > remaining {
			return ErrCounterHistoryBudget
		}
		remaining -= charge
		rows = append(rows, row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func (c *ClickHouse) WalkCounterPoints(ctx context.Context, query CounterQuery, visit func(CounterRow) error) error {
	if err := validateCounterQuery(ctx, query); err != nil {
		return err
	}
	if visit == nil {
		return ErrCounterHistoryInput
	}
	if c == nil || c.conn == nil {
		return ErrCounterHistoryUnavailable
	}
	profile, err := counterExplorerBudget(query.Budget)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, profile.ExecutionLimit)
	defer cancel()
	target, err := c.route(ctx, query.TenantID)
	if err != nil {
		return err
	}
	table, err := counterHistoryTableFor(target)
	if err != nil {
		return err
	}
	lane, err := c.readLane(target, query.TenantID)
	if err != nil {
		return err
	}
	predicate, params, err := counterSourcePredicate(query)
	if err != nil {
		return err
	}
	committed, err := counterCommittedPredicate(target, true)
	if err != nil {
		return err
	}
	settings, err := profile.settings()
	if err != nil {
		return err
	}
	sql := "SELECT " + counterReadColumns() + " FROM " + table + " FINAL WHERE " + predicate + " AND " + committed + " ORDER BY context_id,device_id,if_index,name,poll_started_unix_nanos,capture_key " + settings + " FORMAT JSONEachRow"
	response, err := c.counterRequest(ctx, target, lane, query.TenantID, sql, params)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	contains := compileCounterSelection(query)
	_, err = scanCounterRows(ctx, response.Body, func(row CounterRow, _ []byte) error {
		if !contains(row) {
			return ErrCounterHistoryInput
		}
		return visit(row)
	})
	return err
}

func counterHistoryRow(raw map[string]any) (CounterRow, error) {
	if len(raw) != 23 {
		return CounterRow{}, ErrCounterHistoryInput
	}
	text := func(name string) string { value, _ := raw[name].(string); return value }
	row := CounterRow{TenantID: text("tenant_id"), CounterSource: CounterSource{ContextID: text("context_id"), DeviceID: text("device_id"), AgentID: text("agent_id"), SourceRef: text("source_ref")}, SenderSerial: text("sender_serial"), Name: text("name")}
	for name, target := range map[string]*[32]byte{"capture_key": &row.CaptureKey, "raw_digest": &row.RawDigest} {
		value := text(name)
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != value {
			return CounterRow{}, ErrCounterHistoryInput
		}
		copy(target[:], decoded)
	}
	for name, target := range map[string]*time.Time{"source_assigned_unix_nanos": &row.SourceAssignedAt, "agent_assigned_unix_nanos": &row.AgentAssignedAt, "captured_unix_nanos": &row.CapturedAt, "poll_started_unix_nanos": &row.PollStartedAt, "poll_completed_unix_nanos": &row.PollCompletedAt} {
		value := text(name)
		ns, err := strconv.ParseInt(value, 10, 64)
		if err != nil || ns <= 0 || strconv.FormatInt(ns, 10) != value {
			return CounterRow{}, ErrCounterHistoryInput
		}
		*target = time.Unix(0, ns)
	}
	for name, target := range map[string]*uint32{"population": &row.Population, "if_index": &row.IfIndex, "counter_width": &row.Width, "uptime_ticks": &row.UptimeTicks, "discontinuity_ticks": &row.DiscontinuityTicks} {
		value := text(name)
		word, err := strconv.ParseUint(value, 10, 32)
		if err != nil || strconv.FormatUint(word, 10) != value {
			return CounterRow{}, ErrCounterHistoryInput
		}
		*target = uint32(word)
	}
	for name, target := range map[string]*bool{"uptime_known": &row.UptimeKnown, "discontinuity_known": &row.DiscontinuityKnown} {
		value := text(name)
		if value != "0" && value != "1" {
			return CounterRow{}, ErrCounterHistoryInput
		}
		*target = value == "1"
	}
	value := text("counter_value")
	word, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(word, 10) != value {
		return CounterRow{}, ErrCounterHistoryInput
	}
	row.Value = word
	if err := validateCounterObservation(row); err != nil || text("row_id") != counterRowID(row) {
		return CounterRow{}, ErrCounterHistoryInput
	}
	return row, nil
}
