// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// CSVTable is an already authorized, captured source. Rendering grants no
// access. WalkRows must synchronously yield every row, honor context, and
// return source failures; it must never convert a failed source to empty data.
// Column names are stable source field keys, not shortened display labels.
type CSVTable struct {
	ID, Title, TenantID, Source string
	AbsoluteFrom, AbsoluteTo    time.Time
	TagRevision                 string
	TagAsOf                     time.Time
	Columns                     []CSVColumn
	ExpectedRows                int64
	WalkRows                    func(context.Context, func([]string) error) error
}

// Numeric cells must be canonical base-ten decimal strings. All other cells,
// including metadata and field keys, are untrusted literal text.
type CSVColumn struct {
	Name    string
	Numeric bool
}

type CSVLimits struct {
	Bytes       int64
	TableRows   int64
	MemoryBytes int64
}

type CSVReceipt struct {
	Bytes     int64
	TableRows int64
}

// These are logical table records, not physical lines within quoted cells or
// distinct flow groups. Each source retains its own query and memory limits.
func DefaultCSVLimits() CSVLimits {
	return CSVLimits{Bytes: 256 << 20, TableRows: 500_000, MemoryBytes: 128 << 20}
}

var ErrCSVLimit = errors.New("report CSV output budget exceeded")

// WriteCSV writes to caller-owned staging storage. On ANY error the caller
// must discard that storage; partial bytes are never a publishable artifact.
// A receipt is returned only after complete source counts and Flush succeed.
func WriteCSV(ctx context.Context, target io.Writer, d Document, limits CSVLimits) (CSVReceipt, error) {
	if err := d.Validate(); err != nil {
		return CSVReceipt{}, err
	}
	if target == nil || limits.Bytes <= 0 || limits.TableRows <= 0 || limits.MemoryBytes <= 0 {
		return CSVReceipt{}, fmt.Errorf("report CSV writer and positive limits are required")
	}
	if err := ctx.Err(); err != nil {
		return CSVReceipt{}, err
	}
	var expected int64
	remainingMemory := limits.MemoryBytes - 4096 // encoding/csv's buffered writer
	if remainingMemory < 0 {
		return CSVReceipt{}, ErrCSVLimit
	}
	if err := chargeCSVLegacy(d, &remainingMemory); err != nil {
		return CSVReceipt{}, err
	}
	if int64(len(d.Tables)) > remainingMemory/128 {
		return CSVReceipt{}, ErrCSVLimit
	}
	remainingMemory -= int64(len(d.Tables)) * 128
	identities := make(map[string]bool, len(d.Tables))
	for _, table := range d.Tables {
		if identities[table.ID] {
			return CSVReceipt{}, fmt.Errorf("report table identities must be unique")
		}
		if err := validateCSVTable(table, d.TenantScope, limits, &remainingMemory); err != nil {
			return CSVReceipt{}, err
		}
		if table.ExpectedRows > limits.TableRows-expected {
			return CSVReceipt{}, ErrCSVLimit
		}
		expected += table.ExpectedRows
		identities[table.ID] = true
	}
	output := &boundedCSVWriter{ctx: ctx, target: target, remaining: limits.Bytes}
	writer := csv.NewWriter(output)
	if err := writeCSVLegacy(writer, d); err != nil {
		return CSVReceipt{}, err
	}
	for _, table := range d.Tables {
		if err := writeCSVTable(ctx, writer, table, remainingMemory); err != nil {
			return CSVReceipt{}, err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return CSVReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return CSVReceipt{}, err
	}
	return CSVReceipt{Bytes: limits.Bytes - output.remaining, TableRows: expected}, nil
}

func chargeCSVLegacy(d Document, memory *int64) error {
	charge := func(value string) bool {
		if *memory < 64 || int64(len(value)) > (*memory-64)/2 {
			return false
		}
		*memory -= 2*int64(len(value)) + 64
		return true
	}
	for _, value := range []string{d.Title, d.Preset, d.TenantName, d.TenantScope, d.GeneratedBy, d.RedactionState} {
		if !charge(value) {
			return ErrCSVLimit
		}
	}
	for _, values := range [][]string{d.Provenance, d.CoverageLimitations} {
		for _, value := range values {
			if !charge(value) {
				return ErrCSVLimit
			}
		}
	}
	for key, value := range d.Metrics {
		if !charge(key) || !charge(value) {
			return ErrCSVLimit
		}
	}
	return nil
}

func writeCSVLegacy(writer *csv.Writer, d Document) error {
	rows := [][2]string{
		{"banner", Banner}, {"title", d.Title}, {"preset", d.Preset},
		{"tenant_name", d.TenantName}, {"tenant_scope", d.TenantScope},
		{"absolute_from", d.AbsoluteFrom.UTC().Format(time.RFC3339Nano)},
		{"absolute_to", d.AbsoluteTo.UTC().Format(time.RFC3339Nano)},
		{"generated_at", d.GeneratedAt.UTC().Format(time.RFC3339Nano)},
		{"generated_by", d.GeneratedBy},
		{"provenance", strings.Join(d.Provenance, " | ")},
		{"redaction_state", d.RedactionState},
		{"coverage_limitations", strings.Join(d.CoverageLimitations, " | ")},
	}
	for _, row := range rows {
		if err := writer.Write([]string{row[0], CSVText(row[1])}); err != nil {
			return err
		}
	}
	if err := writer.Write([]string{"metric", "exact_value"}); err != nil {
		return err
	}
	keys := make([]string, 0, len(d.Metrics))
	for key := range d.Metrics {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := writer.Write([]string{CSVText(key), CSVText(d.Metrics[key])}); err != nil {
			return err
		}
	}
	return nil
}

func validateCSVTable(table CSVTable, tenant string, limits CSVLimits, memory *int64) error {
	if table.TenantID != tenant || table.ID == "" || table.Title == "" || table.Source == "" || table.WalkRows == nil || len(table.Columns) == 0 {
		return fmt.Errorf("report table requires its tenant, identity, source, schema and row reader")
	}
	if table.AbsoluteFrom.IsZero() || !table.AbsoluteTo.After(table.AbsoluteFrom) {
		return fmt.Errorf("report table requires its exact absolute interval")
	}
	if table.ExpectedRows < 0 || table.ExpectedRows > limits.TableRows {
		return ErrCSVLimit
	}
	if table.TagRevision != "" {
		revision, err := strconv.ParseInt(table.TagRevision, 10, 64)
		if err != nil || revision < 1 || strconv.FormatInt(revision, 10) != table.TagRevision || table.TagAsOf.IsZero() {
			return fmt.Errorf("report table requires an exact metadata revision and capture time")
		}
	} else if !table.TagAsOf.IsZero() {
		return fmt.Errorf("report table capture time requires its metadata revision")
	}
	// Charge the complete schema and temporary map/header/row slice overhead
	// before allocating them; output bytes are not an allocation allowance.
	if int64(len(table.Columns)) > *memory/128 {
		return ErrCSVLimit
	}
	*memory -= int64(len(table.Columns)) * 128
	remaining := limits.Bytes
	for _, value := range []string{table.ID, table.Title, table.TenantID, table.Source, table.TagRevision} {
		if !utf8.ValidString(value) || int64(len(value)) > remaining {
			return ErrCSVLimit
		}
		if int64(len(value)) > *memory/2 {
			return ErrCSVLimit
		}
		*memory -= int64(len(value)) * 2
		remaining -= int64(len(value))
	}
	seen := make(map[string]bool, len(table.Columns))
	for _, column := range table.Columns {
		if column.Name == "" || seen[column.Name] || !utf8.ValidString(column.Name) {
			return fmt.Errorf("report table requires unique complete UTF-8 field keys")
		}
		if int64(len(column.Name))+32 > remaining {
			return ErrCSVLimit
		}
		if int64(len(column.Name)) > *memory/2 {
			return ErrCSVLimit
		}
		*memory -= int64(len(column.Name)) * 2
		remaining -= int64(len(column.Name)) + 32
		seen[column.Name] = true
	}
	return nil
}

func writeCSVTable(ctx context.Context, writer *csv.Writer, table CSVTable, memory int64) error {
	metadata := [][2]string{
		{"table_id", table.ID}, {"table_title", table.Title}, {"table_source", table.Source},
		{"table_tenant_scope", table.TenantID},
		{"table_absolute_from", table.AbsoluteFrom.UTC().Format(time.RFC3339Nano)},
		{"table_absolute_to", table.AbsoluteTo.UTC().Format(time.RFC3339Nano)},
		{"table_rows", strconv.FormatInt(table.ExpectedRows, 10)},
	}
	if table.TagRevision != "" {
		metadata = append(metadata, [2]string{"table_tag_revision", table.TagRevision},
			[2]string{"table_tag_as_of", table.TagAsOf.UTC().Format(time.RFC3339Nano)})
	}
	for _, pair := range metadata {
		if err := writer.Write([]string{pair[0], CSVText(pair[1])}); err != nil {
			return err
		}
	}
	header := make([]string, len(table.Columns))
	for i, column := range table.Columns {
		header[i] = CSVText(column.Name)
	}
	if err := writer.Write(header); err != nil {
		return err
	}
	var count int64
	var rowErr error
	err := table.WalkRows(ctx, func(row []string) error {
		if rowErr != nil {
			return rowErr
		}
		if rowErr = ctx.Err(); rowErr != nil {
			return rowErr
		}
		if count >= table.ExpectedRows {
			rowErr = fmt.Errorf("report table row count differs from its captured source")
			return rowErr
		}
		encoded, err := encodeCSVTableRow(row, table.Columns, memory)
		if err != nil {
			rowErr = err
			return rowErr
		}
		if rowErr = writer.Write(encoded); rowErr != nil {
			return rowErr
		}
		count++
		return nil
	})
	if err != nil {
		return err
	}
	if rowErr != nil {
		return rowErr
	}
	if count != table.ExpectedRows {
		return fmt.Errorf("report table row count differs from its captured source")
	}
	return nil
}

func encodeCSVTableRow(row []string, columns []CSVColumn, memory int64) ([]string, error) {
	if len(row) != len(columns) {
		return nil, fmt.Errorf("report table row schema differs from its captured source")
	}
	if int64(len(row)) > memory/32 {
		return nil, ErrCSVLimit
	}
	memory -= int64(len(row)) * 32
	for _, value := range row {
		if int64(len(value)) > memory/2 {
			return nil, ErrCSVLimit
		}
		memory -= int64(len(value)) * 2
	}
	encoded := make([]string, len(row))
	for i, value := range row {
		if !utf8.ValidString(value) {
			return nil, fmt.Errorf("report table value is not complete UTF-8")
		}
		if columns[i].Numeric {
			if !csvDecimal(value) {
				return nil, fmt.Errorf("report table numeric cell is not a canonical exact decimal")
			}
			encoded[i] = value
		} else {
			encoded[i] = CSVText(value)
		}
	}
	return encoded, nil
}

func csvDecimal(value string) bool {
	if value == "" {
		return false
	}
	if value[0] == '-' {
		value = value[1:]
	}
	whole, fraction, dotted := strings.Cut(value, ".")
	if whole == "" || len(whole) > 1 && whole[0] == '0' || dotted && fraction == "" {
		return false
	}
	for _, part := range []string{whole, fraction} {
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return true
}

type boundedCSVWriter struct {
	ctx       context.Context
	target    io.Writer
	remaining int64
}

func (w *boundedCSVWriter) Write(body []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(body)) > w.remaining {
		return 0, ErrCSVLimit
	}
	n, err := w.target.Write(body)
	w.remaining -= int64(n)
	if err == nil && n != len(body) {
		err = io.ErrShortWrite
	}
	return n, err
}
