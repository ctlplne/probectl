// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import (
	"bytes"
	"context"
	"encoding/csv"
	"reflect"
	"strings"
	"testing"
)

func TestReportFieldIdentitiesRetainCompleteSchemaAndCapture(t *testing.T) {
	d := testDocument()
	table := reportTable(d, []CSVColumn{{Name: "row.tag.customer"}, {Name: "column.tag.customer"}, {Name: "bytes", Numeric: true}}, [][]string{{"東京", "موقع", "9007199254740993"}})
	table.FieldIDs = map[string]string{"column.tag.customer": "definition-column", "row.tag.customer": "definition-row"}
	d.Tables = []CSVTable{table}
	body, err := RenderCSV(d)
	if err != nil {
		t.Fatal(err)
	}
	reader := csv.NewReader(bytes.NewReader(body))
	reader.FieldsPerRecord = -1
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var identities [][]string
	for _, row := range rows {
		if len(row) > 0 && strings.HasPrefix(row[0], "table_field_id:") {
			identities = append(identities, row)
		}
	}
	want := [][]string{{"table_field_id:column.tag.customer", "definition-column"}, {"table_field_id:row.tag.customer", "definition-row"}}
	if !reflect.DeepEqual(identities, want) {
		t.Fatalf("full immutable field identities missing or unstable: %q", identities)
	}
	pdf, err := RenderPDF(d)
	if err != nil {
		t.Fatal(err)
	}
	text := pdfSemanticText(t, pdf)
	for _, value := range []string{"Field identity column.tag.customer: definition-column", "Field identity row.tag.customer: definition-row", "9223372036854775806", "9007199254740993"} {
		if !strings.Contains(text, value) {
			t.Fatalf("PDF lost field identity or exact capture: %q", value)
		}
	}
	for _, ids := range []map[string]string{{"missing-column": "id"}, {"row.tag.customer": ""}, {"row.tag.customer": string([]byte{0xff})}} {
		d.Tables[0].FieldIDs = ids
		if body, err := RenderCSV(d); err == nil || body != nil {
			t.Fatal("CSV accepted a missing or malformed field identity")
		}
		if body, err := RenderPDF(d); err == nil || body != nil {
			t.Fatal("PDF accepted a missing or malformed field identity")
		}
	}
	limits := DefaultCSVLimits()
	limits.MemoryBytes = 24 << 10
	d.Tables[0].FieldIDs = map[string]string{"row.tag.customer": "definition-row"}
	if _, err := WriteCSV(context.Background(), &bytes.Buffer{}, d, limits); err != nil {
		t.Fatalf("field identity budget fixture cannot render its baseline: %v", err)
	}
	d.Tables[0].FieldIDs = map[string]string{"row.tag.customer": strings.Repeat("x", 10000)}
	if _, err := WriteCSV(context.Background(), &bytes.Buffer{}, d, limits); err == nil {
		t.Fatal("field identities escaped the schema workspace budget")
	}
}
