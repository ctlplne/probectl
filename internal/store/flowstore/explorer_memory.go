// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

// WithExplorerInterfaces attaches the existing tenant-scoped device read model.
func (m *Memory) WithExplorerInterfaces(source ExplorerInterfaceSource) *Memory {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.explorerInterfaces = source
	return m
}
func (m *Memory) explorerSnapshot(ctx context.Context, tenant string, spec flow.QueryPlan) ([]memoryRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	budget := explorerBudgetFor(ctx)
	out := make([]memoryRow, 0, 256)
	size := 0
	for _, entry := range m.rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Storage scope is the outermost condition, including resource accounting.
		if entry.row.TenantID != tenant {
			continue
		}
		if entry.row.TS.Before(spec.From) || !entry.row.TS.Before(spec.To) {
			continue
		}
		row := entry.row
		size += 256 + len(row.AgentID) + len(row.Exporter) + len(row.Protocol) + len(row.SrcAddr) + len(row.DstAddr) + len(row.Transport) + len(row.NetType) + len(row.NextHop) + len(row.SrcASName) + len(row.DstASName) + len(row.SrcCountry) + len(row.DstCountry) + len(entry.key)
		if len(out) >= budget.ReadRows || int64(size) > min(budget.ReadBytes, budget.MemoryBytes) {
			return nil, ErrExplorerBudget
		}
		out = append(out, entry)
	}
	return out, nil
}

var explorerRowFields = func() map[string]int {
	fields := map[string]int{}
	typ := reflect.TypeFor[Row]()
	for i := 0; i < typ.NumField(); i++ {
		tag := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if tag != "" && tag != "-" && tag != "tenant_id" {
			fields[tag] = i
		}
	}
	return fields
}()

func explorerFieldValue(entry memoryRow, name string, spec flow.QueryPlan, names map[string]map[uint32]string,
	vocabulary flow.QueryVocabulary, tagData *TagQueryData) string {
	field, ok := vocabulary.Lookup(name)
	if !ok {
		return ""
	}
	row := entry.row
	if field.Derived == "tenant_tag" {
		if tagData == nil {
			return ""
		}
		value, err := tagData.valueForRow(row, field.TagKey)
		if err != nil {
			return ""
		}
		return value
	}
	switch field.Derived {
	case "src_prefix", "dst_prefix":
		address := row.SrcAddr
		if field.Derived == "dst_prefix" {
			address = row.DstAddr
		}
		ip, err := netip.ParseAddr(address)
		if err != nil {
			return ""
		}
		ip = ip.Unmap()
		bits := *spec.IPv6PrefixLength
		if ip.Is4() {
			bits = *spec.IPv4PrefixLength
		}
		return netip.PrefixFrom(ip, bits).Masked().String()
	case "dscp":
		return strconv.FormatUint(uint64(row.ToS>>2), 10)
	case "tcp_flag_names":
		flags := []string{}
		for i, name := range []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"} {
			if row.TCPFlags&(1<<i) != 0 {
				flags = append(flags, name)
			}
		}
		if len(flags) == 0 {
			return "NONE"
		}
		return strings.Join(flags, ",")
	case "in_if_name", "out_if_name":
		index := row.InIf
		if field.Derived == "out_if_name" {
			index = row.OutIf
		}
		if name := names[row.Exporter][index]; name != "" {
			return name
		}
		return "unmapped:" + row.Exporter + "#" + strconv.FormatUint(uint64(index), 10)
	}
	switch field.Column {
	case "ts":
		return row.TS.UTC().Format(time.RFC3339Nano)
	case "start_ts":
		return row.StartTS.UTC().Format(time.RFC3339Nano)
	case "row_id":
		return entry.key
	}
	index, ok := explorerRowFields[field.Column]
	if !ok {
		return ""
	}
	value := reflect.ValueOf(row).Field(index)
	if value.Kind() == reflect.String {
		if field.Type == flow.QueryAddress {
			if address, err := netip.ParseAddr(value.String()); err == nil {
				return address.Unmap().String()
			}
		}
		return value.String()
	}
	return strconv.FormatUint(value.Uint(), 10)
}

func explorerCanonicalAddress(value string) string {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Unmap().String()
	}
	return value
}
