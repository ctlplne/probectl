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
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/chclient"
)

// WithExplorerInterfaces attaches tenant-scoped device metadata at startup.
func (c *ClickHouse) WithExplorerInterfaces(source ExplorerInterfaceSource) *ClickHouse {
	c.explorerInterfaces = source
	return c
}

// explorerQueryRows is the common bounded POST transport for structured plans.
// Bound values never appear in an HTTP URL, diagnostic body or public error.
func (c *ClickHouse) explorerQueryRows(ctx context.Context, target Target, lane chclient.ReadLane, tenant, sql string, params chParams, tagRows ...[]byte) ([]map[string]any, error) {
	if len(tagRows) > 1 {
		return nil, ErrExplorerBudget
	}
	if len(tagRows) == 1 && int64(len(tagRows[0])) > explorerBudgetFor(ctx).MemoryBytes/4 {
		return nil, ErrExplorerBudget
	}
	// Multipart keeps bounded filter/metadata values out of URLs. It also avoids
	// the HTTP URI ceiling for a large, but permitted, interface-name mapping.
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	if err := form.WriteField("query", sql+" FORMAT JSONEachRow"); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := form.WriteField("param_"+key, params[key]); err != nil {
			return nil, err
		}
	}
	if len(tagRows) == 1 {
		part, err := form.CreateFormFile("tag_lookup", "tag_lookup")
		if err != nil {
			return nil, err
		}
		if _, err := part.Write(tagRows[0]); err != nil {
			return nil, err
		}
	}
	if err := form.Close(); err != nil {
		return nil, err
	}
	endpoint := c.laneBase(lane, target.BaseURL) + "/?" + tenantSettingName + "=" + url.QueryEscape(tenant) + "&wait_end_of_query=1"
	if len(tagRows) == 1 {
		// The external table schema is fixed code, never a tenant-controlled
		// identifier or value. Its rows live only in the TLS multipart body.
		endpoint += "&tag_lookup_format=JSONEachRow&tag_lookup_structure=" +
			url.QueryEscape("lookup_tenant String, lookup_exporter String, tag_values Map(String, String)")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", form.FormDataContentType())
	response, err := lane.Conn.DoBudgetedQuery(lane.Key, request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	raw, err := chclient.ReadResponseBodyBounded(response.Body, explorerBudgetFor(ctx).ResponseBytes)
	if err != nil {
		return nil, err
	}
	if response.StatusCode/100 != 2 {
		// Server errors can contain SQL or literal values. Public errors/logs use
		// only the code; never echo the raw ClickHouse body or bound metadata.
		code := response.Header.Get("X-ClickHouse-Exception-Code")
		if code == "158" || code == "159" || code == "160" || code == "202" || code == "241" || code == "307" || code == "396" || code == "191" {
			return nil, ErrExplorerBudget
		}
		return nil, fmt.Errorf("flow query store status %d (code %s)", response.StatusCode, code)
	}
	rows, err := chclient.Decode(raw)
	if err != nil {
		return nil, errors.New("flow query store returned an invalid response")
	}
	return rows, nil
}

func explorerAddressExpr(column string) string {
	return "replaceRegexpOne(ifNull(toString(toIPv6OrNull(" + column + "))," + column + "),'^::ffff:','')"
}

func explorerFieldExprWithParams(field flow.QueryField, params chParams) string {
	if field.Derived == "tenant_tag" {
		if params == nil || field.TagID == "" || field.TagKey == "" {
			return "''"
		}
		name := "tag_key_" + strings.ReplaceAll(field.TagID, "-", "")
		if subject, key, qualified := strings.Cut(field.TagKey, "."); qualified {
			name += "_" + subject
			switch subject {
			case "in_interface", "out_interface":
				column := "in_if"
				if subject == "out_interface" {
					column = "out_if"
				}
				params[name] = key
				return "ifNull(tag_values[concat('interface.',toString(" + column + "),'.',{" + name + ":String})],'')"
			case "device", "agent":
			default:
				return "''"
			}
		}
		params[name] = field.TagKey
		return "ifNull(tag_values[{" + name + ":String}],'')"
	}
	column := field.Column
	switch field.Derived {
	case "src_prefix", "dst_prefix":
		address := explorerAddressExpr(column)
		return "if(isIPv4String(" + address + "),concat(toString(tupleElement(IPv4CIDRToRange(toIPv4OrDefault(" + address + "),{prefix4:UInt8}),1)),'/',toString({prefix4:UInt8})),if(isIPv6String(" + address + "),concat(toString(tupleElement(IPv6CIDRToRange(toIPv6OrDefault(" + address + "),{prefix6:UInt8}),1)),'/',toString({prefix6:UInt8})),''))"
	case "dscp":
		return "bitShiftRight(tos,2)"
	case "tcp_flag_names":
		return "if(tcp_flags=0,'NONE',arrayStringConcat(arrayMap(x->x.1,arrayFilter(x->bitAnd(tcp_flags,x.2)!=0,[('FIN',1),('SYN',2),('RST',4),('PSH',8),('ACK',16),('URG',32),('ECE',64),('CWR',128)])),','))"
	case "in_if_name", "out_if_name":
		return "if(arrayFirst(x->x.1=exporter AND x.2=" + column + ",JSONExtract({interfaces:String},'Array(Tuple(String, UInt32, String))')).3!='',arrayFirst(x->x.1=exporter AND x.2=" + column + ",JSONExtract({interfaces:String},'Array(Tuple(String, UInt32, String))')).3,concat('unmapped:',exporter,'#',toString(" + column + ")))"
	}
	if field.Type == flow.QueryAddress {
		return explorerAddressExpr(column)
	}
	return column
}

func explorerGroupExprWithParams(field flow.QueryField, params chParams) string {
	expression := explorerFieldExprWithParams(field, params)
	if field.Type == flow.QueryTimestamp {
		return "concat(formatDateTime(" + expression + ",'%Y-%m-%dT%H:%i:%S','UTC'),if(toUnixTimestamp64Milli(" + expression + ")%1000=0,'',concat('.',replaceRegexpOne(leftPad(toString(toUnixTimestamp64Milli(" + expression + ")%1000),3,'0'),'0+$',''))),'Z')"
	}
	return "ifNull(toString(" + expression + "),'')"
}

func explorerPredicateSQL(predicate flow.QueryPredicate, index int, params chParams) (string, error) {
	return explorerPredicateSQLWithVocabulary(predicate, index, params, flow.QueryVocabulary{})
}

func explorerPredicateSQLWithVocabulary(predicate flow.QueryPredicate, index int,
	params chParams, vocabulary flow.QueryVocabulary) (string, error) {
	field, ok := vocabulary.Lookup(predicate.Field)
	if !ok {
		return "", errors.New("unsupported flow field")
	}
	expression := explorerFieldExprWithParams(field, params)
	typ := "String"
	if field.Type == flow.QueryUnsigned {
		typ = "UInt64"
	}
	if field.Type == flow.QueryTimestamp {
		typ = "DateTime64(9,'UTC')"
	}
	bound := []string{}
	for i, value := range predicate.Values {
		name := fmt.Sprintf("filter_%d_%d", index, i)
		if field.Type == flow.QueryTimestamp {
			ts, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return "", err
			}
			value = ts.Format("2006-01-02 15:04:05.999999999")
		}
		params[name] = value
		bound = append(bound, "{"+name+":"+typ+"}")
	}
	join := func(op string) string {
		parts := []string{}
		for _, v := range bound {
			parts = append(parts, expression+op+v)
		}
		return "(" + strings.Join(parts, " OR ") + ")"
	}
	switch predicate.Op {
	case flow.QueryContains, flow.QueryNotContains:
		op := ">0"
		if predicate.Op == flow.QueryNotContains {
			op = "=0"
		}
		return "positionCaseInsensitiveUTF8(toString(" + expression + ")," + bound[0] + ")" + op, nil
	case flow.QueryRegex, flow.QueryNotRegex:
		result := "match(toString(" + expression + ")," + bound[0] + ")"
		if predicate.Op == flow.QueryNotRegex {
			result = "NOT " + result
		}
		return result, nil
	case flow.QueryGreater:
		return "(" + expression + ">" + bound[0] + ")", nil
	case flow.QueryLess:
		return "(" + expression + "<" + bound[0] + ")", nil
	case flow.QueryBitAnd:
		column := expression
		if field.Type == flow.QueryFlags {
			column = "tcp_flags"
			name := fmt.Sprintf("bit_mask_%d", index)
			params[name] = predicate.Values[0]
			return "bitAnd(" + column + ",{" + name + ":UInt8})!=0", nil
		}
		return "bitAnd(" + column + "," + bound[0] + ")!=0", nil
	case flow.QueryEqual, flow.QueryIn:
		return join("="), nil
	case flow.QueryNotEqual, flow.QueryNotIn:
		return "NOT " + join("="), nil
	case flow.QueryBetween:
		return "(" + expression + ">=" + bound[0] + " AND " + expression + "<=" + bound[1] + ")", nil
	case flow.QueryNotBetween:
		return "NOT (" + expression + ">=" + bound[0] + " AND " + expression + "<=" + bound[1] + ")", nil
	case flow.QueryCIDR, flow.QueryNotCIDR:
		parts := []string{}
		for _, v := range bound {
			parts = append(parts, "("+expression+"!='' AND isIPAddressInRange(if("+expression+"='','0.0.0.0',"+expression+"),"+v+"))")
		}
		result := "(" + strings.Join(parts, " OR ") + ")"
		if predicate.Op == flow.QueryNotCIDR {
			result = "NOT " + result
		}
		return result, nil
	case flow.QueryHasAnyFlag, flow.QueryHasNoFlag:
		mask := 0
		for _, name := range predicate.Values {
			for bit, flag := range []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"} {
				if name == flag {
					mask |= 1 << bit
				}
			}
		}
		name := fmt.Sprintf("flag_mask_%d", index)
		params[name] = strconv.Itoa(mask)
		op := "!="
		if predicate.Op == flow.QueryHasNoFlag {
			op = "="
		}
		return "bitAnd(tcp_flags,{" + name + ":UInt8})" + op + "0", nil
	default:
		return "", errors.New("unsupported flow operator")
	}
}

var explorerTablePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`)
