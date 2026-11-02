// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"bytes"
	"encoding/json"
)

// The pinned LibreNMS 26.10.2 QueryBuilderParser generates this query for
// the one supported port-status builder. Requiring exact equality means a
// hand-edited query or an extra predicate cannot look like the finite rule.
// This constant is only a source classifier: no source SQL is ever executed.
const libreNMSPortDownQuery = `SELECT * FROM devices,ports WHERE (devices.device_id = ? AND devices.device_id = ports.device_id) AND ports.ifOperStatus != "up"`

// finiteLibreNMSPortDownDevice recognizes one inert source-rule candidate.
// It returns only a canonical source device ID. The importer still marks the
// rule expression unmapped until an operator-reviewed, disabled native alert
// destination, exact device-agent target and provenance are implemented.
func finiteLibreNMSPortDownDevice(rule libreNMSRule) string {
	if rule.Severity != "warning" && rule.Severity != "critical" ||
		rule.Query != libreNMSPortDownQuery ||
		len(rule.Devices) > 64 || len(rule.Extra) > 256 ||
		len(rule.Builder) > 2048 ||
		!rawBool(rule.Disabled, true) || !rawBool(rule.InvertMap, false) ||
		!rawEmptyArray(rule.Groups) || !rawEmptyArray(rule.Locations) {
		return ""
	}
	var devices []sourceID
	if json.Unmarshal(rule.Devices, &devices) != nil || len(devices) != 1 ||
		devices[0] == "" || devices[0] == "0" {
		return ""
	}
	var extra struct {
		Options map[string]json.RawMessage `json:"options"`
	}
	if json.Unmarshal(rule.Extra, &extra) != nil || len(extra.Options) != 1 ||
		!bytes.Equal(bytes.TrimSpace(extra.Options["override_query"]), []byte("false")) {
		return ""
	}
	var builder map[string]json.RawMessage
	if json.Unmarshal(rule.Builder, &builder) != nil || len(builder) < 2 || len(builder) > 3 ||
		!rawString(builder["condition"], "AND") ||
		(len(builder) == 3 && !rawBool(builder["valid"], true)) {
		return ""
	}
	var conditions []map[string]json.RawMessage
	if json.Unmarshal(builder["rules"], &conditions) != nil || len(conditions) != 1 {
		return ""
	}
	condition := conditions[0]
	if len(condition) != 6 || !rawString(condition["id"], "ports.ifOperStatus") ||
		!rawString(condition["field"], "ports.ifOperStatus") ||
		!rawString(condition["type"], "string") ||
		!rawString(condition["input"], "text") ||
		!rawString(condition["operator"], "not_equal") ||
		!rawString(condition["value"], "up") {
		return ""
	}
	return string(devices[0])
}

func rawBool(raw json.RawMessage, want bool) bool {
	value := bytes.TrimSpace(raw)
	if want {
		return bytes.Equal(value, []byte("true")) || bytes.Equal(value, []byte("1"))
	}
	return bytes.Equal(value, []byte("false")) || bytes.Equal(value, []byte("0"))
}

func rawEmptyArray(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("[]"))
}

func rawString(raw json.RawMessage, want string) bool {
	var value string
	return json.Unmarshal(raw, &value) == nil && value == want
}
