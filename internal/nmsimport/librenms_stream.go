// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"encoding/json"
	"io"
	"math"
	"strconv"
	"unicode/utf8"
)

// LibreNMS v0 returns the complete device list without a documented page
// parameter. Bound each JSON value while decoding, then hand off at most one
// capture page at a time. A failed read leaves the caller's plan inert: the
// caller must seal it only after this function returns nil.
func streamLibreNMSDevices(raw io.Reader, emit func(Snapshot) error) error {
	return streamLibreNMSList(raw, "devices", false, func(value json.RawMessage) (Row, error) {
		var device libreNMSDevice
		if json.Unmarshal(value, &device) != nil {
			return Row{}, ErrInvalidPage
		}
		return libreNMSDeviceRow(device)
	}, emit)
}

func streamLibreNMSLocations(raw io.Reader, emit func(Snapshot) error) error {
	return streamLibreNMSList(raw, "locations", false, func(value json.RawMessage) (Row, error) {
		var location libreNMSLocation
		if json.Unmarshal(value, &location) != nil {
			return Row{}, ErrInvalidPage
		}
		return libreNMSLocationRow(location)
	}, emit)
}

func streamLibreNMSGroups(raw io.Reader, emit func(Snapshot) error) error {
	return streamLibreNMSList(raw, "groups", true, func(value json.RawMessage) (Row, error) {
		var group libreNMSGroup
		if json.Unmarshal(value, &group) != nil {
			return Row{}, ErrInvalidPage
		}
		return libreNMSGroupRow(group)
	}, emit)
}

// The documented per-group endpoint returns an array-wrapped, unpaged list
// of device IDs. The caller must supply a group ID from the previously
// captured group list, never this lower-trust response. Each pair stays a
// separate review candidate so the device row's bounded group_ids field
// cannot silently cap membership.
func streamLibreNMSGroupMembers(raw io.Reader, groupID string, emit func(Snapshot) error) error {
	id, err := strconv.ParseUint(groupID, 10, 64)
	if err != nil || id == 0 || strconv.FormatUint(id, 10) != groupID {
		return ErrInvalidPage
	}
	return streamLibreNMSList(raw, "devices", true, func(value json.RawMessage) (Row, error) {
		var member struct {
			DeviceID sourceID `json:"device_id"`
		}
		if json.Unmarshal(value, &member) != nil || member.DeviceID == "" || member.DeviceID == "0" {
			return Row{}, ErrInvalidPage
		}
		return Row{Kind: "membership", ExternalID: groupID + ":" + string(member.DeviceID),
			UnmappedCodes: []string{"group_unmapped"}}, nil
	}, emit)
}

func streamLibreNMSRules(raw io.Reader, emit func(Snapshot) error) error {
	return streamLibreNMSList(raw, "rules", false, func(value json.RawMessage) (Row, error) {
		var rule libreNMSRule
		if json.Unmarshal(value, &rule) != nil {
			return Row{}, ErrInvalidPage
		}
		return libreNMSRuleRow(rule)
	}, emit)
}

// These LibreNMS v0 lists have no documented page parameter. This decoder
// limits each JSON value and commits at most one normalized capture page at a
// time; a failed final status leaves the caller's plan inert until a complete
// retry replays the same prefix. Raw source fields never cross emit.
func streamLibreNMSList(raw io.Reader, listField string, arrayWrapped bool,
	parse func(json.RawMessage) (Row, error), emit func(Snapshot) error) error {
	if raw == nil || parse == nil || emit == nil ||
		(listField != "devices" && listField != "locations" && listField != "groups" && listField != "rules") {
		return ErrInvalidPage
	}
	budget := &captureValueReader{reader: raw}
	decoder := json.NewDecoder(budget)
	budget.reset()
	if arrayWrapped {
		if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
			return ErrInvalidPage
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return ErrInvalidPage
	}
	var status, haveList, haveCount bool
	var haveMessage bool
	var declaredCount, total int64
	for {
		budget.reset()
		if !decoder.More() {
			break
		}
		budget.reset()
		token, err := decoder.Token()
		if err != nil {
			return ErrInvalidPage
		}
		field, ok := token.(string)
		if !ok {
			return ErrInvalidPage
		}
		budget.reset()
		switch field {
		case "status":
			if status || decoder.Decode(&field) != nil || field != "ok" {
				return ErrInvalidPage
			}
			status = true
		case "count":
			if haveCount || decoder.Decode(&declaredCount) != nil || declaredCount < 0 {
				return ErrInvalidPage
			}
			haveCount = true
		case "message":
			if haveMessage || decoder.Decode(&field) != nil {
				return ErrInvalidPage
			}
			haveMessage = true
		case listField:
			if haveList {
				return ErrInvalidPage
			}
			haveList = true
			total, err = streamLibreNMSRows(decoder, budget, parse, emit)
			if err != nil {
				return err
			}
		default:
			return ErrInvalidPage
		}
	}
	budget.reset()
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return ErrInvalidPage
	}
	if arrayWrapped {
		budget.reset()
		if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
			return ErrInvalidPage
		}
	}
	budget.reset()
	if _, err := decoder.Token(); err != io.EOF || !status || !haveList ||
		(haveCount && declaredCount != total) {
		return ErrInvalidPage
	}
	return nil
}

// streamLibreNMSRows emits one bounded normalized page at a time. The caller
// validates the enclosing status and count before it seals any captured pages.
func streamLibreNMSRows(decoder *json.Decoder, budget *captureValueReader,
	parse func(json.RawMessage) (Row, error), emit func(Snapshot) error) (int64, error) {
	if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
		return 0, ErrInvalidPage
	}
	rows := make([]Row, 0, maxCaptureRowsPerPage)
	seen := make(map[string]struct{}, maxCaptureRowsPerPage)
	var total int64
	for {
		budget.reset()
		if !decoder.More() {
			break
		}
		budget.reset()
		var value json.RawMessage
		if decoder.Decode(&value) != nil || len(value) > maxPageBytes || !utf8.Valid(value) {
			return 0, ErrInvalidPage
		}
		row, err := parse(value)
		if err != nil {
			return 0, ErrInvalidPage
		}
		if _, duplicate := seen[row.ExternalID]; duplicate {
			return 0, ErrInvalidPage
		}
		seen[row.ExternalID] = struct{}{}
		rows = append(rows, row)
		if total == math.MaxInt64 {
			return 0, ErrInvalidPage
		}
		total++
		if len(rows) == maxCaptureRowsPerPage {
			if err := emit(Snapshot{Source: LibreNMS, Rows: rows}); err != nil {
				return 0, err
			}
			rows = make([]Row, 0, maxCaptureRowsPerPage)
			seen = make(map[string]struct{}, maxCaptureRowsPerPage)
		}
	}
	budget.reset()
	if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
		return 0, ErrInvalidPage
	}
	// A complete empty source still needs one zero-row receipt before Seal can
	// distinguish it from a source that never captured.
	if len(rows) > 0 || total == 0 {
		if err := emit(Snapshot{Source: LibreNMS, Rows: rows}); err != nil {
			return 0, err
		}
	}
	return total, nil
}

// The JSON decoder may read ahead, but this reader supplies at most 4 KiB at
// once. Resetting the budget per value bounds one decoded object to 64 MiB
// plus that small read-ahead; it does not cap the number of source records.
type captureValueReader struct {
	reader    io.Reader
	remaining int64
}

func (r *captureValueReader) reset() { r.remaining = maxPageBytes }

func (r *captureValueReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, ErrInvalidPage
	}
	if len(p) > 4096 {
		p = p[:4096]
	}
	if int64(len(p)) > r.remaining {
		p = p[:int(r.remaining)]
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	return n, err
}
