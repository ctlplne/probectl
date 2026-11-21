// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

var errIRRInput = errors.New("invalid original IRR route object")
var errIRRBudget = errors.New("IRR snapshot exceeds resource admission")

type irrRouteObject struct {
	Origin     uint32
	ModifiedAt time.Time
}

type irrRouteRecord struct {
	prefix   netip.Prefix
	object   irrRouteObject
	source   string
	selected bool
	started  bool
	last     string
}

// parseIRRRPSL retains only exact prefix-origin identities and source clocks.
// The caller verifies the digest and publisher metadata for the whole export.
func parseIRRRPSL(ctx context.Context, input io.Reader, source string, generated time.Time, memoryBytes, workUnits int64) (map[netip.Prefix][]irrRouteObject, error) {
	const maxLine = 64 << 10
	const objectBytes = 256
	if memoryBytes < maxLine+objectBytes || workUnits <= 0 {
		return nil, errIRRBudget
	}
	index := make(map[netip.Prefix][]irrRouteObject)
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), maxLine)
	memoryBytes -= maxLine
	var current irrRouteRecord
	publish := func() error {
		record := current
		current = irrRouteRecord{}
		if !record.selected {
			return nil
		}
		if !record.prefix.IsValid() || record.object.Origin == 0 || record.source != source || record.object.ModifiedAt.After(generated) {
			return errIRRInput
		}
		if memoryBytes < objectBytes || workUnits < objectBytes {
			return errIRRBudget
		}
		memoryBytes -= objectBytes
		workUnits -= objectBytes
		index[record.prefix] = append(index[record.prefix], record.object)
		return nil
	}
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		workUnits -= int64(len(scanner.Bytes())) + 1
		if workUnits < 0 {
			return nil, errIRRBudget
		}
		line, _, comment := strings.Cut(scanner.Text(), "#")
		if strings.TrimSpace(line) == "" {
			if comment {
				continue
			}
			if err := publish(); err != nil {
				return nil, err
			}
			continue
		}
		if err := current.readLine(line); err != nil {
			return nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if err := publish(); err != nil {
		return nil, err
	}
	for prefix, objects := range index {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		slices.SortFunc(objects, func(a, b irrRouteObject) int {
			return cmp.Compare(a.Origin, b.Origin)
		})
		for i := 1; i < len(objects); i++ {
			if objects[i-1].Origin == objects[i].Origin {
				return nil, errIRRInput
			}
		}
		index[prefix] = objects
	}
	return index, ctx.Err()
}

func (r *irrRouteRecord) readLine(line string) error {
	switch line[0] {
	case '%':
		return nil
	case ' ', '\t', '+':
		if !r.started || r.selected && (r.last == "route" || r.last == "route6" || r.last == "origin" || r.last == "source" || r.last == "last-modified") {
			return errIRRInput
		}
		return nil
	}
	key, value, ok := strings.Cut(line, ":")
	if !ok || key == "" {
		return errIRRInput
	}
	key, value = strings.ToLower(strings.TrimRight(key, " \t")), strings.TrimSpace(value)
	first := !r.started
	if first {
		r.started, r.selected = true, key == "route" || key == "route6"
	}
	if !r.selected {
		return nil
	}
	r.last = key
	switch key {
	case "route", "route6":
		prefix, err := netip.ParsePrefix(value)
		if !first || err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Is4() != (key == "route") {
			return errIRRInput
		}
		r.prefix = prefix
	case "origin":
		if r.object.Origin != 0 || len(value) < 3 || !strings.EqualFold(value[:2], "AS") {
			return errIRRInput
		}
		number, err := strconv.ParseUint(value[2:], 10, 32)
		if err != nil || number == 0 || number == 23456 {
			return errIRRInput
		}
		r.object.Origin = uint32(number)
	case "source":
		if r.source != "" || value == "" {
			return errIRRInput
		}
		r.source = strings.ToUpper(value)
	case "last-modified":
		clock, err := time.Parse(time.RFC3339, value)
		if err != nil || clock.IsZero() || !r.object.ModifiedAt.IsZero() {
			return errIRRInput
		}
		r.object.ModifiedAt = clock.UTC()
	}
	return nil
}
