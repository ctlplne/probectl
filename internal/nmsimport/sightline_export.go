// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/crypto"
)

// SightlineColumnMapping comes from the operator's actual export headers.
// The public vendor overview describes managed objects and protected traffic
// scope. These explicitly chosen fields are part of this preview's provenance.
type SightlineColumnMapping struct {
	ExternalID string `json:"external_id"`
	Label      string `json:"label"`
	Prefix     string `json:"prefix"`
}

type SightlinePrefixCandidate struct {
	Row        int    `json:"row"`
	ExternalID string `json:"external_id"`
	Label      string `json:"label"`
	Prefix     string `json:"prefix"`
}

type SightlineExportPreview struct {
	Mapping         SightlineColumnMapping     `json:"mapping"`
	Prefixes        []SightlinePrefixCandidate `json:"prefixes"`
	UnmappedColumns int                        `json:"unmapped_columns"`
}

var sightlineIdentifier = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:@-]{0,127}$`)

// ParseSightlineExport projects a bounded customer-provided CSV. Its output is
// a preview, so another step selects the destination tenant and context.
func ParseSightlineExport(ctx context.Context, input io.Reader, mapping SightlineColumnMapping) (SightlineExportPreview, error) {
	const maximumBytes = 16 << 20
	const maximumRows = maxCaptureRowsPerPage
	if input == nil {
		return SightlineExportPreview{}, ErrInvalidPage
	}
	if err := ctx.Err(); err != nil {
		return SightlineExportPreview{}, err
	}
	limited := &io.LimitedReader{R: input, N: maximumBytes + 1}
	records := csv.NewReader(limited)
	header, err := records.Read()
	if err != nil {
		return SightlineExportPreview{}, ErrInvalidPage
	}
	fields, err := sightlineFields(header, mapping)
	if err != nil {
		return SightlineExportPreview{}, err
	}
	preview := SightlineExportPreview{Mapping: mapping, Prefixes: []SightlinePrefixCandidate{}, UnmappedColumns: len(header) - 3}
	known := map[string]struct{}{}
	labels := map[string]string{}
	for row := 1; ; row++ {
		if err := ctx.Err(); err != nil {
			return SightlineExportPreview{}, err
		}
		values, err := records.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || row > maximumRows || limited.N <= 0 {
			return SightlineExportPreview{}, ErrInvalidPage
		}
		record, err := sightlineCandidate(row, values, fields)
		if err != nil {
			return SightlineExportPreview{}, err
		}
		key := record.ExternalID + "\x00" + record.Prefix
		if _, conflict := known[key]; conflict {
			return SightlineExportPreview{}, fmt.Errorf("%w: duplicate managed object and prefix in data row %d", ErrInvalidPage, row)
		}
		if previous, exists := labels[record.ExternalID]; exists && previous != record.Label {
			return SightlineExportPreview{}, fmt.Errorf("%w: conflicting managed object labels in data row %d", ErrInvalidPage, row)
		}
		known[key] = struct{}{}
		labels[record.ExternalID] = record.Label
		preview.Prefixes = append(preview.Prefixes, record)
	}
	if limited.N <= 0 || len(preview.Prefixes) == 0 {
		return SightlineExportPreview{}, ErrInvalidPage
	}
	return preview, ctx.Err()
}

func sightlineFields(header []string, mapping SightlineColumnMapping) ([3]int, error) {
	var columns [3]int
	if len(header) > 128 {
		return columns, ErrInvalidPage
	}
	for i, want := range []string{mapping.ExternalID, mapping.Label, mapping.Prefix} {
		if !sightlineLabel(want) {
			return columns, ErrInvalidPage
		}
		columns[i] = -1
		for position, name := range header {
			if position == 0 {
				name = strings.TrimPrefix(name, "\ufeff")
			}
			if name != want {
				continue
			}
			if columns[i] >= 0 {
				return columns, ErrInvalidPage
			}
			columns[i] = position
		}
		if columns[i] < 0 {
			return columns, ErrInvalidPage
		}
	}
	if columns[0] == columns[1] || columns[0] == columns[2] || columns[1] == columns[2] {
		return columns, ErrInvalidPage
	}
	return columns, nil
}

func sightlineCandidate(row int, values []string, fields [3]int) (SightlinePrefixCandidate, error) {
	external, label, network := values[fields[0]], values[fields[1]], values[fields[2]]
	prefix, err := netip.ParsePrefix(network)
	if err != nil || !sightlineIdentifier.MatchString(external) || !sightlineLabel(label) ||
		!sightlineCanonicalPrefix(prefix, network) {
		return SightlinePrefixCandidate{}, fmt.Errorf("%w: invalid managed object data row %d", ErrInvalidPage, row)
	}
	return SightlinePrefixCandidate{Row: row, ExternalID: external, Label: label, Prefix: prefix.String()}, nil
}

func sightlineLabel(text string) bool {
	return text != "" && len(text) <= 160 && utf8.ValidString(text) && strings.TrimSpace(text) == text &&
		strings.IndexFunc(text, unicode.IsControl) < 0
}

func sightlineCanonicalPrefix(prefix netip.Prefix, raw string) bool {
	return prefix.Bits() > 0 && !prefix.Addr().Is4In6() && prefix == prefix.Masked() && prefix.String() == raw
}

// The capture receipt binds the operator mapping and the exact normalized
// rows. Raw vendor CSV and columns outside the mapping are discarded.
func parseSightlineManagedObjects(ctx context.Context, raw io.Reader) (Snapshot, error) {
	var page struct {
		ColumnMapping SightlineColumnMapping `json:"column_mapping"`
		CSV           string                 `json:"csv"`
	}
	if err := decodePage(raw, &page); err != nil {
		return Snapshot{}, err
	}
	preview, err := ParseSightlineExport(ctx, strings.NewReader(page.CSV), page.ColumnMapping)
	if err != nil {
		return Snapshot{}, err
	}
	mapping, err := json.Marshal(page.ColumnMapping)
	if err != nil {
		return Snapshot{}, ErrInvalidPage
	}
	digest := hex.EncodeToString(crypto.Hash(mapping))
	if len(digest) != 64 {
		return Snapshot{}, ErrInvalidPage
	}
	var unmapped []string
	if preview.UnmappedColumns > 0 {
		unmapped = []string{"sightline_additional_columns"}
	}
	result := Snapshot{Source: Sightline, Rows: make([]Row, 0, len(preview.Prefixes))}
	for _, item := range preview.Prefixes {
		result.Rows = append(result.Rows, Row{
			Kind: "prefix", ExternalID: item.ExternalID + "|" + item.Prefix, Label: item.Label,
			Address: item.Prefix, SourceMappingDigest: digest, UnmappedCodes: unmapped,
		})
	}
	return result, nil
}

func prefixExportSource(kind Kind) bool {
	return kind == Sightline || kind == DefenseFlow
}

func safeProtectedPrefixRow(row Row, source Kind) bool {
	vendorID, network, found := strings.Cut(row.ExternalID, "|")
	prefix, err := netip.ParsePrefix(row.Address)
	return found && network == row.Address && sightlineIdentifier.MatchString(vendorID) && err == nil &&
		sightlineCanonicalPrefix(prefix, row.Address) && sightlineLabel(row.Label) &&
		len(row.SourceMappingDigest) == 64 && lowerHex(row.SourceMappingDigest) &&
		row.Hostname == "" && row.ParentID == "" && row.LocationID == "" && row.LocationLabel == "" &&
		len(row.GroupIDs) == 0 && row.PollSeconds == 0 && row.Severity == "" &&
		(len(row.UnmappedCodes) == 0 || len(row.UnmappedCodes) == 1 &&
			(source == Sightline && row.UnmappedCodes[0] == "sightline_additional_columns" ||
				source == DefenseFlow && row.UnmappedCodes[0] == "defenseflow_additional_fields"))
}
