// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"strings"

	"github.com/ctlplne/probectl/internal/crypto"
)

const (
	defenseFlowMaximumBytes   = 16 << 20
	defenseFlowMaximumEntries = 2048
)

type defenseFlowExportPage struct {
	ConfigurationZIP string                 `json:"configuration_zip_base64"`
	Member           string                 `json:"member"`
	Format           string                 `json:"format"`
	Records          []string               `json:"records_path"`
	Mapping          SightlineColumnMapping `json:"field_mapping"`
}

// The operator identifies the exact member and fields from their authorized
// backup. The published export mechanism defines the ZIP container and
// protected objects. The importer uses no presumed internal backup layout.
func parseDefenseFlowProtectedObjects(ctx context.Context, input io.Reader) (Snapshot, error) {
	var page defenseFlowExportPage
	if err := decodePage(input, &page); err != nil || page.ConfigurationZIP == "" || !defenseFlowSafePath(page.Member) ||
		len(page.Records) > 8 {
		return Snapshot{}, ErrInvalidPage
	}
	archive, err := io.ReadAll(io.LimitReader(base64.NewDecoder(base64.StdEncoding.Strict(), strings.NewReader(page.ConfigurationZIP)),
		defenseFlowMaximumBytes+1))
	if err != nil || len(archive) == 0 || len(archive) > defenseFlowMaximumBytes {
		return Snapshot{}, ErrInvalidPage
	}
	defer clear(archive)
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	member, err := readDefenseFlowMember(archive, page.Member)
	if err != nil {
		return Snapshot{}, err
	}
	defer clear(member)
	var preview SightlineExportPreview
	switch {
	case page.Format == "csv" && len(page.Records) == 0:
		preview, err = ParseSightlineExport(ctx, bytes.NewReader(member), page.Mapping)
	case page.Format == "json":
		preview, err = parseDefenseFlowRecords(ctx, member, page.Records, page.Mapping)
	default:
		return Snapshot{}, ErrInvalidPage
	}
	if err != nil {
		return Snapshot{}, err
	}
	return defenseFlowPrefixSnapshot(archive, page, preview)
}

func defenseFlowSafePath(name string) bool {
	return name != "." && len(name) <= 512 && fs.ValidPath(name) && !strings.ContainsAny(name, "\\:\x00")
}

// Only one regular member is opened. It is read to EOF in memory for its
// checksum. ZIP paths, irrelevant documents and metadata stay unretained.
func readDefenseFlowMember(raw []byte, name string) ([]byte, error) {
	catalog, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil || len(catalog.File) == 0 || len(catalog.File) > defenseFlowMaximumEntries {
		return nil, ErrInvalidPage
	}
	var selected *zip.File
	seen := make(map[string]bool, len(catalog.File))
	for _, file := range catalog.File {
		normalized := strings.TrimSuffix(file.Name, "/")
		if !defenseFlowSafePath(normalized) || seen[normalized] {
			return nil, ErrInvalidPage
		}
		seen[normalized] = true
		if file.Name == name {
			selected = file
		}
	}
	if selected == nil || !selected.Mode().IsRegular() || selected.UncompressedSize64 == 0 ||
		selected.UncompressedSize64 > defenseFlowMaximumBytes || selected.Flags&1 != 0 {
		return nil, ErrInvalidPage
	}
	unpacked, err := selected.Open()
	if err != nil {
		return nil, ErrInvalidPage
	}
	defer unpacked.Close()
	content, err := io.ReadAll(io.LimitReader(unpacked, defenseFlowMaximumBytes+1))
	if err != nil || len(content) > defenseFlowMaximumBytes || uint64(len(content)) != selected.UncompressedSize64 {
		clear(content)
		return nil, ErrInvalidPage
	}
	return content, nil
}

func parseDefenseFlowRecords(ctx context.Context, raw []byte, path []string, mapping SightlineColumnMapping) (SightlineExportPreview, error) {
	preview := SightlineExportPreview{Mapping: mapping, Prefixes: []SightlinePrefixCandidate{}}
	keys := []string{mapping.ExternalID, mapping.Label, mapping.Prefix}
	if keys[0] == keys[1] || keys[0] == keys[2] || keys[1] == keys[2] {
		return SightlineExportPreview{}, ErrInvalidPage
	}
	for _, key := range keys {
		if !sightlineLabel(key) {
			return SightlineExportPreview{}, ErrInvalidPage
		}
	}
	for _, node := range path {
		object, err := defenseFlowJSONObject(raw)
		if err != nil || !sightlineLabel(node) || len(object[node]) == 0 {
			return SightlineExportPreview{}, ErrInvalidPage
		}
		raw = object[node]
	}
	records := json.NewDecoder(bytes.NewReader(raw))
	if token, err := records.Token(); err != nil || token != json.Delim('[') {
		return SightlineExportPreview{}, ErrInvalidPage
	}
	seen := map[string]struct{}{}
	labels := map[string]string{}
	for records.More() {
		if err := ctx.Err(); err != nil {
			return SightlineExportPreview{}, err
		}
		var record json.RawMessage
		if len(preview.Prefixes) >= maxCaptureRowsPerPage || records.Decode(&record) != nil {
			return SightlineExportPreview{}, ErrInvalidPage
		}
		object, err := defenseFlowJSONObject(record)
		if err != nil {
			return SightlineExportPreview{}, err
		}
		values := make([]string, len(keys))
		for i, key := range keys {
			if json.Unmarshal(object[key], &values[i]) != nil {
				return SightlineExportPreview{}, ErrInvalidPage
			}
		}
		out, err := sightlineCandidate(len(preview.Prefixes)+1, values, [3]int{0, 1, 2})
		if err != nil {
			return SightlineExportPreview{}, err
		}
		key := out.ExternalID + "\x00" + out.Prefix
		_, duplicate := seen[key]
		if previous, exists := labels[out.ExternalID]; duplicate || exists && previous != out.Label {
			return SightlineExportPreview{}, ErrInvalidPage
		}
		seen[key], labels[out.ExternalID] = struct{}{}, out.Label
		preview.Prefixes = append(preview.Prefixes, out)
		preview.UnmappedColumns = max(preview.UnmappedColumns, len(object)-len(keys))
	}
	if token, err := records.Token(); err != nil || token != json.Delim(']') ||
		!jsonDocumentEnded(raw, records) || len(preview.Prefixes) == 0 {
		return SightlineExportPreview{}, ErrInvalidPage
	}
	return preview, ctx.Err()
}

func defenseFlowJSONObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, ErrInvalidPage
	}
	result := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || len(result) >= 128 || len(result[key]) != 0 {
			return nil, ErrInvalidPage
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, ErrInvalidPage
		}
		result[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || !jsonDocumentEnded(raw, decoder) {
		return nil, ErrInvalidPage
	}
	return result, nil
}

func defenseFlowPrefixSnapshot(archive []byte, page defenseFlowExportPage, preview SightlineExportPreview) (Snapshot, error) {
	mapping, err := json.Marshal(struct {
		Archive string
		Member  string
		Format  string
		Records []string
		Fields  SightlineColumnMapping
	}{hex.EncodeToString(crypto.Hash(archive)), page.Member, page.Format, page.Records, page.Mapping})
	if err != nil {
		return Snapshot{}, ErrInvalidPage
	}
	digest := hex.EncodeToString(crypto.Hash(mapping))
	if len(digest) != 64 {
		return Snapshot{}, ErrInvalidPage
	}
	var unmapped []string
	if preview.UnmappedColumns > 0 {
		unmapped = []string{"defenseflow_additional_fields"}
	}
	out := Snapshot{Source: DefenseFlow, Rows: make([]Row, 0, len(preview.Prefixes))}
	for _, item := range preview.Prefixes {
		out.Rows = append(out.Rows, Row{
			Kind: "prefix", ExternalID: item.ExternalID + "|" + item.Prefix, Label: item.Label,
			Address: item.Prefix, SourceMappingDigest: digest, UnmappedCodes: unmapped,
		})
	}
	return out, nil
}
