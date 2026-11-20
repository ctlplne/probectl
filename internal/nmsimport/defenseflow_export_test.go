// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDefenseFlowMappedConfigurationArchive(t *testing.T) {
	cases := []struct {
		name, member, data string
		path               []string
	}{
		{"csv", "fixture/objects.csv", "key,name,network,other\nedge-1,Example,192.0.2.0/24,discard-example\n", nil},
		{"json", "fixture/objects.json", `{"inventory":{"entries":[{"key":"edge-1","name":"Example","network":"192.0.2.0/24","private":"discard-example"}]}}`, []string{"inventory", "entries"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page := defenseFlowExportPage{
				ConfigurationZIP: defenseFlowFixtureArchive(t, tc.member, tc.data),
				Member:           tc.member,
				Format:           tc.name,
				Records:          tc.path,
				Mapping:          SightlineColumnMapping{ExternalID: "key", Label: "name", Prefix: "network"},
			}
			parse := func() (Snapshot, error) {
				raw, err := json.Marshal(page)
				if err != nil {
					t.Fatal(err)
				}
				return parseDefenseFlowProtectedObjects(t.Context(), bytes.NewReader(raw))
			}
			result, err := parse()
			if err != nil || result.Source != DefenseFlow || len(result.Rows) != 1 {
				t.Fatal("explicit protected-object mapping lost the documented inventory shape", result, err)
			}
			row := result.Rows[0]
			if row.ExternalID != "edge-1|192.0.2.0/24" || row.Label != "Example" || row.Kind != "prefix" ||
				row.Address != "192.0.2.0/24" || len(row.SourceMappingDigest) != 64 ||
				len(row.UnmappedCodes) != 1 || row.UnmappedCodes[0] != "defenseflow_additional_fields" {
				t.Fatalf("unexpected protected prefix: %+v", row)
			}
			encoded, err := json.Marshal(result)
			if err != nil || strings.Contains(string(encoded), "discard") || strings.Contains(string(encoded), tc.member) {
				t.Fatal("private archive detail survived normalization", err)
			}
			replay, err := parse()
			if err != nil || len(replay.Rows) != 1 || replay.Rows[0].SourceMappingDigest != row.SourceMappingDigest {
				t.Fatal("identical archive replay did not preserve its mapping digest", replay, err)
			}
			page.Member = "fixture/other.txt"
			if invalid, err := parse(); !errors.Is(err, ErrInvalidPage) || len(invalid.Rows) != 0 {
				t.Fatal("selecting an unrelated archive member produced plan rows", invalid, err)
			}
		})
	}
}

func TestDefenseFlowRejectsAmbiguousArchiveInputs(t *testing.T) {
	for _, tc := range []struct {
		name, selected, recorded, body string
	}{
		{"ambiguous JSON fields", "object.json", "object.json", `[{"key":"left","key":"right","name":"Site","network":"192.0.2.0/24"}]`},
		{"path outside the archive root", "../object.json", "../object.json", `[]`},
		{"unselected member", "object.json", "other.json", `[]`},
		{"foreign document shape", "object.json", "object.json", `{"sites":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page := defenseFlowExportPage{
				ConfigurationZIP: defenseFlowFixtureArchive(t, tc.recorded, tc.body),
				Member:           tc.selected,
				Format:           "json",
				Mapping:          SightlineColumnMapping{ExternalID: "key", Label: "name", Prefix: "network"},
			}
			raw, err := json.Marshal(page)
			if err != nil {
				t.Fatal(err)
			}
			if result, err := parseDefenseFlowProtectedObjects(t.Context(), bytes.NewReader(raw)); !errors.Is(err, ErrInvalidPage) || len(result.Rows) != 0 {
				t.Fatal("unreviewable archive produced plan rows", result, err)
			}
		})
	}
}

func defenseFlowFixtureArchive(t *testing.T, member, data string) string {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, record := range [][2]string{{member, data}, {"fixture/other.txt", "discard-other"}} {
		file, err := writer.Create(record[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(record[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buffer.Bytes())
}
