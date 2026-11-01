// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"io"
	"strings"
)

// PRTG API v2 experimental device/group lists return arrays of tree nodes.
// A future caller must follow Link pagination, capture probes as well, and resolve
// every parent by ID before preview can propose a destination group or site.
// These endpoints remain versioned preview until a live trial is available.
func parsePRTGDevices(r io.Reader) (Snapshot, error) { return parsePRTGTreePage(r, "device") }
func parsePRTGGroups(r io.Reader) (Snapshot, error)  { return parsePRTGTreePage(r, "group") }
func parsePRTGProbes(r io.Reader) (Snapshot, error)  { return parsePRTGTreePage(r, "probe") }

func parsePRTGTreePage(r io.Reader, kind string) (Snapshot, error) {
	var page []struct {
		ID       sourceID `json:"id"`
		ParentID sourceID `json:"parentid"`
		Name     string   `json:"name"`
		Basic    struct {
			Host string `json:"host"`
		} `json:"basic"`
	}
	if err := decodePage(r, &page); err != nil || page == nil || len(page) > 3000 {
		return Snapshot{}, ErrInvalidPage
	}
	out := Snapshot{Source: PRTG, Rows: make([]Row, 0, len(page))}
	seen := make(map[string]struct{}, len(page))
	for _, object := range page {
		id := string(object.ID)
		if id == "" || id == "0" {
			return Snapshot{}, ErrInvalidPage
		}
		if _, duplicate := seen[id]; duplicate {
			return Snapshot{}, ErrInvalidPage
		}
		seen[id] = struct{}{}
		row := Row{Kind: kind, ExternalID: id, ParentID: string(object.ParentID),
			Label: safeLabel(object.Name), UnmappedCodes: []string{"parent_unresolved", "site_unmapped"}}
		if row.Label == "" {
			row.UnmappedCodes = append(row.UnmappedCodes, "missing_safe_label")
		}
		if row.ParentID == "" {
			row.UnmappedCodes = append(row.UnmappedCodes, "parent_id_unavailable")
		}
		if kind == "device" {
			row.Address = safeAddress(object.Basic.Host)
			if row.Address == "" {
				row.Hostname = safeDNSHost(object.Basic.Host)
				if row.Hostname == "" {
					row.UnmappedCodes = append(row.UnmappedCodes, "host_unmapped")
				} else {
					row.UnmappedCodes = append(row.UnmappedCodes, "dns_host_unmapped")
				}
			}
		}
		out.Rows = append(out.Rows, row)
	}
	return out, nil
}

// safeDNSHost preserves only a hostname candidate for review. It never
// resolves DNS, treats a source string as a URL or confers sender authority.
func safeDNSHost(raw string) string {
	host := strings.TrimSuffix(strings.TrimSpace(raw), ".")
	if host == "" || len(host) > 253 {
		return ""
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
				(char < '0' || char > '9') && char != '-' {
				return ""
			}
		}
	}
	return strings.ToLower(host)
}
