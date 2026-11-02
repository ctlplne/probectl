// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
)

// planRow is the exact field vocabulary of nms_import_rows. This is not a
// permission to write: a tenant-scoped preview service must derive the tenant
// and context from the authenticated operator and choose the action after a
// forced-RLS lookup. No source row can declare its own destination context.
type planRow struct {
	RowNumber     int64    `json:"row_number"`
	ObjectKind    string   `json:"object_kind"`
	ExternalID    string   `json:"external_id"`
	Label         string   `json:"label"`
	Address       string   `json:"address"`
	Hostname      string   `json:"hostname"`
	ParentID      string   `json:"parent_id"`
	LocationID    string   `json:"location_id"`
	LocationLabel string   `json:"location_label"`
	GroupIDs      []string `json:"group_ids"`
	PollSeconds   int64    `json:"poll_seconds"`
	Severity      string   `json:"severity"`
	UnmappedCodes []string `json:"unmapped_codes"`
	ReviewOnly    bool     `json:"review_only"`
}

var allowedUnmappedCodes = map[string]bool{
	"delivery_unmapped":          true,
	"dns_host_unmapped":          true,
	"dynamic_predicate_unmapped": true,
	"expression_unmapped":        true,
	"group_unmapped":             true,
	"host_unmapped":              true,
	"item_id_unavailable":        true,
	"membership_not_captured":    true,
	"member_removal_candidate":   true,
	"missing_ip_address":         true,
	"missing_safe_label":         true,
	"multiple_primary_addresses": true,
	"parent_id_unavailable":      true,
	"parent_unresolved":          true,
	"poll_interval_unmapped":     true,
	"poll_cadence_conflict":      true,
	"poll_item_unmapped":         true,
	"poll_proposal":              true,
	"poll_settings_unmapped":     true,
	"poll_status_unmapped":       true,
	"poll_transport_unmapped":    true,
	"severity_unmapped":          true,
	"site_unmapped":              true,
	"trigger_id_unavailable":     true,
}

// normalizePlanPage checks every parser output again before it can become a
// stored preview row. firstRow is the global ordinal supplied by the paged
// capture, not a per-page index, so missing IDs stay distinct across pages.
// The resulting rows do not decide create/update or perform a database write.
func normalizePlanPage(tenantID, contextID, sourceInstance, generationHash string,
	sourceKind Kind, snapshot Snapshot, firstRow int64) ([]planRow, error) {
	if id, err := uuid.Parse(tenantID); err != nil || id == uuid.Nil {
		return nil, ErrInvalidPage
	}
	if id, err := uuid.Parse(contextID); err != nil || id == uuid.Nil {
		return nil, ErrInvalidPage
	}
	if !safeInstanceRef(sourceInstance) ||
		len(generationHash) != 64 || !lowerHex(generationHash) || firstRow < 0 ||
		!knownSource(sourceKind) || snapshot.Source != sourceKind ||
		(snapshot.Version != "" && safeLabel(snapshot.Version) != snapshot.Version) {
		return nil, ErrInvalidPage
	}
	result := make([]planRow, 0, len(snapshot.Rows))
	seen := make(map[string]struct{}, len(snapshot.Rows))
	for i, row := range snapshot.Rows {
		if int64(i) > int64(^uint64(0)>>1)-firstRow {
			return nil, ErrInvalidPage
		}
		kind := planKind(row.Kind)
		if kind == "" || !safePlanFields(row, sourceKind) {
			return nil, ErrInvalidPage
		}
		if kind == "membership" && !safeMembershipRow(row, sourceKind) {
			return nil, ErrInvalidPage
		}
		if (row.Label == "" && len(row.UnmappedCodes) == 0) ||
			(kind == "device" && row.Address == "" && row.Hostname == "" &&
				!hasCode(row.UnmappedCodes, "missing_ip_address") &&
				!hasCode(row.UnmappedCodes, "host_unmapped")) {
			return nil, ErrInvalidPage
		}
		id := row.ExternalID
		reviewOnly := len(row.UnmappedCodes) > 0
		if id == "" {
			missingItemID := row.Kind == "poll_item" && hasCode(row.UnmappedCodes, "item_id_unavailable")
			missingTriggerID := row.Kind == "rule" && hasCode(row.UnmappedCodes, "trigger_id_unavailable")
			if snapshot.Source != Zabbix || (!missingItemID && !missingTriggerID) {
				return nil, ErrInvalidPage
			}
			hash := crypto.Default.Hash([]byte("probectl:nms-review-key:v1\x00" + tenantID + "\x00" +
				contextID + "\x00" + string(snapshot.Source) + "\x00" + sourceInstance + "\x00" +
				generationHash + "\x00" + kind + "\x00" + strconv.FormatInt(firstRow+int64(i), 10)))
			if len(hash) < 16 {
				return nil, ErrInvalidPage
			}
			id = "unmapped-" + hex.EncodeToString(hash[:16])
			reviewOnly = true
		}
		key := kind + "\x00" + id
		if _, duplicate := seen[key]; duplicate {
			return nil, ErrInvalidPage
		}
		seen[key] = struct{}{}
		result = append(result, planRow{RowNumber: firstRow + int64(i), ObjectKind: kind,
			ExternalID: id, Label: row.Label, Address: row.Address, Hostname: row.Hostname,
			ParentID: row.ParentID, LocationID: row.LocationID, LocationLabel: row.LocationLabel,
			GroupIDs: canonicalStrings(row.GroupIDs), PollSeconds: row.PollSeconds,
			Severity: row.Severity, UnmappedCodes: canonicalStrings(row.UnmappedCodes),
			ReviewOnly: reviewOnly})
	}
	return result, nil
}

func knownSource(kind Kind) bool {
	switch kind {
	case LibreNMS, Zabbix, Orion, PRTG:
		return true
	default:
		return false
	}
}

func safeInstanceRef(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index, char := range value {
		if (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			(index > 0 && (char == '.' || char == '_' || char == '-')) {
			continue
		}
		return false
	}
	return true
}

func planKind(kind string) string {
	switch kind {
	case "device", "group", "site", "membership":
		return kind
	case "probe":
		return "site"
	case "poll_item":
		return "poll_setting"
	case "rule":
		return "alert_rule"
	default:
		return ""
	}
}

// A membership is an exact group/device pair from one source. The separator
// follows a canonical numeric LibreNMS group ID or a fixed-width Zabbix group
// UUID, so the host key may itself contain a colon without ambiguity.
func safeMembershipID(value string) bool {
	group, device, ok := strings.Cut(value, ":")
	return ok && len(value) <= 256 &&
		(canonicalSourceNumber(group) && canonicalSourceNumber(device) ||
			safeZabbixUUID(group) == group && group != "" &&
				device != "" && safeLabel(device) == device)
}

// Only the parser for the declared source may produce its pair shape. The
// row is review-only until its same-plan group and device are both chosen.
func safeMembershipRow(row Row, source Kind) bool {
	group, device, ok := strings.Cut(row.ExternalID, ":")
	if !ok || !safeMembershipID(row.ExternalID) ||
		(source == LibreNMS && (!canonicalSourceNumber(group) || !canonicalSourceNumber(device))) ||
		(source == Zabbix && (safeZabbixUUID(group) != group || group == "" ||
			device == "" || safeLabel(device) != device)) ||
		(source != LibreNMS && source != Zabbix) {
		return false
	}
	return row.Label == "" && row.Address == "" &&
		row.Hostname == "" && row.ParentID == "" && row.LocationID == "" &&
		row.LocationLabel == "" && len(row.GroupIDs) == 0 && row.PollSeconds == 0 &&
		row.Severity == "" && len(row.UnmappedCodes) == 1 &&
		(row.UnmappedCodes[0] == "group_unmapped" ||
			row.UnmappedCodes[0] == "member_removal_candidate")
}

func canonicalSourceNumber(value string) bool {
	n, err := strconv.ParseUint(value, 10, 64)
	return err == nil && n != 0 && strconv.FormatUint(n, 10) == value
}

func safePlanFields(row Row, source Kind) bool {
	for _, value := range []string{row.ExternalID, row.Label, row.Hostname,
		row.ParentID, row.LocationID, row.LocationLabel} {
		if safeLabel(value) != value {
			return false
		}
	}
	if row.Address != "" && safeAddress(row.Address) != row.Address {
		return false
	}
	// Zabbix's documented host identity is its host key, not a numeric ID.
	// Item and trigger rows retain that safe key so the destination mapper
	// can use same-source device provenance instead of guessing by address.
	parentIsZabbixHost := source == Zabbix && (row.Kind == "poll_item" || row.Kind == "rule")
	if (row.Hostname != "" && safeDNSHost(row.Hostname) != row.Hostname) ||
		(row.ParentID != "" && !parentIsZabbixHost && !lowerHex(row.ParentID)) ||
		(row.LocationID != "" && !lowerHex(row.LocationID)) {
		return false
	}
	if row.PollSeconds < 0 || row.PollSeconds > 604800 || len(row.GroupIDs) > 256 ||
		len(row.UnmappedCodes) > 32 {
		return false
	}
	if row.Severity != "" && row.Severity != "ok" && row.Severity != "warning" && row.Severity != "critical" {
		return false
	}
	groupBytes := 0
	for _, id := range row.GroupIDs {
		groupBytes += len(id)
		if len(id) > 256 || !lowerHex(id) {
			return false
		}
	}
	if groupBytes+len(row.GroupIDs) > 65536 {
		return false
	}
	codeBytes := 0
	for _, code := range row.UnmappedCodes {
		codeBytes += len(code)
		if !allowedUnmappedCodes[code] {
			return false
		}
	}
	return codeBytes+len(row.UnmappedCodes) <= 1024
}

func lowerHex(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return false
		}
	}
	return true
}

func hasCode(codes []string, wanted string) bool {
	for _, code := range codes {
		if code == wanted {
			return true
		}
	}
	return false
}

func canonicalStrings(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}
	out := append([]string(nil), raw...)
	sort.Strings(out)
	unique := out[:0]
	for _, value := range out {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return unique
}
