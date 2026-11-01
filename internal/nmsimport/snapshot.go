// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package nmsimport decodes bounded, untrusted NMS source pages into safe
// candidate rows. It never grants a source tenant, routing-context or agent
// authority; the tenant-scoped apply path owns those decisions.
package nmsimport

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A source page is independently bounded. Callers can request more pages;
// this is not a total inventory cap or a limit on the number of imports.
const maxPageBytes = 64 << 20

var ErrInvalidPage = errors.New("nmsimport: invalid source page")

// Kind identifies only the source format. It does not identify a tenant or
// authorize network access to that source.
type Kind string

const (
	LibreNMS Kind = "librenms"
	Zabbix   Kind = "zabbix"
	Orion    Kind = "orion"
	PRTG     Kind = "prtg"
)

// Row is an allowlisted preview candidate. Arbitrary source JSON, macros,
// community strings, alert expressions and notification targets are never
// copied into this type. Group and site labels do not select a VRF.
type Row struct {
	Kind          string   `json:"kind"`
	ExternalID    string   `json:"external_id"`
	Label         string   `json:"label,omitempty"`
	Address       string   `json:"address,omitempty"`
	Hostname      string   `json:"hostname,omitempty"`
	LocationID    string   `json:"location_id,omitempty"`
	LocationLabel string   `json:"location_label,omitempty"`
	ParentID      string   `json:"parent_id,omitempty"`
	GroupIDs      []string `json:"group_ids,omitempty"`
	PollSeconds   int64    `json:"poll_seconds,omitempty"`
	Severity      string   `json:"severity,omitempty"`
	UnmappedCodes []string `json:"unmapped_codes,omitempty"`
}

// Snapshot is source evidence for a later tenant-bound dry run. The source
// generation and tenant/context binding are supplied by the preview service,
// never by the untrusted export or a device address.
type Snapshot struct {
	Source  Kind   `json:"source"`
	Version string `json:"version,omitempty"`
	Rows    []Row  `json:"rows"`
}

func decodePage(r io.Reader, target any) error {
	data, err := io.ReadAll(io.LimitReader(r, maxPageBytes+1))
	if err != nil || len(data) > maxPageBytes || !utf8.Valid(data) {
		return ErrInvalidPage
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return ErrInvalidPage
	}
	if decoder.Decode(new(any)) != io.EOF {
		return ErrInvalidPage
	}
	return nil
}

// sourceID accepts documented numeric strings or integers and canonicalizes
// leading zeroes. Required IDs reject zero at their call sites; optional site
// and operation IDs may use it. Invalid forms never appear in error text.
type sourceID string

func (id *sourceID) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*id = ""
		return nil
	}
	var text string
	if len(data) > 0 && data[0] == '"' {
		if err := json.Unmarshal(data, &text); err != nil {
			return ErrInvalidPage
		}
	} else {
		text = string(data)
	}
	text = strings.TrimSpace(text)
	if text == "" || len(text) > 256 {
		return ErrInvalidPage
	}
	n, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return ErrInvalidPage
	}
	*id = sourceID(strconv.FormatUint(n, 10))
	return nil
}

func safeLabel(text string) string {
	text = strings.TrimSpace(text)
	if len(text) > 256 {
		return ""
	}
	for _, r := range text {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return text
}

func safeAddress(text string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(text))
	if err != nil || addr.Zone() != "" {
		return ""
	}
	return addr.Unmap().String()
}

// Zabbix's exported group/item/trigger UUIDs are 32 hex digits. Never copy
// arbitrary source text into an identifier that preview or provenance echoes.
func safeZabbixUUID(raw string) string {
	if len(raw) != 32 {
		return ""
	}
	for _, char := range raw {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') && (char < 'A' || char > 'F') {
			return ""
		}
	}
	return strings.ToLower(raw)
}

type libreNMSDevice struct {
	ID         sourceID `json:"device_id"`
	Hostname   string   `json:"hostname"`
	Display    string   `json:"display"`
	IP         string   `json:"ip"`
	LocationID sourceID `json:"location_id"`
}

func libreNMSDeviceRow(device libreNMSDevice) (Row, error) {
	if device.ID == "" || device.ID == "0" {
		return Row{}, ErrInvalidPage
	}
	label := safeLabel(device.Display)
	if label == "" {
		label = safeLabel(device.Hostname)
	}
	row := Row{Kind: "device", ExternalID: string(device.ID), Label: label,
		Address: safeAddress(device.IP), LocationID: string(device.LocationID)}
	if row.LocationID == "0" {
		row.LocationID = ""
	}
	if row.Address == "" {
		row.Address = safeAddress(device.Hostname)
	}
	if row.Address == "" {
		row.UnmappedCodes = append(row.UnmappedCodes, "missing_ip_address")
	}
	if row.Label == "" {
		row.UnmappedCodes = append(row.UnmappedCodes, "missing_safe_label")
	}
	if row.LocationID == "" {
		row.UnmappedCodes = append(row.UnmappedCodes, "site_unmapped")
	}
	return row, nil
}

// parseLibreNMSDevices reads one documented /api/v0/devices response. The
// caller captures and snapshots the source before applying anything; this parser
// retains source IDs and safe display fields but ignores credential fields.
func parseLibreNMSDevices(r io.Reader) (Snapshot, error) {
	var page struct {
		Status  string           `json:"status"`
		Devices []libreNMSDevice `json:"devices"`
	}
	if err := decodePage(r, &page); err != nil || page.Status != "ok" || page.Devices == nil {
		return Snapshot{}, ErrInvalidPage
	}
	out := Snapshot{Source: LibreNMS, Rows: make([]Row, 0, len(page.Devices))}
	seen := make(map[string]struct{}, len(page.Devices))
	for _, device := range page.Devices {
		row, err := libreNMSDeviceRow(device)
		if err != nil {
			return Snapshot{}, ErrInvalidPage
		}
		if _, duplicate := seen[row.ExternalID]; duplicate {
			return Snapshot{}, ErrInvalidPage
		}
		seen[row.ExternalID] = struct{}{}
		out.Rows = append(out.Rows, row)
	}
	return out, nil
}

// parseLibreNMSGroups reads the documented array-wrapped devicegroups list.
// Membership is fetched through a separate endpoint, so every row records
// that it is still missing; a dynamic predicate is never executed or copied.
func parseLibreNMSGroups(r io.Reader) (Snapshot, error) {
	var page []struct {
		Status string `json:"status"`
		Groups []struct {
			ID      sourceID        `json:"id"`
			Name    string          `json:"name"`
			Pattern json.RawMessage `json:"pattern"`
		} `json:"groups"`
	}
	if err := decodePage(r, &page); err != nil || len(page) != 1 || page[0].Status != "ok" || page[0].Groups == nil {
		return Snapshot{}, ErrInvalidPage
	}
	out := Snapshot{Source: LibreNMS, Rows: make([]Row, 0, len(page[0].Groups))}
	seen := make(map[string]struct{}, len(page[0].Groups))
	for _, group := range page[0].Groups {
		id := string(group.ID)
		if id == "" || id == "0" {
			return Snapshot{}, ErrInvalidPage
		}
		if _, duplicate := seen[id]; duplicate {
			return Snapshot{}, ErrInvalidPage
		}
		seen[id] = struct{}{}
		row := Row{Kind: "group", ExternalID: id, Label: safeLabel(group.Name),
			UnmappedCodes: []string{"membership_not_captured"}}
		if row.Label == "" {
			row.UnmappedCodes = append(row.UnmappedCodes, "missing_safe_label")
		}
		var pattern string
		if len(group.Pattern) != 0 && string(group.Pattern) != "null" {
			if json.Unmarshal(group.Pattern, &pattern) != nil {
				return Snapshot{}, ErrInvalidPage
			}
			if strings.TrimSpace(pattern) != "" {
				row.UnmappedCodes = append(row.UnmappedCodes, "dynamic_predicate_unmapped")
			}
		}
		out.Rows = append(out.Rows, row)
	}
	return out, nil
}

// parseLibreNMSRules reads /api/v0/rules without retaining the source rule
// expression, extra JSON, operation, transport, runbook URL or credentials.
// No rule is considered mapped until an explicit finite rule compiler exists.
func parseLibreNMSRules(r io.Reader) (Snapshot, error) {
	var page struct {
		Status string `json:"status"`
		Rules  []struct {
			ID               sourceID        `json:"id"`
			Name             string          `json:"name"`
			Severity         string          `json:"severity"`
			AlertOperationID sourceID        `json:"alert_operation_id"`
			Operations       json.RawMessage `json:"operations"`
		} `json:"rules"`
	}
	if err := decodePage(r, &page); err != nil || page.Status != "ok" || page.Rules == nil {
		return Snapshot{}, ErrInvalidPage
	}
	out := Snapshot{Source: LibreNMS, Rows: make([]Row, 0, len(page.Rules))}
	seen := make(map[string]struct{}, len(page.Rules))
	for _, rule := range page.Rules {
		id := string(rule.ID)
		if id == "" || id == "0" {
			return Snapshot{}, ErrInvalidPage
		}
		if _, duplicate := seen[id]; duplicate {
			return Snapshot{}, ErrInvalidPage
		}
		seen[id] = struct{}{}
		row := Row{Kind: "rule", ExternalID: id, Label: safeLabel(rule.Name),
			UnmappedCodes: []string{"expression_unmapped"}}
		if row.Label == "" {
			row.UnmappedCodes = append(row.UnmappedCodes, "missing_safe_label")
		}
		switch strings.ToLower(strings.TrimSpace(rule.Severity)) {
		case "ok", "warning", "critical":
			row.Severity = strings.ToLower(strings.TrimSpace(rule.Severity))
		default:
			row.UnmappedCodes = append(row.UnmappedCodes, "severity_unmapped")
		}
		if rule.AlertOperationID != "" && rule.AlertOperationID != "0" {
			row.UnmappedCodes = append(row.UnmappedCodes, "delivery_unmapped")
		} else if operations := bytes.TrimSpace(rule.Operations); len(operations) != 0 && string(operations) != "null" && string(operations) != "[]" {
			row.UnmappedCodes = append(row.UnmappedCodes, "delivery_unmapped")
		}
		out.Rows = append(out.Rows, row)
	}
	return out, nil
}

// parseZabbixHosts reads one JSON host configuration export. The documented
// JSON form is sufficient to carry host, group and direct-trigger metadata;
// YAML/XML are separate adapters. Macro values and trigger expressions are
// never decoded into the safe snapshot or error text.
func parseZabbixHosts(r io.Reader) (Snapshot, error) {
	var export struct {
		Zabbix struct {
			Version string `json:"version"`
			Groups  []struct {
				UUID string `json:"uuid"`
				Name string `json:"name"`
			} `json:"host_groups"`
			Hosts []struct {
				Host   string `json:"host"`
				Name   string `json:"name"`
				Groups []struct {
					Name string `json:"name"`
				} `json:"groups"`
				Interfaces []struct {
					IP      string `json:"ip"`
					Default string `json:"default"`
					UseIP   string `json:"useip"`
				} `json:"interfaces"`
				Items []struct {
					UUID     string `json:"uuid"`
					Triggers []struct {
						UUID string `json:"uuid"`
					} `json:"triggers"`
				} `json:"items"`
			} `json:"hosts"`
		} `json:"zabbix_export"`
	}
	if err := decodePage(r, &export); err != nil || export.Zabbix.Version == "" || export.Zabbix.Hosts == nil {
		return Snapshot{}, ErrInvalidPage
	}
	out := Snapshot{Source: Zabbix, Version: safeLabel(export.Zabbix.Version)}
	if out.Version == "" {
		return Snapshot{}, ErrInvalidPage
	}
	groupIDs := make(map[string]string, len(export.Zabbix.Groups))
	seenGroupIDs := make(map[string]struct{}, len(export.Zabbix.Groups))
	for _, group := range export.Zabbix.Groups {
		id, name := safeZabbixUUID(group.UUID), safeLabel(group.Name)
		if id == "" || name == "" {
			return Snapshot{}, ErrInvalidPage
		}
		if _, exists := groupIDs[name]; exists {
			return Snapshot{}, ErrInvalidPage
		}
		if _, duplicate := seenGroupIDs[id]; duplicate {
			return Snapshot{}, ErrInvalidPage
		}
		seenGroupIDs[id] = struct{}{}
		groupIDs[name] = id
		out.Rows = append(out.Rows, Row{Kind: "group", ExternalID: id, Label: name})
	}
	seenHostIDs := make(map[string]struct{}, len(export.Zabbix.Hosts))
	for _, host := range export.Zabbix.Hosts {
		id := safeLabel(host.Host)
		if id == "" {
			return Snapshot{}, ErrInvalidPage
		}
		if _, duplicate := seenHostIDs[id]; duplicate {
			return Snapshot{}, ErrInvalidPage
		}
		seenHostIDs[id] = struct{}{}
		label := safeLabel(host.Name)
		if label == "" {
			label = safeLabel(id)
		}
		row := Row{Kind: "device", ExternalID: id, Label: label}
		for _, group := range host.Groups {
			if groupID, ok := groupIDs[group.Name]; ok {
				row.GroupIDs = append(row.GroupIDs, groupID)
			} else {
				row.UnmappedCodes = append(row.UnmappedCodes, "group_unmapped")
			}
		}
		for _, iface := range host.Interfaces {
			if (iface.Default != "" && iface.Default != "1" && iface.Default != "YES") ||
				(iface.UseIP != "" && iface.UseIP != "1" && iface.UseIP != "YES") ||
				safeAddress(iface.IP) == "" {
				continue
			}
			if row.Address != "" && row.Address != safeAddress(iface.IP) {
				row.Address = ""
				row.UnmappedCodes = append(row.UnmappedCodes, "multiple_primary_addresses")
				break
			}
			row.Address = safeAddress(iface.IP)
		}
		if row.Address == "" {
			row.UnmappedCodes = append(row.UnmappedCodes, "missing_ip_address")
		}
		if row.Label == "" {
			row.UnmappedCodes = append(row.UnmappedCodes, "missing_safe_label")
		}
		out.Rows = append(out.Rows, row)
		for _, item := range host.Items {
			itemID := safeZabbixUUID(item.UUID)
			codes := []string{"poll_item_unmapped"}
			if itemID == "" {
				codes = append(codes, "item_id_unavailable")
			}
			out.Rows = append(out.Rows, Row{Kind: "poll_item", ExternalID: itemID,
				UnmappedCodes: codes})
			for _, trigger := range item.Triggers {
				triggerID := safeZabbixUUID(trigger.UUID)
				codes := []string{"expression_unmapped"}
				if triggerID == "" {
					codes = append(codes, "trigger_id_unavailable")
				}
				out.Rows = append(out.Rows, Row{Kind: "rule", ExternalID: triggerID,
					UnmappedCodes: codes})
			}
		}
	}
	return out, nil
}
