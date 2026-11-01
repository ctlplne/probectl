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
)

// Row is an allowlisted preview candidate. Arbitrary source JSON, macros,
// community strings, alert expressions and notification targets are never
// copied into this type. Group and site labels do not select a VRF.
type Row struct {
	Kind          string   `json:"kind"`
	ExternalID    string   `json:"external_id"`
	Label         string   `json:"label,omitempty"`
	Address       string   `json:"address,omitempty"`
	LocationID    string   `json:"location_id,omitempty"`
	GroupIDs      []string `json:"group_ids,omitempty"`
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
	if err != nil || len(data) > maxPageBytes {
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

// sourceID accepts the documented JSON string or integer shapes while
// rejecting zero, booleans, floats and unbounded IDs without echoing them.
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
		n, err := strconv.ParseUint(string(data), 10, 64)
		if err != nil {
			return ErrInvalidPage
		}
		text = strconv.FormatUint(n, 10)
	}
	text = strings.TrimSpace(text)
	if text == "" || len(text) > 256 {
		return ErrInvalidPage
	}
	*id = sourceID(text)
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
	if err != nil {
		return ""
	}
	return addr.String()
}

// ParseLibreNMSDevices reads one documented /api/v0/devices response. The
// caller pages and snapshots the source before applying anything; this parser
// retains source IDs and safe display fields but ignores credential fields.
func ParseLibreNMSDevices(r io.Reader) (Snapshot, error) {
	var page struct {
		Status  string `json:"status"`
		Devices []struct {
			ID         sourceID `json:"device_id"`
			Hostname   string   `json:"hostname"`
			Display    string   `json:"display"`
			IP         string   `json:"ip"`
			LocationID sourceID `json:"location_id"`
		} `json:"devices"`
	}
	if err := decodePage(r, &page); err != nil || page.Status != "ok" || page.Devices == nil {
		return Snapshot{}, ErrInvalidPage
	}
	out := Snapshot{Source: LibreNMS, Rows: make([]Row, 0, len(page.Devices))}
	for _, device := range page.Devices {
		if device.ID == "" || device.ID == "0" {
			return Snapshot{}, ErrInvalidPage
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
		out.Rows = append(out.Rows, row)
	}
	return out, nil
}

// ParseZabbixHosts reads one JSON host configuration export. The documented
// JSON form is sufficient to carry host, group and direct-trigger metadata;
// YAML/XML are separate adapters. Macro values and trigger expressions are
// never decoded into the safe snapshot or error text.
func ParseZabbixHosts(r io.Reader) (Snapshot, error) {
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
	for _, group := range export.Zabbix.Groups {
		id, name := strings.TrimSpace(group.UUID), safeLabel(group.Name)
		if id == "" || len(id) > 256 || name == "" {
			return Snapshot{}, ErrInvalidPage
		}
		if _, exists := groupIDs[name]; exists {
			return Snapshot{}, ErrInvalidPage
		}
		groupIDs[name] = id
		out.Rows = append(out.Rows, Row{Kind: "group", ExternalID: id, Label: name})
	}
	for _, host := range export.Zabbix.Hosts {
		id := strings.TrimSpace(host.Host)
		if id == "" || len(id) > 256 {
			return Snapshot{}, ErrInvalidPage
		}
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
			itemID := strings.TrimSpace(item.UUID)
			codes := []string{"poll_item_unmapped"}
			if itemID == "" || len(itemID) > 256 {
				itemID = ""
				codes = append(codes, "item_id_unavailable")
			}
			out.Rows = append(out.Rows, Row{Kind: "poll_item", ExternalID: itemID,
				UnmappedCodes: codes})
			for _, trigger := range item.Triggers {
				triggerID := strings.TrimSpace(trigger.UUID)
				codes := []string{"expression_unmapped"}
				if triggerID == "" || len(triggerID) > 256 {
					triggerID = ""
					codes = append(codes, "trigger_id_unavailable")
				}
				out.Rows = append(out.Rows, Row{Kind: "rule", ExternalID: triggerID,
					UnmappedCodes: codes})
			}
		}
	}
	return out, nil
}
