// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"
)

const (
	maxSNMPVendorProfiles = 64
	maxSNMPVendorObjects  = 32
	maxSNMPVendorRows     = 256
)

// SNMPVendorProfile selects original read-only objects on a configured target.
// Numeric sysObjectID arcs are authoritative. A description prefix can narrow
// selection when several products share an identity branch.
type SNMPVendorProfile struct {
	ID             string             `yaml:"id"`
	Vendor         string             `yaml:"vendor"`
	Platform       string             `yaml:"platform"`
	SysObjectID    string             `yaml:"sys_object_id"`
	MatchSubtree   bool               `yaml:"match_subtree,omitempty"`
	SysDescrPrefix string             `yaml:"sys_descr_prefix,omitempty"`
	Objects        []SNMPVendorObject `yaml:"objects"`
}

// SNMPVendorObject declares a scalar instance or a column root. Table rows
// retain the numeric instance index emitted by the device.
type SNMPVendorObject struct {
	MIB             string  `yaml:"mib_object"`
	OID             string  `yaml:"oid"`
	Kind            string  `yaml:"kind"`
	Syntax          string  `yaml:"syntax"`
	Metric          string  `yaml:"metric"`
	Unit            string  `yaml:"unit"`
	Multiplier      float64 `yaml:"multiplier,omitempty"`
	Index           string  `yaml:"index,omitempty"`
	ZeroUnavailable bool    `yaml:"zero_unavailable,omitempty"`
	ValidValues     []int64 `yaml:"valid_values,omitempty"`
}

var (
	snmpProfileID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	snmpMIBSymbol = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}::[A-Za-z][A-Za-z0-9-]{0,63}$`)
)

func normalizeSNMPOID(raw string) (string, bool) {
	const maxOIDLength = 256 // canonical identity fits the device series label bound
	if len(raw) < 3 {
		return "", false
	}
	oid := strings.TrimPrefix(raw, ".")
	if len(oid) >= maxOIDLength {
		return "", false
	}
	var arcs int
	for arc := range strings.SplitSeq(oid, ".") {
		if arc == "" || len(arc) > 10 || len(arc) > 1 && arc[0] == '0' || arc[0] < '0' || arc[0] > '9' {
			return "", false
		}
		value, err := strconv.ParseUint(arc, 10, 32)
		if err != nil || arcs == 0 && value > 2 || arcs == 1 && oid[0] != '2' && value > 39 {
			return "", false
		}
		arcs++
	}
	return "." + oid, arcs >= 2 && arcs <= 128
}

// ValidSNMPMetricSource checks the provenance received on the device bus.
// A reserved selection value and a noncanonical identity cannot mint labels.
func ValidSNMPMetricSource(metric, unit, profile, sysObjectID, mibObject, objectID string) bool {
	sys, sysOK := normalizeSNMPOID(sysObjectID)
	oid, oidOK := normalizeSNMPOID(objectID)
	return unit != "" && vendorMetricUnits[metric] == unit &&
		profile != "auto" && snmpProfileID.MatchString(profile) && snmpMIBSymbol.MatchString(mibObject) &&
		sysOK && oidOK && sys == sysObjectID && oid == objectID
}

func validateSNMPVendorProfiles(profiles []SNMPVendorProfile) error {
	if len(profiles) > maxSNMPVendorProfiles {
		return errors.New("too many SNMP vendor profiles")
	}
	ids := make(map[string]bool, len(profiles))
	for _, profile := range profiles {
		if profile.ID == "auto" || !snmpProfileID.MatchString(profile.ID) || ids[profile.ID] {
			return fmt.Errorf("invalid or duplicate SNMP vendor profile ID %q", profile.ID)
		}
		if err := validateSNMPVendorProfile(profile); err != nil {
			return fmt.Errorf("SNMP vendor profile %q: %w", profile.ID, err)
		}
		ids[profile.ID] = true
	}
	return nil
}

func validateSNMPVendorProfile(profile SNMPVendorProfile) error {
	if _, valid := normalizeSNMPOID(profile.SysObjectID); !valid {
		return errors.New("invalid sys_object_id")
	}
	if profile.Vendor == "" || len(profile.Vendor) > 80 || profile.Platform == "" || len(profile.Platform) > 80 ||
		len(profile.SysDescrPrefix) > 128 || len(profile.Objects) == 0 || len(profile.Objects) > maxSNMPVendorObjects {
		return errors.New("invalid vendor, platform, description prefix or object count")
	}
	seen := make(map[string]bool, len(profile.Objects))
	metrics := make(map[string]bool, len(profile.Objects))
	for _, obj := range profile.Objects {
		oid, valid := normalizeSNMPOID(obj.OID)
		if !valid || seen[oid] || metrics[obj.Metric] || !snmpMIBSymbol.MatchString(obj.MIB) {
			return fmt.Errorf("invalid or duplicate object for %q", obj.MIB)
		}
		if err := validateSNMPVendorObject(obj, oid); err != nil {
			return fmt.Errorf("SNMP object %q: %w", obj.MIB, err)
		}
		seen[oid] = true
		metrics[obj.Metric] = true
	}
	return nil
}

func validateSNMPVendorObject(obj SNMPVendorObject, oid string) error {
	if obj.Kind != "scalar" && obj.Kind != "column" || obj.Kind == "scalar" && !strings.HasSuffix(oid, ".0") {
		return errors.New("expected a scalar instance ending in .0 or a column root")
	}
	if obj.Index != "" && (obj.Kind != "column" || obj.Index != "if_index") {
		return errors.New("if_index requires a documented table column")
	}
	if obj.Syntax != "integer" && obj.Syntax != "gauge32" {
		return errors.New("expected integer or gauge32 syntax")
	}
	if unit := vendorMetricUnits[obj.Metric]; unit == "" || obj.Unit != unit {
		return errors.New("unsupported metric or mismatched unit")
	}
	if obj.Multiplier < 0 || obj.Multiplier > 1e9 || math.IsNaN(obj.Multiplier) {
		return errors.New("invalid reading multiplier")
	}
	if len(obj.ValidValues) > 0 && (obj.Syntax != "integer" || len(obj.ValidValues) > 32 || obj.Multiplier != 0) {
		return errors.New("valid_values requires at most 32 exact signed integer codes")
	}
	for _, value := range obj.ValidValues {
		if value < math.MinInt32 || value > math.MaxInt32 {
			return errors.New("state code is outside the Integer32 range")
		}
	}
	return nil
}

// selectSNMPVendorProfile fails closed on an ambiguous identity. A more
// specific object ID outranks a wider match, and a documented description
// prefix narrows matches on the same identity branch.
func selectSNMPVendorProfile(profiles []SNMPVendorProfile, rawOID, description string) *SNMPVendorProfile {
	oid, ok := normalizeSNMPOID(rawOID)
	if !ok {
		return nil
	}
	best, tied := -1, false
	var score int
	for i, profile := range profiles {
		rank := snmpVendorProfileRank(profile, oid, description)
		switch {
		case rank > score:
			best, score, tied = i, rank, false
		case rank > 0 && rank == score:
			tied = true
		}
	}
	if best < 0 || tied {
		return nil
	}
	return &profiles[best]
}

func snmpVendorProfileRank(profile SNMPVendorProfile, oid, description string) int {
	match, valid := normalizeSNMPOID(profile.SysObjectID)
	if !valid || oid != match && (!profile.MatchSubtree || !strings.HasPrefix(oid, match+".")) ||
		!strings.HasPrefix(description, profile.SysDescrPrefix) {
		return 0
	}
	const descriptionRankRange = 129
	score := len(match) * 2 * descriptionRankRange
	if !profile.MatchSubtree {
		score += descriptionRankRange
	}
	return score + len(profile.SysDescrPrefix)
}

func configureSNMPVendorTargets(devices []Target, custom []SNMPVendorProfile) error {
	profiles := append(slices.Clone(builtinSNMPVendorProfiles), custom...)
	if err := validateSNMPVendorProfiles(profiles); err != nil {
		return err
	}
	for i := range devices {
		if err := configureSNMPVendorTarget(&devices[i], profiles); err != nil {
			return fmt.Errorf("device: devices[%d]: %w", i, err)
		}
	}
	return nil
}

func configureSNMPVendorTarget(target *Target, profiles []SNMPVendorProfile) error {
	target.vendorProfiles = nil
	if target.SNMPVendorProfile == "" {
		return nil
	}
	if target.Transport != TransportSNMPv2c && target.Transport != TransportSNMPv3 {
		return errors.New("snmp_vendor_profile requires an SNMP transport")
	}
	if target.SNMPVendorProfile == "auto" {
		target.vendorProfiles = profiles
		return nil
	}
	for _, profile := range profiles {
		if profile.ID == target.SNMPVendorProfile {
			target.vendorProfiles = []SNMPVendorProfile{profile}
			return nil
		}
	}
	return fmt.Errorf("unknown SNMP vendor profile %q", target.SNMPVendorProfile)
}

func appendSNMPVendorMetrics(ctx context.Context, conn snmpConn, target Target, inv *Inventory, base Metric, standard []Metric, identity []gosnmp.SnmpPDU) []Metric {
	if len(target.vendorProfiles) == 0 {
		return standard
	}
	inv.SysObjectID = snmpSystemObjectID(identity)
	profile := selectSNMPVendorProfile(target.vendorProfiles, inv.SysObjectID, snmpVendorDescription(identity))
	if profile == nil {
		return standard
	}
	inv.VendorProfile, base.DeviceName = profile.ID, inv.SysName
	base.SNMPProfile, base.SNMPSystemObjectID = profile.ID, inv.SysObjectID
	vendor := readSNMPVendorProfile(ctx, conn, *profile, base)
	if len(vendor) == 0 {
		return standard
	}
	deviceWide := make(map[string]bool)
	for i := range vendor {
		metric := &vendor[i]
		if metric.IfIndex != 0 {
			metric.IfName = inv.Interfaces[metric.IfIndex].Name
		}
		if metric.Component == "" && metric.IfIndex == 0 {
			deviceWide[metric.Name] = true
		}
	}
	standard = slices.DeleteFunc(standard, func(m Metric) bool {
		return m.IfIndex == 0 && m.Component == "" && m.PhysicalChannel == "" && deviceWide[m.Name]
	})
	return append(standard, vendor...)
}

func snmpSystemObjectID(rows []gosnmp.SnmpPDU) string {
	var oid string
	for _, row := range rows {
		if row.Name != oidSysObjectID {
			continue
		}
		candidate, valid := normalizeSNMPOID(pduString(row))
		if oid != "" || row.Type != gosnmp.ObjectIdentifier || !valid {
			return ""
		}
		oid = candidate
	}
	return oid
}

func snmpVendorDescription(rows []gosnmp.SnmpPDU) string {
	var description string
	var found bool
	for _, row := range rows {
		if row.Name != oidSysDescr {
			continue
		}
		if found || row.Type != gosnmp.OctetString {
			return ""
		}
		found = true
		description = pduString(row)
	}
	if len(description) > 255 {
		return ""
	}
	return description
}

func readSNMPVendorProfile(ctx context.Context, conn snmpConn, profile SNMPVendorProfile, base Metric) []Metric {
	byOID := make(map[string]SNMPVendorObject, len(profile.Objects))
	var scalarOIDs []string
	for _, obj := range profile.Objects {
		if obj.Kind == "scalar" {
			oid, _ := normalizeSNMPOID(obj.OID)
			byOID[oid] = obj
			scalarOIDs = append(scalarOIDs, oid)
		}
	}
	out := readSNMPVendorScalars(ctx, conn, scalarOIDs, byOID, base)
	remaining := maxSNMPVendorRows
	for _, obj := range profile.Objects {
		if obj.Kind != "column" {
			continue
		}
		if remaining == 0 || ctx.Err() != nil {
			break
		}
		rows, visited := readSNMPVendorColumn(ctx, conn, obj, base, remaining)
		remaining -= visited
		out = append(out, rows...)
	}
	return out
}

func readSNMPVendorScalars(ctx context.Context, conn snmpConn, oids []string, objects map[string]SNMPVendorObject, base Metric) []Metric {
	if len(oids) == 0 || ctx.Err() != nil {
		return nil
	}
	rows, err := conn.Get(oids)
	if err != nil || len(rows) > len(oids) {
		return nil
	}
	seen := make(map[string]bool, len(rows))
	var out []Metric
	for _, row := range rows {
		oid, valid := normalizeSNMPOID(row.Name)
		obj, requested := objects[oid]
		if !valid || !requested || seen[oid] {
			return nil
		}
		seen[oid] = true
		if metric, ok := makeSNMPVendorMetric(base, obj, row, ""); ok {
			out = append(out, metric)
		}
	}
	return out
}

func readSNMPVendorColumn(ctx context.Context, conn snmpConn, obj SNMPVendorObject, base Metric, capacity int) ([]Metric, int) {
	root, _ := normalizeSNMPOID(obj.OID)
	var out []Metric
	var visited int
	seen := make(map[string]bool)
	err := conn.BulkWalk(root, func(row gosnmp.SnmpPDU) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if visited == capacity {
			return errors.New("SNMP vendor poll row budget exhausted")
		}
		visited++
		oid, valid := normalizeSNMPOID(row.Name)
		index, belongs := strings.CutPrefix(oid, root+".")
		if !valid || !belongs || seen[index] {
			return errors.New("invalid or duplicate SNMP column instance")
		}
		seen[index] = true
		if metric, ok := makeSNMPVendorMetric(base, obj, row, index); ok {
			out = append(out, metric)
		}
		return nil
	})
	if err != nil {
		return nil, visited
	}
	return out, visited
}

func makeSNMPVendorMetric(base Metric, obj SNMPVendorObject, row gosnmp.SnmpPDU, index string) (Metric, bool) {
	value, ok := snmpVendorValue(obj.Syntax, row)
	if !ok || value == 0 && obj.ZeroUnavailable ||
		len(obj.ValidValues) > 0 && !slices.Contains(obj.ValidValues, int64(value)) {
		return Metric{}, false
	}
	if obj.Multiplier != 0 {
		value *= obj.Multiplier
	}
	if obj.Unit == "percent" && (value < 0 || value > 100) ||
		value < 0 && obj.Unit != "celsius" && obj.Unit != "dBm" && obj.Unit != "1" {
		return Metric{}, false
	}
	base.Name, base.Value, base.Unit, base.Component = obj.Metric, value, obj.Unit, index
	base.SNMPMIBObject = obj.MIB
	base.SNMPOID, _ = normalizeSNMPOID(obj.OID)
	if obj.Index == "if_index" {
		value, err := strconv.ParseUint(index, 10, 32)
		if err != nil || value == 0 || value > math.MaxUint32 {
			return Metric{}, false
		}
		base.IfIndex, base.Component = uint32(value), ""
	}
	return base, true
}

func snmpVendorValue(syntax string, row gosnmp.SnmpPDU) (float64, bool) {
	if syntax == "gauge32" && row.Type == gosnmp.Gauge32 {
		value, ok := snmpExactUnsigned(row.Value, 32)
		return float64(value), ok
	}
	if syntax != "integer" || row.Type != gosnmp.Integer {
		return 0, false
	}
	signed, ok := mibSignedInteger(row)
	return float64(signed), ok
}

var vendorMetricUnits = map[string]string{
	MetricCPUUtilization:                          "percent",
	MetricMemoryUsed:                              "bytes",
	MetricMemoryTotal:                             "bytes",
	"probectl.device.memory.utilization":          "percent",
	MetricSensorCelsius:                           "celsius",
	"probectl.device.fan.speed.rpm":               "rpm",
	"probectl.device.fan.state":                   "1",
	"probectl.device.power.supply.watts":          "watts",
	"probectl.device.power.supply.capacity.watts": "watts",
	"probectl.device.power.supply.state":          "1",
	MetricOpticalInputDBM:                         "dBm",
	MetricOpticalOutputDBM:                        "dBm",
	MetricOpticalBiasMA:                           "mA",
	MetricOpticalVoltage:                          "V",
	"probectl.device.sessions.active":             "sessions",
	"probectl.device.wifi.stations.associated":    "stations",
}
