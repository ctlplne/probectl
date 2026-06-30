// SPDX-License-Identifier: LicenseRef-probectl-TBD

package device

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// SNMP OIDs probectl maps (standard MIBs only; vendor MIBs are deliberately
// out of scope — "MIB coverage variance" is handled by graceful degradation,
// not by chasing every enterprise tree).
const (
	oidSysDescr  = ".1.3.6.1.2.1.1.1.0"
	oidSysUpTime = ".1.3.6.1.2.1.1.3.0" // TimeTicks (1/100 s)
	oidSysName   = ".1.3.6.1.2.1.1.5.0"

	// IF-MIB ifTable / ifXTable (per-ifIndex columns).
	oidIfDescr       = ".1.3.6.1.2.1.2.2.1.2"
	oidIfOperStatus  = ".1.3.6.1.2.1.2.2.1.8" // 1 = up
	oidIfInDiscards  = ".1.3.6.1.2.1.2.2.1.13"
	oidIfInErrors    = ".1.3.6.1.2.1.2.2.1.14"
	oidIfOutDiscards = ".1.3.6.1.2.1.2.2.1.19"
	oidIfOutErrors   = ".1.3.6.1.2.1.2.2.1.20"
	oidIfName        = ".1.3.6.1.2.1.31.1.1.1.1"
	oidIfHCInOctets  = ".1.3.6.1.2.1.31.1.1.1.6"
	oidIfHCOutOctets = ".1.3.6.1.2.1.31.1.1.1.10"
	oidIfHighSpeed   = ".1.3.6.1.2.1.31.1.1.1.15" // Mbps

	// ipAddrTable: ipAdEntIfIndex, indexed by the IP itself -> interface addrs
	// (the path-hop correlation key).
	oidIPAdEntIfIndex = ".1.3.6.1.2.1.4.20.1.2"

	// HOST-RESOURCES: CPU + storage.
	oidHrProcessorLoad      = ".1.3.6.1.2.1.25.3.3.1.2"
	oidHrStorageType        = ".1.3.6.1.2.1.25.2.3.1.2"
	oidHrStorageAllocUnits  = ".1.3.6.1.2.1.25.2.3.1.4"
	oidHrStorageSize        = ".1.3.6.1.2.1.25.2.3.1.5"
	oidHrStorageUsed        = ".1.3.6.1.2.1.25.2.3.1.6"
	oidHrStorageTypeRAM     = ".1.3.6.1.2.1.25.2.1.2" // hrStorageRam
	oidEntPhySensorType     = ".1.3.6.1.2.1.99.1.1.1.1"
	oidEntPhySensorValue    = ".1.3.6.1.2.1.99.1.1.1.4"
	oidEntPhysicalName      = ".1.3.6.1.2.1.47.1.1.1.1.7"
	entPhySensorTypeCelsius = 8
)

// snmpConn is the transport seam: the real gosnmp client in production, a
// canned-PDU fake in tests (the snmpsim-style integration test drives the real
// one when PROBECTL_TEST_SNMP_TARGET is set).
type snmpConn interface {
	Get(oids []string) ([]gosnmp.SnmpPDU, error)
	BulkWalk(root string, fn gosnmp.WalkFunc) error
	Close() error
}

// gosnmpConn adapts *gosnmp.GoSNMP onto snmpConn.
type gosnmpConn struct{ g *gosnmp.GoSNMP }

func (c gosnmpConn) Get(oids []string) ([]gosnmp.SnmpPDU, error) {
	pkt, err := c.g.Get(oids)
	if err != nil {
		return nil, err
	}
	return pkt.Variables, nil
}
func (c gosnmpConn) BulkWalk(root string, fn gosnmp.WalkFunc) error { return c.g.BulkWalk(root, fn) }
func (c gosnmpConn) Close() error                                   { return c.g.Conn.Close() }

// dialSNMP opens a v2c or v3 session per the device config + resolved
// credential. SNMPv3 USM auth/priv runs inside gosnmp (protocol-mandated
// algorithms, like a TLS handshake's crypto — the internal/crypto seam
// (guardrail 3) governs probectl's own cryptography, and the FIPS posture for
// SNMPv3 is documented in docs/device-telemetry.md).
func dialSNMP(dev Target, cred Credential) (snmpConn, error) {
	g := &gosnmp.GoSNMP{
		Target:  dev.Address,
		Port:    dev.Port,
		Timeout: 5 * time.Second,
		Retries: 1,
		MaxOids: 32,
	}
	switch dev.Transport {
	case TransportSNMPv2c:
		if cred.Community == "" {
			return nil, fmt.Errorf("device %s: credential %q has no community for snmpv2c", dev.Address, dev.Credential)
		}
		g.Version = gosnmp.Version2c
		g.Community = cred.Community
	case TransportSNMPv3:
		if cred.Username == "" {
			return nil, fmt.Errorf("device %s: credential %q has no username for snmpv3", dev.Address, dev.Credential)
		}
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		usm := &gosnmp.UsmSecurityParameters{UserName: cred.Username}
		flags := gosnmp.NoAuthNoPriv
		if cred.AuthPass != "" {
			flags = gosnmp.AuthNoPriv
			usm.AuthenticationPassphrase = cred.AuthPass
			switch cred.AuthProto {
			case "", "sha":
				usm.AuthenticationProtocol = gosnmp.SHA
			case "sha256":
				usm.AuthenticationProtocol = gosnmp.SHA256
			case "sha512":
				usm.AuthenticationProtocol = gosnmp.SHA512
			case "md5":
				usm.AuthenticationProtocol = gosnmp.MD5
			default:
				return nil, fmt.Errorf("device %s: unknown auth proto %q", dev.Address, cred.AuthProto)
			}
		}
		if cred.PrivPass != "" {
			flags = gosnmp.AuthPriv
			usm.PrivacyPassphrase = cred.PrivPass
			switch cred.PrivProto {
			case "", "aes":
				usm.PrivacyProtocol = gosnmp.AES
			case "aes256":
				usm.PrivacyProtocol = gosnmp.AES256
			case "des":
				usm.PrivacyProtocol = gosnmp.DES
			default:
				return nil, fmt.Errorf("device %s: unknown priv proto %q", dev.Address, cred.PrivProto)
			}
		}
		g.MsgFlags = flags
		g.SecurityParameters = usm
	default:
		return nil, fmt.Errorf("device %s: transport %q is not an SNMP transport", dev.Address, dev.Transport)
	}
	if err := g.Connect(); err != nil {
		return nil, fmt.Errorf("device %s: snmp connect: %w", dev.Address, err)
	}
	return gosnmpConn{g: g}, nil
}

// pollSNMP performs one poll: system group, IF-MIB tables, address table,
// HOST-RESOURCES CPU/memory, optional sensors. Every table degrades
// independently — a vendor that lacks a MIB simply yields fewer metrics.
func pollSNMP(conn snmpConn, dev Target, tenant, agent string, now time.Time) ([]Metric, Inventory, error) {
	inv := Inventory{Device: dev.Address, Interfaces: map[uint32]Interface{}}
	base := Metric{TenantID: tenant, AgentID: agent, Device: dev.Address, Source: SourceSNMP, At: now}
	var out []Metric

	// System group: identity + uptime. Total failure here means the device is
	// unreachable/misauthenticated — that IS an error (the caller counts it).
	pdus, err := conn.Get([]string{oidSysName, oidSysUpTime, oidSysDescr})
	if err != nil {
		return nil, inv, fmt.Errorf("device %s: system group: %w", dev.Address, err)
	}
	for _, p := range pdus {
		switch {
		case strings.HasPrefix(p.Name, oidSysName[:len(oidSysName)-2]):
			inv.SysName = pduString(p)
		case strings.HasPrefix(p.Name, oidSysDescr[:len(oidSysDescr)-2]):
			inv.SysDescr = pduString(p)
		case strings.HasPrefix(p.Name, oidSysUpTime[:len(oidSysUpTime)-2]):
			m := base
			m.DeviceName = inv.SysName
			m.Name, m.Value, m.Unit = MetricUptimeSeconds, pduFloat(p)/100, "seconds"
			out = append(out, m)
		}
	}

	// IF-MIB: build the interface map column by column.
	ifc := func(idx uint32) *Interface {
		e, ok := inv.Interfaces[idx]
		if !ok {
			e = Interface{Index: idx}
		}
		inv.Interfaces[idx] = e
		return &e
	}
	setIf := func(idx uint32, f func(*Interface)) {
		e := ifc(idx)
		f(e)
		inv.Interfaces[idx] = *e
	}
	walkColumn(conn, oidIfDescr, func(idx uint32, p gosnmp.SnmpPDU) {
		setIf(idx, func(e *Interface) { e.Descr = pduString(p) })
	})
	walkColumn(conn, oidIfName, func(idx uint32, p gosnmp.SnmpPDU) {
		setIf(idx, func(e *Interface) { e.Name = pduString(p) })
	})
	walkColumn(conn, oidIfOperStatus, func(idx uint32, p gosnmp.SnmpPDU) {
		setIf(idx, func(e *Interface) { e.OperUp = pduFloat(p) == 1 })
	})
	walkColumn(conn, oidIfHighSpeed, func(idx uint32, p gosnmp.SnmpPDU) {
		setIf(idx, func(e *Interface) { e.SpeedMbps = uint64(pduFloat(p)) })
	})

	// Counter columns become metrics directly (cumulative counters; the TSDB
	// rates them at query time, Prometheus-style).
	counterCols := []struct {
		oid, name string
	}{
		{oidIfHCInOctets, MetricIfInOctets},
		{oidIfHCOutOctets, MetricIfOutOctets},
		{oidIfInErrors, MetricIfInErrors},
		{oidIfOutErrors, MetricIfOutErrors},
		{oidIfInDiscards, MetricIfInDiscards},
		{oidIfOutDiscards, MetricIfOutDiscards},
	}
	counters := map[uint32]map[string]float64{}
	for _, col := range counterCols {
		col := col
		walkColumn(conn, col.oid, func(idx uint32, p gosnmp.SnmpPDU) {
			if counters[idx] == nil {
				counters[idx] = map[string]float64{}
			}
			counters[idx][col.name] = pduFloat(p)
		})
	}

	// ipAddrTable: interface addresses (the hop-correlation key).
	_ = conn.BulkWalk(oidIPAdEntIfIndex, func(p gosnmp.SnmpPDU) error {
		ipStr := strings.TrimPrefix(p.Name, oidIPAdEntIfIndex+".")
		if addr, err := netip.ParseAddr(ipStr); err == nil {
			idx := uint32(pduFloat(p))
			setIf(idx, func(e *Interface) { e.Addrs = append(e.Addrs, addr) })
		}
		return nil
	})

	// Emit per-interface metrics now that names are known.
	for idx, e := range inv.Interfaces {
		if e.Name == "" {
			e.Name = e.Descr
			inv.Interfaces[idx] = e
		}
		mk := func(name string, v float64, unit string) {
			m := base
			m.DeviceName = inv.SysName
			m.IfIndex, m.IfName = idx, e.Name
			m.Name, m.Value, m.Unit = name, v, unit
			out = append(out, m)
		}
		mk(MetricIfOperStatus, boolFloat(e.OperUp), "")
		if e.SpeedMbps > 0 {
			// ifHighSpeed is natively Mbps; the metric name says mbps and so
			// must the unit label (was "bps" — a label-only bug; the VALUE
			// was always Mbps, so no series ever needs rescaling).
			mk(MetricIfSpeedMbps, float64(e.SpeedMbps), "Mbps")
		}
		for name, v := range counters[idx] {
			unit := "octets"
			if strings.Contains(name, "errors") || strings.Contains(name, "discards") {
				unit = "packets"
			}
			mk(name, v, unit)
		}
	}

	// HOST-RESOURCES CPU: average hrProcessorLoad across cores.
	var loadSum float64
	var loadN int
	walkColumn(conn, oidHrProcessorLoad, func(_ uint32, p gosnmp.SnmpPDU) {
		loadSum += pduFloat(p)
		loadN++
	})
	if loadN > 0 {
		m := base
		m.DeviceName = inv.SysName
		m.Name, m.Value, m.Unit = MetricCPUUtilization, loadSum/float64(loadN), "percent"
		out = append(out, m)
	}

	// HOST-RESOURCES memory: the first hrStorage row whose type is hrStorageRam.
	type storRow struct{ units, size, used float64 }
	stor := map[uint32]*storRow{}
	ramRows := map[uint32]bool{}
	walkColumn(conn, oidHrStorageType, func(idx uint32, p gosnmp.SnmpPDU) {
		if strings.TrimPrefix(pduString(p), ".") == strings.TrimPrefix(oidHrStorageTypeRAM, ".") {
			ramRows[idx] = true
		}
	})
	for _, col := range []struct {
		oid string
		set func(*storRow, float64)
	}{
		{oidHrStorageAllocUnits, func(r *storRow, v float64) { r.units = v }},
		{oidHrStorageSize, func(r *storRow, v float64) { r.size = v }},
		{oidHrStorageUsed, func(r *storRow, v float64) { r.used = v }},
	} {
		col := col
		walkColumn(conn, col.oid, func(idx uint32, p gosnmp.SnmpPDU) {
			if stor[idx] == nil {
				stor[idx] = &storRow{}
			}
			col.set(stor[idx], pduFloat(p))
		})
	}
	for idx := range ramRows {
		r := stor[idx]
		if r == nil || r.units == 0 {
			continue
		}
		mu := base
		mu.DeviceName = inv.SysName
		mu.Name, mu.Value, mu.Unit = MetricMemoryUsed, r.used*r.units, "bytes"
		mt := base
		mt.DeviceName = inv.SysName
		mt.Name, mt.Value, mt.Unit = MetricMemoryTotal, r.size*r.units, "bytes"
		out = append(out, mu, mt)
		break // one RAM row is the device's memory
	}

	// Optional entity sensors (temperature only — the broadly comparable one).
	if dev.Sensors {
		sensorNames := map[uint32]string{}
		walkColumn(conn, oidEntPhysicalName, func(idx uint32, p gosnmp.SnmpPDU) {
			sensorNames[idx] = pduString(p)
		})
		celsius := map[uint32]bool{}
		walkColumn(conn, oidEntPhySensorType, func(idx uint32, p gosnmp.SnmpPDU) {
			if int(pduFloat(p)) == entPhySensorTypeCelsius {
				celsius[idx] = true
			}
		})
		walkColumn(conn, oidEntPhySensorValue, func(idx uint32, p gosnmp.SnmpPDU) {
			if !celsius[idx] {
				return
			}
			m := base
			m.DeviceName = inv.SysName
			m.IfIndex, m.IfName = idx, sensorNames[idx]
			m.Name, m.Value, m.Unit = MetricSensorCelsius, pduFloat(p), "celsius"
			out = append(out, m)
		})
	}

	return out, inv, nil
}

// walkColumn walks one table column, handing each row's trailing index to fn.
// Walk errors are swallowed — MIB variance degrades, never fails (the system
// group above is the reachability check).
func walkColumn(conn snmpConn, oid string, fn func(idx uint32, p gosnmp.SnmpPDU)) {
	_ = conn.BulkWalk(oid, func(p gosnmp.SnmpPDU) error {
		tail := strings.TrimPrefix(p.Name, oid+".")
		idx, err := strconv.ParseUint(tail, 10, 32)
		if err != nil {
			return nil // non-scalar index (e.g. compound) — skip the row
		}
		fn(uint32(idx), p)
		return nil
	})
}

// pduFloat coerces the gosnmp dynamic value types to float64 (counters,
// gauges, timeticks, integers).
func pduFloat(p gosnmp.SnmpPDU) float64 {
	switch v := p.Value.(type) {
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case uint:
		return float64(v)
	case uint32:
		return float64(v)
	case uint64:
		return float64(v)
	case float64:
		return v
	default:
		return 0
	}
}

// pduString coerces OctetString / ObjectIdentifier values.
func pduString(p gosnmp.SnmpPDU) string {
	switch v := p.Value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return ""
	}
}

func boolFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
