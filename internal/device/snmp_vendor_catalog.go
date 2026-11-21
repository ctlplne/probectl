// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

var ciscoProcessorObjects = []SNMPVendorObject{
	{MIB: "CISCO-PROCESS-MIB::cpmCPUTotalMonIntervalValue", OID: ".1.3.6.1.4.1.9.9.109.1.1.1.1.10",
		Kind: "column", Syntax: "gauge32", Metric: MetricCPUUtilization, Unit: "percent"},
}

// Only the numeric definitions and names from the vendor MIBs are used here.
// Each definition keeps the original object identity and expected wire type.
var builtinSNMPVendorProfiles = []SNMPVendorProfile{
	{
		ID: "cisco-ios", Vendor: "Cisco", Platform: "IOS on Catalyst 2960-X",
		SysObjectID: ".1.3.6.1.4.1.9.1.1695", Objects: ciscoProcessorObjects,
	},
	{
		ID: "cisco-ios-xe", Vendor: "Cisco", Platform: "IOS XE on ISR 4331",
		SysObjectID: ".1.3.6.1.4.1.9.1.2068", Objects: ciscoProcessorObjects,
	},
	{
		ID: "cisco-nx-os", Vendor: "Cisco", Platform: "NX-OS on Nexus 9396PX",
		SysObjectID: ".1.3.6.1.4.1.9.1.1925", Objects: ciscoProcessorObjects,
	},
	{
		ID: "arista-eos", Vendor: "Arista", Platform: "EOS",
		SysObjectID: ".1.3.6.1.4.1.30065.1", MatchSubtree: true,
		Objects: []SNMPVendorObject{
			{MIB: "HOST-RESOURCES-MIB::hrProcessorLoad", OID: oidHrProcessorLoad, Kind: "column", Syntax: "integer", Metric: MetricCPUUtilization, Unit: "percent"},
		},
	},
	{
		ID: "fortinet-forti-os", Vendor: "Fortinet", Platform: "FortiOS on FortiGate",
		SysObjectID: ".1.3.6.1.4.1.12356.101.1", MatchSubtree: true,
		Objects: []SNMPVendorObject{
			{MIB: "FORTINET-FORTIGATE-MIB::fgSysCpuUsage", OID: ".1.3.6.1.4.1.12356.101.4.1.3.0", Kind: "scalar", Syntax: "gauge32", Metric: MetricCPUUtilization, Unit: "percent"},
			{MIB: "FORTINET-FORTIGATE-MIB::fgSysMemUsage", OID: ".1.3.6.1.4.1.12356.101.4.1.4.0", Kind: "scalar", Syntax: "gauge32", Metric: "probectl.device.memory.utilization", Unit: "percent"},
		},
	},
	{
		ID: "juniper-junos", Vendor: "Juniper Networks", Platform: "Junos OS",
		SysObjectID: ".1.3.6.1.4.1.2636.1.1.1.2", MatchSubtree: true,
		Objects: []SNMPVendorObject{
			{MIB: "JUNIPER-MIB::jnxOperatingCPU", OID: ".1.3.6.1.4.1.2636.3.1.13.1.8", Kind: "column", Syntax: "gauge32", Metric: MetricCPUUtilization, Unit: "percent", ZeroUnavailable: true},
			{MIB: "JUNIPER-DOM-MIB::jnxDomCurrentRxLaserPower", OID: ".1.3.6.1.4.1.2636.3.60.1.1.1.1.5", Kind: "column", Syntax: "integer", Metric: MetricOpticalInputDBM, Unit: "dBm", Multiplier: 0.01, Index: "if_index"},
			{MIB: "JUNIPER-DOM-MIB::jnxDomCurrentTxLaserOutputPower", OID: ".1.3.6.1.4.1.2636.3.60.1.1.1.1.7", Kind: "column", Syntax: "integer", Metric: MetricOpticalOutputDBM, Unit: "dBm", Multiplier: 0.01, Index: "if_index"},
		},
	},
	{
		ID: "mikrotik-router-os", Vendor: "MikroTik", Platform: "RouterOS",
		SysObjectID: ".1.3.6.1.4.1.14988.1", MatchSubtree: true,
		Objects: []SNMPVendorObject{
			{MIB: "MIKROTIK-MIB::mtxrHlTemperature", OID: ".1.3.6.1.4.1.14988.1.1.3.10.0", Kind: "scalar", Syntax: "integer", Metric: MetricSensorCelsius, Unit: "celsius", Multiplier: 0.1},
			{MIB: "MIKROTIK-MIB::mtxrHlFanSpeed1", OID: ".1.3.6.1.4.1.14988.1.1.3.17.0", Kind: "scalar", Syntax: "gauge32", Metric: "probectl.device.fan.speed.rpm", Unit: "rpm"},
			{MIB: "MIKROTIK-MIB::mtxrOpticalTxPower", OID: ".1.3.6.1.4.1.14988.1.1.19.1.1.9", Kind: "column", Syntax: "integer", Metric: MetricOpticalOutputDBM, Unit: "dBm", Multiplier: 0.001},
			{MIB: "MIKROTIK-MIB::mtxrOpticalRxPower", OID: ".1.3.6.1.4.1.14988.1.1.19.1.1.10", Kind: "column", Syntax: "integer", Metric: MetricOpticalInputDBM, Unit: "dBm", Multiplier: 0.001},
		},
	},
	{
		ID: "palo-alto-pan-os", Vendor: "Palo Alto Networks", Platform: "PAN-OS on PA-440",
		SysObjectID: ".1.3.6.1.4.1.25461.2.3.54",
		Objects: []SNMPVendorObject{
			{MIB: "PAN-COMMON-MIB::panSessionActive", OID: ".1.3.6.1.4.1.25461.2.1.2.3.3.0", Kind: "scalar", Syntax: "integer", Metric: "probectl.device.sessions.active", Unit: "sessions"},
			{MIB: "HOST-RESOURCES-MIB::hrProcessorLoad", OID: oidHrProcessorLoad, Kind: "column", Syntax: "integer", Metric: MetricCPUUtilization, Unit: "percent"},
		},
	},
	{
		ID: "palo-alto-pa-5450", Vendor: "Palo Alto Networks", Platform: "PAN-OS on PA-5450",
		SysObjectID: ".1.3.6.1.4.1.25461.2.3.57",
		Objects: []SNMPVendorObject{
			{MIB: "PAN-ENTITY-EXT-MIB::panEntryPowerSupplyPowerCapacity", OID: ".1.3.6.1.4.1.25461.1.1.7.1.4.1.1.1", Kind: "column", Syntax: "integer", Metric: "probectl.device.power.supply.capacity.watts", Unit: "watts"},
			{MIB: "PAN-COMMON-MIB::panSessionActive", OID: ".1.3.6.1.4.1.25461.2.1.2.3.3.0", Kind: "scalar", Syntax: "integer", Metric: "probectl.device.sessions.active", Unit: "sessions"},
		},
	},
	{
		ID: "ubiquiti-unifi", Vendor: "Ubiquiti", Platform: "UniFi access points",
		SysObjectID: ".1.3.6.1.4.1.41112.1.6", MatchSubtree: true,
		Objects: []SNMPVendorObject{
			{MIB: "UBNT-Combined-MIB::unifiVapNumStations", OID: ".1.3.6.1.4.1.41112.1.6.1.2.1.8", Kind: "column", Syntax: "integer", Metric: "probectl.device.wifi.stations.associated", Unit: "stations"},
		},
	},
	{
		ID: "hpe-aruba-5406r", Vendor: "HPE Aruba Networking", Platform: "AOS-S on 5406R zl2",
		SysObjectID: ".1.3.6.1.4.1.11.2.3.7.11.160",
		Objects: []SNMPVendorObject{
			{MIB: "FAN-MIB::hpicfFanState", OID: ".1.3.6.1.4.1.11.2.14.11.5.1.54.2.1.1.4", Kind: "column", Syntax: "integer", Metric: "probectl.device.fan.state", Unit: "1",
				ValidValues: []int64{0, 1, 2, 3, 4, 5}},
			{MIB: "POWERSUPPLY-MIB::hpicfPsState", OID: ".1.3.6.1.4.1.11.2.14.11.5.1.55.1.1.1.2", Kind: "column", Syntax: "integer", Metric: "probectl.device.power.supply.state", Unit: "1",
				ValidValues: []int64{1, 2, 3, 4, 5, 7, 8, 9}},
		},
	},
}
