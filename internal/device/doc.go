// Package device implements the S39 (F18) device-telemetry plane: an SNMP
// poller (v2c/v3) and a gNMI/OpenConfig streaming collector that both
// normalize into one DeviceMetric, published to the bus
// (probectl.device.metrics) and landed in the TSDB by the control plane —
// the LibreNMS plane, OTel-disciplined.
//
// Design notes:
//
//   - One model, two transports: SNMP (IF-MIB interface health + HC counters,
//     HOST-RESOURCES CPU/memory, optional entity sensors) and gNMI Subscribe
//     (OpenConfig interface counters/oper-status) emit identical metric names,
//     so dashboards, alerts, and correlation never care how a device speaks.
//   - Correlation: each SNMP poll also builds an interface Inventory
//     (ifIndex, ifName, addresses from ipAddrTable); the Correlator joins
//     path hops (responder IP -> device interface) and flow records
//     (exporter + ifIndex -> named interface) onto the device plane.
//   - Credentials are resolved through the CredentialSource seam by NAME —
//     config carries references, never secrets (CLAUDE.md §7 guardrail 6).
//     The env provider is the pre-S41 default; S41 plugs Vault/CyberArk into
//     the same seam. Credentials are never logged (redacted Stringers).
//   - MIB coverage varies wildly between vendors: every table walk degrades
//     gracefully (a missing table skips its metrics, never fails the poll).
//   - gNMI dials TLS with certificate verification by default (custom CA via
//     ca_file); verification is never disabled (guardrail 12). Plaintext is
//     an explicit per-device opt-in for lab gear and is loudly logged.
package device
