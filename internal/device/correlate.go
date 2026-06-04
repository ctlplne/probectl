package device

import (
	"net/netip"
	"sync"
)

// Ref points a signal from another plane (a path hop, a flow record) at the
// device/interface that produced or carried it — the S39 correlation contract.
type Ref struct {
	Device  string `json:"device"`
	SysName string `json:"sys_name,omitempty"`
	IfIndex uint32 `json:"if_index,omitempty"`
	IfName  string `json:"if_name,omitempty"`
}

// Correlator indexes the SNMP inventories so the path and flow planes can be
// joined onto the device plane:
//
//   - a path hop's responder IP matches an interface address (ipAddrTable) or
//     the device's own management address;
//   - a flow record's (exporter address, ifIndex) matches the exporting
//     device's named interface.
//
// It is safe for concurrent use (the runtime updates it after every poll).
type Correlator struct {
	mu      sync.RWMutex
	byIP    map[netip.Addr]Ref
	devices map[string]Inventory // keyed by management address
}

// NewCorrelator returns an empty correlator.
func NewCorrelator() *Correlator {
	return &Correlator{byIP: map[netip.Addr]Ref{}, devices: map[string]Inventory{}}
}

// Update replaces a device's inventory (called after each successful poll).
func (c *Correlator) Update(inv Inventory) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Drop the device's previous IP index entries, then re-add.
	for ip, ref := range c.byIP {
		if ref.Device == inv.Device {
			delete(c.byIP, ip)
		}
	}
	c.devices[inv.Device] = inv

	if mgmt, err := netip.ParseAddr(inv.Device); err == nil {
		c.byIP[mgmt] = Ref{Device: inv.Device, SysName: inv.SysName}
	}
	for _, ifc := range inv.Interfaces {
		for _, a := range ifc.Addrs {
			c.byIP[a] = Ref{Device: inv.Device, SysName: inv.SysName, IfIndex: ifc.Index, IfName: ifc.Name}
		}
	}
}

// MatchHopIP correlates a path hop's responder IP to a device interface.
func (c *Correlator) MatchHopIP(ip string) (Ref, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Ref{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	ref, ok := c.byIP[addr]
	return ref, ok
}

// MatchExporterInterface correlates a flow record's (exporter, ifIndex) to the
// exporting device's named interface — exporter is the flow datagram's source
// address, which is the device's management/loopback address in practice.
func (c *Correlator) MatchExporterInterface(exporter string, ifIndex uint32) (Ref, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	inv, ok := c.devices[exporter]
	if !ok {
		// The exporter may speak from an interface address rather than the
		// configured management address — fall back to the IP index.
		if addr, err := netip.ParseAddr(exporter); err == nil {
			if ref, hit := c.byIP[addr]; hit {
				inv, ok = c.devices[ref.Device], true
			}
		}
		if !ok {
			return Ref{}, false
		}
	}
	ifc, ok := inv.Interfaces[ifIndex]
	if !ok {
		return Ref{Device: inv.Device, SysName: inv.SysName}, false
	}
	return Ref{Device: inv.Device, SysName: inv.SysName, IfIndex: ifc.Index, IfName: ifc.Name}, true
}

// Devices reports the known device count (stats/tests).
func (c *Correlator) Devices() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.devices)
}
