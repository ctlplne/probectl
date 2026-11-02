// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cmdb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// NetBox looks up CIs via the NetBox REST API. It is read-only and uses a
// token-scoped integration account:
//
//	GET {base}/api/ipam/ip-addresses/?address={ip}
//	GET {base}/api/dcim/devices/?name={hostname}
//	GET {base}/api/virtualization/virtual-machines/?name={hostname}
//
// NetBox uses "Authorization: Token <token>". The token is read from the
// environment by the builder, never from files or logs.
type NetBox struct {
	base       string
	token      string
	client     *http.Client
	tenants    map[string]string
	bindingErr error
}

// NewNetBox builds a NetBox CMDB provider. base is the NetBox instance URL,
// e.g. https://netbox.example.com.
func NewNetBox(base, token string, tenants map[string]string) *NetBox {
	bindings, err := validatedNetBoxTenantMap(tenants)
	return &NetBox{
		tenants: bindings, bindingErr: err,
		base:   strings.TrimRight(base, "/"),
		token:  token,
		client: crypto.HardenedHTTPClient(15 * time.Second),
	}
}

// Name implements Provider.
func (n *NetBox) Name() string { return "netbox" }

// Lookup implements Provider.
func (n *NetBox) Lookup(ctx context.Context, key string) ([]CI, error) {
	_, source, err := n.sourceTenant(ctx)
	if err != nil {
		return nil, err
	}
	key = CanonicalKey(key)
	if key == "" {
		return nil, nil
	}
	if _, err := netip.ParseAddr(key); err == nil {
		return n.lookupIP(ctx, key, source)
	}
	devices, err := n.lookupDevices(ctx, key, source)
	if err != nil {
		return nil, err
	}
	vms, err := n.lookupVMs(ctx, key, source)
	if err != nil {
		return nil, err
	}
	return append(devices, vms...), nil
}

func (n *NetBox) lookupIP(ctx context.Context, key, source string) ([]CI, error) {
	q := url.Values{}
	q.Set("tenant_id", source)
	q.Set("address", key)
	q.Set("limit", fmt.Sprint(maxCIsPerLookup))
	var parsed struct {
		Count   int    `json:"count"`
		Next    string `json:"next"`
		Results []struct {
			ID             int           `json:"id"`
			Tenant         *netBoxTenant `json:"tenant"`
			Display        string        `json:"display"`
			Address        string        `json:"address"`
			DNSName        string        `json:"dns_name"`
			URL            string        `json:"url"`
			AssignedObject struct {
				Name   string `json:"name"`
				Device struct {
					Name    string        `json:"name"`
					Display string        `json:"display"`
					Tenant  *netBoxTenant `json:"tenant"`
				} `json:"device"`
				VirtualMachine struct {
					Name    string        `json:"name"`
					Display string        `json:"display"`
					Tenant  *netBoxTenant `json:"tenant"`
				} `json:"virtual_machine"`
			} `json:"assigned_object"`
		} `json:"results"`
	}
	if err := n.get(ctx, "/api/ipam/ip-addresses/?"+q.Encode(), &parsed); err != nil {
		return nil, err
	}
	if parsed.Next != "" || parsed.Count != len(parsed.Results) || parsed.Count > maxCIsPerLookup {
		return nil, ErrTenantBinding
	}
	out := make([]CI, 0, len(parsed.Results))
	for _, r := range parsed.Results {
		if r.ID <= 0 || !r.Tenant.matches(source) {
			return nil, ErrTenantBinding
		}
		if CanonicalKey(stripCIDR(r.Address)) != key ||
			(r.AssignedObject.Device.Tenant != nil && !r.AssignedObject.Device.Tenant.matches(source)) ||
			(r.AssignedObject.VirtualMachine.Tenant != nil && !r.AssignedObject.VirtualMachine.Tenant.matches(source)) {
			return nil, ErrTenantBinding
		}
		// A brief related device/VM has no tenant attestation in normal
		// NetBox responses. Only project attributes of the owned IP CI.
		name := firstNonEmpty(r.DNSName, r.Display, r.Address)
		out = append(out, CI{
			SysID:     fmt.Sprintf("netbox:ipam.ip_address:%d", r.ID),
			Name:      name,
			Class:     "netbox.ip_address",
			IPAddress: stripCIDR(r.Address),
			FQDN:      strings.ToLower(r.DNSName),
			URL:       firstNonEmpty(uiURL(n.base, r.URL), r.URL),
			Extra: map[string]string{
				"source":  "netbox",
				"address": r.Address,
			},
		})
	}
	return out, nil
}

func (n *NetBox) lookupDevices(ctx context.Context, key, source string) ([]CI, error) {
	q := url.Values{}
	q.Set("tenant_id", source)
	q.Set("name", key)
	q.Set("limit", fmt.Sprint(maxCIsPerLookup))
	var parsed struct {
		Count   int    `json:"count"`
		Next    string `json:"next"`
		Results []struct {
			ID        int           `json:"id"`
			Tenant    *netBoxTenant `json:"tenant"`
			Name      string        `json:"name"`
			Display   string        `json:"display"`
			URL       string        `json:"url"`
			Role      named         `json:"role"`
			Site      named         `json:"site"`
			PrimaryIP struct {
				Address string `json:"address"`
			} `json:"primary_ip4"`
			DeviceType struct {
				Model string `json:"model"`
			} `json:"device_type"`
		} `json:"results"`
	}
	if err := n.get(ctx, "/api/dcim/devices/?"+q.Encode(), &parsed); err != nil {
		return nil, err
	}
	if parsed.Next != "" || parsed.Count != len(parsed.Results) || parsed.Count > maxCIsPerLookup {
		return nil, ErrTenantBinding
	}
	out := make([]CI, 0, len(parsed.Results))
	for _, r := range parsed.Results {
		if r.ID <= 0 || !r.Tenant.matches(source) {
			return nil, ErrTenantBinding
		}
		if CanonicalKey(r.Name) != key {
			return nil, ErrTenantBinding
		}
		out = append(out, CI{
			SysID:     fmt.Sprintf("netbox:dcim.device:%d", r.ID),
			Name:      firstNonEmpty(r.Display, r.Name),
			Class:     "netbox.device",
			IPAddress: stripCIDR(r.PrimaryIP.Address),
			FQDN:      strings.ToLower(r.Name),
			URL:       firstNonEmpty(uiURL(n.base, r.URL), r.URL),
			Extra: compactExtra(map[string]string{
				"source": "netbox",
				"role":   r.Role.Name,
				"site":   r.Site.Name,
				"model":  r.DeviceType.Model,
			}),
		})
	}
	return out, nil
}

func (n *NetBox) lookupVMs(ctx context.Context, key, source string) ([]CI, error) {
	q := url.Values{}
	q.Set("tenant_id", source)
	q.Set("name", key)
	q.Set("limit", fmt.Sprint(maxCIsPerLookup))
	var parsed struct {
		Count   int    `json:"count"`
		Next    string `json:"next"`
		Results []struct {
			ID        int           `json:"id"`
			Tenant    *netBoxTenant `json:"tenant"`
			Name      string        `json:"name"`
			Display   string        `json:"display"`
			URL       string        `json:"url"`
			Role      named         `json:"role"`
			Site      named         `json:"site"`
			Cluster   named         `json:"cluster"`
			PrimaryIP struct {
				Address string `json:"address"`
			} `json:"primary_ip4"`
		} `json:"results"`
	}
	if err := n.get(ctx, "/api/virtualization/virtual-machines/?"+q.Encode(), &parsed); err != nil {
		return nil, err
	}
	if parsed.Next != "" || parsed.Count != len(parsed.Results) || parsed.Count > maxCIsPerLookup {
		return nil, ErrTenantBinding
	}
	out := make([]CI, 0, len(parsed.Results))
	for _, r := range parsed.Results {
		if r.ID <= 0 || !r.Tenant.matches(source) {
			return nil, ErrTenantBinding
		}
		if CanonicalKey(r.Name) != key {
			return nil, ErrTenantBinding
		}
		out = append(out, CI{
			SysID:     fmt.Sprintf("netbox:virtualization.virtual_machine:%d", r.ID),
			Name:      firstNonEmpty(r.Display, r.Name),
			Class:     "netbox.virtual_machine",
			IPAddress: stripCIDR(r.PrimaryIP.Address),
			FQDN:      strings.ToLower(r.Name),
			URL:       firstNonEmpty(uiURL(n.base, r.URL), r.URL),
			Extra: compactExtra(map[string]string{
				"source":  "netbox",
				"role":    r.Role.Name,
				"site":    r.Site.Name,
				"cluster": r.Cluster.Name,
			}),
		})
	}
	return out, nil
}

func (n *NetBox) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if n.token != "" {
		req.Header.Set("Authorization", "Token "+n.token)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("netbox: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if err != nil {
		return fmt.Errorf("netbox read: %w", err)
	}
	if len(body) > 4<<20 {
		return ErrTenantBinding
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("netbox: status %d", resp.StatusCode)
	}
	if err := validateNetBoxJSON(body); err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return ErrTenantBinding
	}
	return nil
}

type named struct {
	Name string `json:"name"`
}

func stripCIDR(address string) string {
	addr, _, _ := strings.Cut(strings.TrimSpace(address), "/")
	return addr
}

func uiURL(base, apiURL string) string {
	apiURL = strings.TrimSpace(apiURL)
	if apiURL == "" {
		return ""
	}
	return strings.Replace(apiURL, strings.TrimRight(base, "/")+"/api/", strings.TrimRight(base, "/")+"/", 1)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func compactExtra(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		if strings.TrimSpace(v) != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
