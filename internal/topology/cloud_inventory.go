// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package topology

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/crypto"
)

const (
	MaxCloudInventoryResources = 2048
	MaxCloudInventoryLinks     = 4096
	cloudInventoryPages        = 32
	cloudInventoryPageBytes    = 2 << 20
	cloudInventoryTimeout      = 90 * time.Second
)

const (
	CloudNetwork NodeKind = "cloud_network"
	CloudSubnet  NodeKind = "cloud_subnet"
	CloudGateway NodeKind = "cloud_gateway"
	CloudPeering NodeKind = "cloud_peering"
)

type CloudInventorySource struct {
	Provider string `json:"provider"`
	Account  string `json:"account"`
	Location string `json:"location"`
}

type CloudInventoryResource struct {
	ID       string   `json:"id"`
	Kind     NodeKind `json:"kind"`
	Type     string   `json:"type"`
	CIDRs    []string `json:"cidrs,omitempty"`
	State    string   `json:"state,omitempty"`
	External bool     `json:"external,omitempty"`
}

type CloudInventoryLink struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

// CloudInventory is a complete snapshot from one configured cloud scope. The
// tenant is supplied by the persistence caller, outside these provider data.
type CloudInventory struct {
	Source     CloudInventorySource     `json:"source"`
	ObservedAt time.Time                `json:"observed_at"`
	Resources  []CloudInventoryResource `json:"resources"`
	Links      []CloudInventoryLink     `json:"links"`
}

func (inventory CloudInventory) Validate() error {
	switch inventory.Source.Provider {
	case "aws", "azure", "gcp":
	default:
		return errors.New("topology: unknown cloud inventory provider")
	}
	if !cloudInventoryText(inventory.Source.Account, 256) || !cloudInventoryText(inventory.Source.Location, 128) || inventory.ObservedAt.IsZero() ||
		len(inventory.Resources) > MaxCloudInventoryResources || len(inventory.Links) > MaxCloudInventoryLinks {
		return errors.New("topology: invalid cloud inventory source, clock or size")
	}
	kinds := make(map[string]NodeKind, len(inventory.Resources))
	for _, r := range inventory.Resources {
		if kinds[r.ID] != "" || !r.valid() {
			return errors.New("topology: invalid or repeated cloud resource identity")
		}
		kinds[r.ID] = r.Kind
	}
	links := make(map[CloudInventoryLink]struct{}, len(inventory.Links))
	for _, link := range inventory.Links {
		if _, exists := links[link]; exists || !link.valid(kinds[link.From], kinds[link.To]) {
			return errors.New("topology: invalid or repeated cloud resource relationship")
		}
		links[link] = struct{}{}
	}
	return nil
}

func (r CloudInventoryResource) valid() bool {
	switch r.Kind {
	case CloudNetwork, CloudSubnet, CloudGateway, CloudPeering:
	default:
		return false
	}
	if !cloudInventoryText(r.ID, 1024) || !cloudInventoryText(r.Type, 64) || (r.State != "" && !cloudInventoryText(r.State, 64)) ||
		len(r.CIDRs) > 64 || (r.External && r.Kind != CloudPeering) {
		return false
	}
	for _, cidr := range r.CIDRs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil || p.Masked().String() != cidr {
			return false
		}
	}
	return true
}

func (link CloudInventoryLink) valid(from, to NodeKind) bool {
	switch link.Kind {
	case "cloud_contains":
		return from == CloudNetwork && to == CloudSubnet
	case "cloud_attachment":
		return (from == CloudNetwork || from == CloudSubnet) && to == CloudGateway
	case "cloud_peering_requester", "cloud_peering_accepter":
		return from == CloudNetwork && to == CloudPeering
	default:
		return false
	}
}

func cloudInventoryText(s string, limit int) bool {
	return s != "" && len(s) <= limit && utf8.ValidString(s) && strings.TrimSpace(s) == s &&
		strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) < 0
}

func cloudInventoryCIDRs(inputs ...string) ([]string, error) {
	if len(inputs) > 65 {
		return nil, errors.New("topology: too many cloud network prefixes")
	}
	var out []string
	for _, address := range inputs {
		if address == "" {
			continue
		}
		p, err := netip.ParsePrefix(address)
		if err != nil {
			return nil, errors.New("topology: invalid cloud network prefix")
		}
		out = append(out, p.Masked().String())
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// ProjectCloudInventory appends inventory relationships to the visualization.
// They remain separate from the traversal graph used for what-if predictions.
func ProjectCloudInventory(viz *Viz, inventory CloudInventory) error {
	if err := inventory.Validate(); err != nil {
		return err
	}
	ids := make(map[string]string, len(inventory.Resources))
	for _, r := range inventory.Resources {
		encoded, _ := json.Marshal([]string{inventory.Source.Provider, inventory.Source.Account,
			inventory.Source.Location, r.ID})
		id := "cloud:" + hex.EncodeToString(crypto.Hash(encoded))
		ids[r.ID] = id
		label := r.ID[strings.LastIndexByte(r.ID, '/')+1:]
		viz.Nodes = append(viz.Nodes, VizNode{ID: id, Kind: string(r.Kind), Label: label, Cloud: &VizCloudObject{
			CloudInventorySource: inventory.Source, ResourceID: r.ID, Type: r.Type, CIDRs: append([]string(nil), r.CIDRs...),
			State: r.State, External: r.External, ObservedAt: inventory.ObservedAt,
		}})
	}
	for _, link := range inventory.Links {
		viz.Edges = append(viz.Edges, VizEdge{From: ids[link.From], To: ids[link.To], Kind: link.Kind, ObservedAt: inventory.ObservedAt})
	}
	return nil
}
