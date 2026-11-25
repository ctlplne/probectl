// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package topology

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/secrets"
)

const (
	azureInventoryHost            = "management.azure.com"
	azureInventoryNetworkVersion  = "2025-05-01"
	azureInventoryResourceVersion = "2021-04-01"
	azureInventoryGatewayKind     = "Microsoft.Network/virtualNetworkGateways"
	azureInventoryGatewayFilter   = "resourceType eq '" + azureInventoryGatewayKind + "'"
	azureInventoryMaxGatewayReads = 128
)

type AzureInventoryConfig struct {
	Subscription, CredentialRef string
}

// DiscoverAzureCloudInventory reads a complete inventory from one Azure
// subscription. The access token goes only to Azure Resource Manager.
func DiscoverAzureCloudInventory(ctx context.Context, cfg AzureInventoryConfig, resolver *secrets.Resolver) (CloudInventory, error) {
	client := cloudInventoryHTTPClient()
	defer client.CloseIdleConnections()
	return discoverAzureCloudInventory(ctx, client, cfg, resolver)
}

func discoverAzureCloudInventory(ctx context.Context, client *http.Client, cfg AzureInventoryConfig, resolver *secrets.Resolver) (CloudInventory, error) {
	subscription, err := uuid.Parse(cfg.Subscription)
	if err != nil || subscription == uuid.Nil || !strings.EqualFold(subscription.String(), cfg.Subscription) || resolver == nil {
		return CloudInventory{}, errors.New("topology: Azure inventory requires a subscription UUID and secrets resolver")
	}
	ctx, cancel := context.WithTimeout(ctx, cloudInventoryTimeout)
	defer cancel()
	token, release, err := resolveCloudInventoryOAuth(ctx, resolver, cfg.CredentialRef)
	if err != nil {
		return CloudInventory{}, err
	}
	defer release()
	return (azureInventoryClient{http: client, subscription: subscription.String(), token: token}).read(ctx)
}

type azureInventoryClient struct {
	http         *http.Client
	subscription string
	token        []byte
}

func (c azureInventoryClient) read(ctx context.Context) (CloudInventory, error) {
	observedAt := time.Now().UTC()
	subscription := "/subscriptions/" + c.subscription
	networks := subscription + "/providers/Microsoft.Network/"
	vnets, err := c.list(ctx, networks+"virtualNetworks", azureInventoryNetworkVersion, "", MaxCloudInventoryResources)
	if err != nil {
		return CloudInventory{}, fmt.Errorf("topology: Azure virtual networks: %w", err)
	}
	nats, err := c.list(ctx, networks+"natGateways", azureInventoryNetworkVersion, "", MaxCloudInventoryResources)
	if err != nil {
		return CloudInventory{}, fmt.Errorf("topology: Azure NAT gateways: %w", err)
	}
	listed, err := c.list(ctx, subscription+"/resources", azureInventoryResourceVersion, azureInventoryGatewayFilter, azureInventoryMaxGatewayReads)
	if err != nil {
		return CloudInventory{}, fmt.Errorf("topology: Azure virtual network gateway identities: %w", err)
	}
	gateways, err := c.readGateways(ctx, listed)
	if err != nil {
		return CloudInventory{}, fmt.Errorf("topology: Azure virtual network gateways: %w", err)
	}
	return (azureNetworkInventory{vnets: vnets, nats: nats, gateways: gateways}).normalize(c.subscription, observedAt)
}

func (c azureInventoryClient) readGateways(ctx context.Context, listed []azureNetworkObject) ([]azureNetworkObject, error) {
	gateways := make([]azureNetworkObject, 0, len(listed))
	seen := make(map[string]bool, len(listed))
	for _, item := range listed {
		id := azureOwnedNetworkID(item.ID, c.subscription, "virtualNetworkGateways", "")
		if id == "" || !strings.EqualFold(item.Type, azureInventoryGatewayKind) || seen[id] {
			return nil, errors.New("invalid or repeated gateway resource in the subscription list")
		}
		seen[id] = true
		u := azureInventoryURL(item.ID, azureInventoryNetworkVersion, "")
		var gateway azureNetworkObject
		if err := c.get(ctx, u, &gateway); err != nil {
			return nil, err
		}
		if azureOwnedNetworkID(gateway.ID, c.subscription, "virtualNetworkGateways", "") != id {
			return nil, errors.New("gateway response identity changed")
		}
		gateways = append(gateways, gateway)
	}
	return gateways, nil
}

func azureInventoryURL(path, version, filter string) url.URL {
	params := url.Values{"api-version": {version}}
	if filter != "" {
		params.Set("$filter", filter)
	}
	return url.URL{Scheme: "https", Host: azureInventoryHost, Path: path, RawQuery: params.Encode()}
}

func (c azureInventoryClient) list(ctx context.Context, path, version, filter string, maxResults int) ([]azureNetworkObject, error) {
	endpoint := azureInventoryURL(path, version, filter)
	var items []azureNetworkObject
	seen := make(map[string]bool)
	for range cloudInventoryPages {
		var page struct {
			Value    *[]azureNetworkObject `json:"value"`
			NextLink string                `json:"nextLink"`
		}
		if err := c.get(ctx, endpoint, &page); err != nil {
			return nil, err
		}
		if page.Value == nil || len(*page.Value) > maxResults-len(items) {
			return nil, errors.New("list omitted its result set or exceeded the resource budget")
		}
		items = append(items, *page.Value...)
		if page.NextLink == "" {
			return items, nil
		}
		next, cursor, err := azureInventoryContinuation(page.NextLink, path, version, filter)
		if err != nil || seen[cursor] {
			return nil, errors.New("pagination left the configured list or repeated its cursor")
		}
		seen[cursor] = true
		endpoint = next
	}
	return nil, errors.New("list exceeded the page budget")
}

func azureInventoryContinuation(raw, path, version, filter string) (url.URL, string, error) {
	invalid := errors.New("invalid Azure Resource Manager continuation")
	if !cloudInventoryText(raw, 8192) || strings.Contains(raw, "#") {
		return url.URL{}, "", invalid
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, azureInventoryHost) ||
		u.User != nil || u.Opaque != "" || u.RawPath != "" || !strings.EqualFold(u.Path, path) {
		return url.URL{}, "", invalid
	}
	params, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(params["api-version"]) != 1 || params.Get("api-version") != version {
		return url.URL{}, "", invalid
	}
	var cursor string
	filterSeen := false
	for key, values := range params {
		if len(values) != 1 {
			return url.URL{}, "", invalid
		}
		switch strings.ToLower(key) {
		case "api-version":
			if key != "api-version" {
				return url.URL{}, "", invalid
			}
		case "$filter":
			if filterSeen || filter == "" || !strings.EqualFold(values[0], filter) {
				return url.URL{}, "", invalid
			}
			filterSeen = true
		case "$skiptoken", "skiptoken":
			if cursor != "" || !cloudInventoryText(values[0], 4096) {
				return url.URL{}, "", invalid
			}
			cursor = values[0]
		default:
			return url.URL{}, "", invalid
		}
	}
	if cursor == "" {
		return url.URL{}, "", invalid
	}
	// Preserve the provider's paging query after validating each field. Use the
	// configured HTTPS origin and collection path for the next request.
	next := azureInventoryURL(path, version, filter)
	next.RawQuery = u.RawQuery
	return next, cursor, nil
}

func (c azureInventoryClient) get(ctx context.Context, endpoint url.URL, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return errors.New("could not construct request")
	}
	req.Header.Set("Authorization", "Bearer "+string(c.token))
	req.Header.Set("Accept", "application/json")
	body, err := readCloudInventoryResponse(c.http, req)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return errors.New("response is invalid")
	}
	return nil
}
