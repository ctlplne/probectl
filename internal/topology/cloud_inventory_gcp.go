// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package topology

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/ctlplne/probectl/internal/secrets"
)

type GCPInventoryConfig struct {
	Project, CredentialRef string
}

var gcpTopologyProject = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)

// DiscoverGCPCloudInventory reads a complete Compute Engine network inventory
// scoped to one project. Each API URL comes from the configured project and a
// fixed list method. Resource references are identifiers, never request URLs.
func DiscoverGCPCloudInventory(ctx context.Context, cfg GCPInventoryConfig, resolver *secrets.Resolver) (CloudInventory, error) {
	client := cloudInventoryHTTPClient()
	defer client.CloseIdleConnections()
	return discoverGCPCloudInventory(ctx, client, cfg, resolver)
}

func discoverGCPCloudInventory(ctx context.Context, client *http.Client, cfg GCPInventoryConfig, resolver *secrets.Resolver) (CloudInventory, error) {
	if !gcpTopologyProject.MatchString(cfg.Project) || resolver == nil {
		return CloudInventory{}, errors.New("topology: GCP inventory requires a project ID and secrets resolver")
	}
	ctx, cancel := context.WithTimeout(ctx, cloudInventoryTimeout)
	defer cancel()
	credential, release, err := resolveCloudInventoryOAuth(ctx, resolver, cfg.CredentialRef)
	if err != nil {
		return CloudInventory{}, err
	}
	defer release()
	source := gcpInventoryClient{http: client, project: cfg.Project, token: credential}
	return source.read(ctx)
}

type gcpInventoryClient struct {
	http    *http.Client
	project string
	token   []byte
}

type gcpInventoryList struct {
	Kind        string          `json:"kind"`
	Items       json.RawMessage `json:"items"`
	Next        string          `json:"nextPageToken"`
	Warning     *gcpListWarning `json:"warning"`
	Unreachable []string        `json:"unreachables"`
}

type gcpListWarning struct {
	Code string `json:"code"`
}

func (c gcpInventoryClient) read(ctx context.Context) (CloudInventory, error) {
	observedAt := time.Now().UTC()
	var raw gcpNetworkInventory
	for _, method := range []struct {
		collection, responseKind string
		aggregated               bool
		dst                      *[]gcpNetworkObject
	}{
		{"networks", "compute#networkList", false, &raw.networks},
		{"subnetworks", "compute#subnetworkAggregatedList", true, &raw.subnets},
		{"vpnGateways", "compute#vpnGatewayAggregatedList", true, &raw.vpn},
		{"targetVpnGateways", "compute#targetVpnGatewayAggregatedList", true, &raw.classicVPN},
		{"routers", "compute#routerAggregatedList", true, &raw.routers},
		{"routes", "compute#routeList", false, &raw.routes},
	} {
		if err := c.list(ctx, method.collection, method.responseKind, method.aggregated, method.dst); err != nil {
			return CloudInventory{}, err
		}
	}
	return raw.normalize(c.project, observedAt)
}

func (c gcpInventoryClient) list(ctx context.Context, collection, responseKind string, aggregate bool, dst *[]gcpNetworkObject) error {
	params := url.Values{"maxResults": {"100"}}
	scope := "global"
	if aggregate {
		scope = "aggregated"
		params.Set("returnPartialSuccess", "false")
	}
	endpoint := url.URL{Scheme: "https", Host: "compute.googleapis.com", Path: "/compute/v1/projects/" + c.project + "/" + scope + "/" + collection}
	seen := make(map[string]bool)
	for range cloudInventoryPages {
		endpoint.RawQuery = params.Encode()
		page, err := c.query(ctx, endpoint.String(), responseKind)
		if err != nil {
			return fmt.Errorf("topology: GCP %s list: %w", collection, err)
		}
		if len(page.Unreachable) != 0 || !gcpCompleteWarning(page.Warning) {
			return fmt.Errorf("topology: GCP %s inventory page is incomplete", collection)
		}
		if err := page.appendItems(collection, aggregate, dst); err != nil {
			return fmt.Errorf("topology: GCP %s inventory: %w", collection, err)
		}
		if page.Next == "" {
			return nil
		}
		if !cloudInventoryText(page.Next, 2048) || seen[page.Next] {
			return fmt.Errorf("topology: GCP %s returned invalid pagination", collection)
		}
		seen[page.Next] = true
		params.Set("pageToken", page.Next)
	}
	return fmt.Errorf("topology: GCP %s exceeds the page budget", collection)
}

func gcpCompleteWarning(warning *gcpListWarning) bool {
	return warning == nil || warning.Code == "NO_RESULTS_ON_PAGE"
}

func (page gcpInventoryList) appendItems(collection string, aggregate bool, dst *[]gcpNetworkObject) error {
	if len(page.Items) == 0 || bytes.Equal(page.Items, []byte("null")) {
		return nil
	}
	if !aggregate {
		return appendGCPInventoryItems(page.Items, dst)
	}
	var scopes map[string]map[string]json.RawMessage
	if err := json.Unmarshal(page.Items, &scopes); err != nil || len(scopes) > MaxCloudInventoryResources {
		return errors.New("invalid regional result set")
	}
	for _, scope := range scopes {
		var warning *gcpListWarning
		if value := scope["warning"]; value != nil {
			if err := json.Unmarshal(value, &warning); err != nil || !gcpCompleteWarning(warning) {
				return errors.New("incomplete regional result set")
			}
		}
		raws := scope[collection]
		if raws == nil && warning == nil {
			return errors.New("regional response omitted its result set")
		}
		if raws != nil {
			if err := appendGCPInventoryItems(raws, dst); err != nil {
				return err
			}
		}
	}
	return nil
}

func appendGCPInventoryItems(raw json.RawMessage, dst *[]gcpNetworkObject) error {
	var items []gcpNetworkObject
	if err := json.Unmarshal(raw, &items); err != nil || len(items) > MaxCloudInventoryResources-len(*dst) {
		return errors.New("invalid result set or resource budget exceeded")
	}
	*dst = append(*dst, items...)
	return nil
}

func (c gcpInventoryClient) query(ctx context.Context, endpoint, responseKind string) (gcpInventoryList, error) {
	var page gcpInventoryList
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return page, errors.New("could not construct request")
	}
	req.Header.Set("Authorization", "Bearer "+string(c.token))
	req.Header.Set("Accept", "application/json")
	body, err := readCloudInventoryResponse(c.http, req)
	if err != nil {
		return page, err
	}
	if err := json.Unmarshal(body, &page); err != nil || page.Kind != responseKind {
		return page, errors.New("response is invalid")
	}
	return page, nil
}
