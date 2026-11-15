// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const azureRangeTermsURL = "https://learn.microsoft.com/en-us/azure/virtual-network/service-tags-overview"

type azureRangeCloud struct {
	cloud, documentID string
	legacy            bool
}

var azureRangeClouds = map[string]azureRangeCloud{
	"azure_public":  {"Public", "56519", false},
	"azure_usgov":   {"AzureGovernment", "57063", false},
	"azure_china":   {"China", "57062", false},
	"azure_germany": {"AzureGermany", "57064", true},
}

func azureDiscoveryURL(cloud azureRangeCloud) string {
	return "https://www.microsoft.com/en-us/download/details.aspx?id=" + cloud.documentID
}

func parseAzureServiceRanges(ctx context.Context, raw []byte, dataset *serviceRangeDataset, remaining *int64, cloud azureRangeCloud) error {
	var document struct {
		Change json.RawMessage `json:"changeNumber"`
		Cloud  string          `json:"cloud"`
		Values []struct {
			Name       string `json:"name"`
			Properties *struct {
				Region   *string  `json:"region"`
				Service  *string  `json:"systemService"`
				Prefixes []string `json:"addressPrefixes"`
			} `json:"properties"`
		} `json:"values"`
	}
	if err := json.Unmarshal(raw, &document); err != nil || document.Cloud != cloud.cloud || document.Values == nil || len(document.Change) == 0 {
		return serviceRangeDecodeError("Azure cloud")
	}
	// The change number is an opaque nonnegative integer, not a timestamp or
	// a machine-sized counter. Keep the publisher's complete decimal identity.
	for _, digit := range document.Change {
		if digit < '0' || digit > '9' {
			return serviceRangeDecodeError("Azure change number")
		}
	}
	dataset.status.Version, dataset.status.TermsURL = string(document.Change), azureRangeTermsURL
	for _, row := range document.Values {
		if err := ctx.Err(); err != nil {
			return err
		}
		properties := row.Properties
		if !validServiceRangeLabel(row.Name) || properties == nil || properties.Region == nil || properties.Service == nil || properties.Prefixes == nil {
			return serviceRangeDecodeError("Azure service tag")
		}
		service, region := *properties.Service, *properties.Region
		if service == "" {
			service = row.Name
			// Only an explicit matching region can be removed from the tag.
			// Purpose suffixes such as AzureFrontDoor.Frontend stay distinct.
			if suffix := "." + region; region != "" && strings.HasSuffix(strings.ToLower(service), strings.ToLower(suffix)) {
				service = service[:len(service)-len(suffix)]
			}
		}
		if !validServiceRangeLabel(service) || region != "" && !validServiceRangeLabel(region) {
			return serviceRangeDecodeError("Azure service or region")
		}
		for _, prefix := range properties.Prefixes {
			if err := dataset.add(ctx, prefix, service, region, remaining); err != nil {
				return err
			}
		}
	}
	return nil
}

// Microsoft rotates weekly filenames. Discover the one complete cloud export
// from its fixed publisher page rather than retaining a dated download URL.
func fetchAzureServiceRangeInput(ctx context.Context, client Doer, publisher string, cloud azureRangeCloud, limit int64) (serviceRangeInput, error) {
	page, discoveredAt, err := fetchServiceRangeBody(ctx, client, azureDiscoveryURL(cloud), "text/html", limit)
	if err != nil {
		return serviceRangeInput{}, err
	}
	endpoint, err := azureServiceRangeDownloadURL(page, cloud)
	if err != nil {
		return serviceRangeInput{}, err
	}
	raw, fetchedAt, err := fetchServiceRangeBody(ctx, client, endpoint, "application/json", limit)
	if err != nil {
		return serviceRangeInput{}, err
	}
	if discoveredAt.Before(fetchedAt) {
		fetchedAt = discoveredAt
	}
	return serviceRangeInput{Publisher: publisher, FetchedAt: fetchedAt, Complete: true, Data: raw}, nil
}

func azureServiceRangeDownloadURL(page []byte, cloud azureRangeCloud) (string, error) {
	tokens := html.NewTokenizer(bytes.NewReader(page))
	var found string
	for {
		switch tokens.Next() {
		case html.ErrorToken:
			if !errors.Is(tokens.Err(), io.EOF) || found == "" {
				return "", errors.New("azure discovery has no unique complete cloud download")
			}
			return found, nil
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokens.Token()
			if token.Data != "a" {
				continue
			}
			for _, attribute := range token.Attr {
				if attribute.Key != "href" {
					continue
				}
				endpoint, err := url.Parse(attribute.Val)
				if err != nil || endpoint.Scheme != "https" || endpoint.Host != "download.microsoft.com" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.RawPath != "" || !strings.HasPrefix(endpoint.Path, "/download/") || path.Clean(endpoint.Path) != endpoint.Path {
					continue
				}
				name := strings.TrimPrefix(path.Base(endpoint.Path), "ServiceTags_"+cloud.cloud+"_")
				date := strings.TrimSuffix(name, ".json")
				if len(date) != 8 || name != date+".json" || path.Base(endpoint.Path) != "ServiceTags_"+cloud.cloud+"_"+date+".json" {
					continue
				}
				if _, err := time.Parse("20060102", date); err != nil {
					continue
				}
				if found != "" && found != endpoint.String() {
					return "", errors.New("azure discovery contains ambiguous cloud downloads")
				}
				found = endpoint.String()
			}
		}
	}
}
