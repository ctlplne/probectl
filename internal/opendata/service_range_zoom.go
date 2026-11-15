// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"errors"
	"slices"
	"strings"
	"unicode/utf8"
)

const zoomRangeTermsURL = "https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0060548"

type zoomRangePublisher struct {
	file, service string
	family        int
	networkOnly   bool
}

// All original text downloads linked by the publisher. Port variants retain
// their own source IDs, even when their ranges overlap. Dependency lists do
// not prove an application: shared cloud/CDN addresses remain provenance only.
var zoomRangePublishers = map[string]zoomRangePublisher{
	"zoom_common":                {"Zoom.txt", "Zoom", 0, false},
	"zoom_meetings_ipv4":         {"ZoomMeetings.txt", "Zoom Meetings", 32, false},
	"zoom_meetings_ipv6":         {"ZoomMeetings-IPv6.txt", "Zoom Meetings", 128, false},
	"zoom_crc":                   {"ZoomCRC.txt", "Zoom Cloud Room Connector", 0, false},
	"zoom_phone_ipv4":            {"ZoomPhone.txt", "Zoom Phone", 32, false},
	"zoom_phone_ipv6":            {"ZoomPhone-IPv6.txt", "Zoom Phone", 128, false},
	"zoom_phone_tcp443":          {"ZoomPhone-TCP443.txt", "Zoom Phone", 0, false},
	"zoom_phone_tcp5091":         {"ZoomPhone-TCP5091.txt", "Zoom Phone", 0, false},
	"zoom_phone_tcp390":          {"ZoomPhone-TCP390.txt", "Zoom Phone", 0, false},
	"zoom_phone_udp3478":         {"ZoomPhone-UDP3478.txt", "Zoom Phone", 0, false},
	"zoom_phone_udp20000_64000":  {"ZoomPhone-UDP20000-64000.txt", "Zoom Phone", 0, false},
	"zoom_contact_center_ipv4":   {"ZoomCC.txt", "Zoom Contact Center", 32, false},
	"zoom_contact_center_ipv6":   {"ZoomCC-IPv6.txt", "Zoom Contact Center", 128, false},
	"zoom_contact_center_widget": {"ZCCFlowScriptCallWidget.txt", "Zoom Contact Center widget network dependency", 0, true},
	"zoom_virtual_agent_ipv4":    {"ZoomZVA.txt", "Zoom Virtual Agent", 32, false},
	"zoom_virtual_agent_ipv6":    {"ZoomZVA-IPv6.txt", "Zoom Virtual Agent", 128, false},
	"zoom_virtual_agent_widget":  {"ZVAFlowScriptCallWidget.txt", "Zoom Virtual Agent widget network dependency", 0, true},
	"zoom_cdn_ipv4":              {"ZoomCDN.txt", "Zoom CDN network dependency", 32, true},
	"zoom_cdn_ipv6":              {"ZoomCDN-IPv6.txt", "Zoom CDN network dependency", 128, true},
	"zoom_apps":                  {"ZoomApps.txt", "Zoom Apps network dependency", 0, true},
	"zoom_apps_ipv6":             {"ZoomApps-IPv6.txt", "Zoom Apps network dependency", 128, true},
	"zoom_pso_ipv4":              {"ZoomPSO.txt", "Zoom PSO Network Assessment", 32, false},
}

func expandServiceRangePublishers(publishers []string) []string {
	var expanded []string
	for _, publisher := range publishers {
		if publisher != "zoom" && publisher != "m365" && publisher != "azure" {
			expanded = append(expanded, publisher)
			continue
		}
		var originals []string
		switch publisher {
		case "zoom":
			for id := range zoomRangePublishers {
				originals = append(originals, id)
			}
		case "m365":
			for id := range m365RangeInstances {
				originals = append(originals, id)
			}
		case "azure":
			for id := range azureRangeClouds {
				originals = append(originals, id)
			}
		}
		slices.Sort(originals)
		expanded = append(expanded, originals...)
	}
	return expanded
}

func validateServiceRangeDocument(ctx context.Context, publisher string, raw []byte) error {
	if _, text := zoomRangePublishers[publisher]; !text {
		return validateServiceJSON(ctx, raw)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !utf8.Valid(raw) {
		return errors.New("published text range document must be valid UTF-8")
	}
	return nil
}

func parseZoomServiceRanges(ctx context.Context, raw []byte, dataset *serviceRangeDataset, remaining *int64, source zoomRangePublisher) error {
	dataset.status.Version = "sha256:" + dataset.status.Digest
	dataset.status.TermsURL = zoomRangeTermsURL
	for original := range strings.FieldsSeq(string(raw)) {
		prefix, err := serviceRangeAddressPrefix(original)
		if err != nil {
			return err
		}
		if source.family != 0 && !serviceRangeFamily(prefix, source.family == 32) {
			return serviceRangeDecodeError("Zoom address family")
		}
		if err := dataset.add(ctx, prefix, source.service, "", remaining); err != nil {
			return err
		}
	}
	return ctx.Err()
}
