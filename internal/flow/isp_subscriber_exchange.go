// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"encoding/csv"
	"errors"
	"regexp"
	"strings"
	"time"
)

type SubscriberExchangeRequest struct {
	Target     string `json:"target"`
	ExternalID string `json:"external_id"`
}

type SubscriberExchangePreview struct {
	Target  string `json:"target"`
	Preview bool   `json:"preview"`
	CSV     string `json:"csv"`
}

var subscriberExchangeID = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:@-]{0,127}$`)

func (selection SubscriberExchangeRequest) identifierColumn() string {
	switch selection.Target {
	case "splynx":
		return "service_id"
	case "sonar":
		return "account_id"
	case "uisp":
		return "subscriber_id"
	default:
		return ""
	}
}

func (selection SubscriberExchangeRequest) Validate() error {
	if selection.identifierColumn() == "" || !subscriberExchangeID.MatchString(selection.ExternalID) {
		return errors.New("select a supported exchange preview and a stable external identifier")
	}
	return nil
}

// SubscriberExchangeCSV maps the operator's external identifier to the same
// exact report counters. The vendor preview starts from one authorized usage
// report and exposes its observation and tag revision with the exported row.
func SubscriberExchangeCSV(report SubscriberUsageReport, selection SubscriberExchangeRequest) (SubscriberExchangePreview, error) {
	var out SubscriberExchangePreview
	if err := selection.Validate(); err != nil {
		return out, err
	}
	var csvBody strings.Builder
	writer := csv.NewWriter(&csvBody)
	if err := writer.WriteAll([][]string{
		{selection.identifierColumn(), "observed_from_utc", "observed_to_utc",
			"download_bytes", "upload_bytes", "within_subscriber_bytes", "total_bytes",
			"download_packets", "upload_packets", "within_subscriber_packets", "total_packets",
			"view_version", "tag_revision"},
		{selection.ExternalID, report.From.UTC().Format(time.RFC3339Nano), report.To.UTC().Format(time.RFC3339Nano),
			report.Download.Bytes, report.Upload.Bytes, report.Internal.Bytes, report.Total.Bytes,
			report.Download.Packets, report.Upload.Packets, report.Internal.Packets, report.Total.Packets,
			report.ViewVersion, report.TagRevision},
	}); err != nil {
		return out, err
	}
	return SubscriberExchangePreview{Target: selection.Target, Preview: true, CSV: csvBody.String()}, nil
}
