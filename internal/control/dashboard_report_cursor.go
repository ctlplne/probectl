// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"net/url"
	"strconv"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/store"
)

type reportInboxCursor struct {
	Version  int                          `json:"version"`
	Tenant   string                       `json:"tenant"`
	Owner    string                       `json:"owner"`
	Position store.ReportArtifactPosition `json:"position"`
}

// This cursor is an untrusted position in already-visible metadata, never an
// authority. Every page rechecks current tenant, view and source permissions.
func parseReportInboxPage(query url.Values, tenant, owner string, memory int64) (int, *store.ReportArtifactPosition, error) {
	limit := store.ReportArtifactHeaderBatchRows
	for name, values := range query {
		if (name != "limit" && name != "cursor") || len(values) != 1 {
			return 0, nil, apierror.Validation("report inbox accepts one limit and cursor")
		}
	}
	if raw, ok := query["limit"]; ok {
		value, err := strconv.Atoi(raw[0])
		if err != nil || value < 1 || value > math.MaxInt32-1 {
			return 0, nil, apierror.Validation("report page limit must be a positive representable row count")
		}
		limit = value
	}
	raw := query.Get("cursor")
	if _, present := query["cursor"]; !present {
		return limit, nil, nil
	}
	if raw == "" {
		return 0, nil, apierror.Validation("report inbox cursor is invalid")
	}
	if int64(base64.RawURLEncoding.DecodedLen(len(raw))) > memory/8 {
		return 0, nil, store.ErrReportMetadataBudget
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil {
		return 0, nil, apierror.Validation("report inbox cursor is invalid")
	}
	var cursor reportInboxCursor
	reader := json.NewDecoder(bytes.NewReader(decoded))
	reader.DisallowUnknownFields()
	if err := reader.Decode(&cursor); err != nil {
		return 0, nil, apierror.Validation("report inbox cursor is invalid")
	}
	if reader.Decode(new(any)) != io.EOF {
		return 0, nil, apierror.Validation("report inbox cursor is invalid")
	}
	canonical, err := json.Marshal(cursor)
	if err != nil || !bytes.Equal(canonical, decoded) || cursor.Version != 1 || cursor.Tenant != tenant || cursor.Owner != owner || cursor.Position.GeneratedAt.IsZero() || cursor.Position.ID == "" {
		return 0, nil, apierror.Validation("report inbox cursor differs from the current scope")
	}
	return limit, &cursor.Position, nil
}

func encodeReportInboxCursor(tenant, owner string, position store.ReportArtifactPosition) (string, error) {
	raw, err := json.Marshal(reportInboxCursor{Version: 1, Tenant: tenant, Owner: owner, Position: position})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
