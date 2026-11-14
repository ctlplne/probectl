// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"encoding/json"
	"io"
	"net/mail"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// ReportEmailDestination is deployment-managed routing metadata. Tenant APIs
// select only a matching configured destination; no request supplies recipients
// or SMTP credentials. SMTP uses the existing PROBECTL_ALERT_SMTP_* transport.
type ReportEmailDestination struct {
	TenantID   string   `json:"tenant_id"`
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Recipients []string `json:"recipients"`
}

func (l *loader) reportEmailDestinations(key string) []ReportEmailDestination {
	raw := strings.TrimSpace(l.str(key, ""))
	if raw == "" {
		return nil
	}
	var destinations []ReportEmailDestination
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&destinations); err != nil {
		l.errf("%s: expected a JSON array of tenant email destinations", key)
		return nil
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		l.errf("%s: trailing JSON is not allowed", key)
		return nil
	}
	seen := map[string]bool{}
	for _, destination := range destinations {
		tenant, err := uuid.Parse(destination.TenantID)
		if err != nil || tenant == uuid.Nil || tenant.String() != destination.TenantID || !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(destination.ID) || strings.TrimSpace(destination.Name) == "" || len(destination.Recipients) == 0 {
			l.errf("%s: canonical tenant, nonempty destination ID/name and recipients are required", key)
			continue
		}
		identity := destination.TenantID + "/" + destination.ID
		if seen[identity] {
			l.errf("%s: destination IDs must be unique inside a tenant", key)
		}
		seen[identity] = true
		recipients := map[string]bool{}
		for _, recipient := range destination.Recipients {
			parsed, err := mail.ParseAddress(recipient)
			if err != nil || parsed.Address != recipient || strings.ContainsAny(recipient, "\r\n") || recipients[recipient] {
				l.errf("%s: recipients must be distinct bare mail addresses", key)
			}
			recipients[recipient] = true
		}
	}
	return destinations
}
