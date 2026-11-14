// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
)

// The opaque destination ID binds tenant consent to exact configured recipients.
// A recipient change creates a new ID; old schedules cannot silently redirect.
func reportEmailDestinationID(destination config.ReportEmailDestination) string {
	raw, _ := json.Marshal(struct {
		Tenant, ID string
		Recipients []string
	}{destination.TenantID, destination.ID, destination.Recipients})
	return "email/" + destination.ID + "/" + hex.EncodeToString(crypto.Hash(raw))
}
func (s *Server) reportEmailDestination(tenant, id string) (config.ReportEmailDestination, error) {
	if s == nil || s.cfg == nil {
		return config.ReportEmailDestination{}, apierror.Validation("report destination is not configured")
	}
	for _, destination := range s.cfg.ReportEmailDestinations {
		if destination.TenantID == tenant && reportEmailDestinationID(destination) == id {
			return destination, nil
		}
	}
	return config.ReportEmailDestination{}, apierror.Validation("report destination is not configured for this tenant or its recipients changed")
}
func (s *Server) validateReportDestination(tenant, id string) error {
	if id == reportInboxDestination {
		return nil
	}
	if _, err := s.reportEmailDestination(tenant, id); err != nil {
		return err
	}
	if _, ok := s.alertChannelDeps.Mail.(alert.AttachmentMailSender); !ok {
		return apierror.Unavailable("report email transport is not configured")
	}
	return nil
}
func (s *Server) reportDestinations(tenant string) []reportDestination {
	result := []reportDestination{{ID: reportInboxDestination, Name: "Tenant report inbox", Kind: "local", Ready: true}}
	if s.cfg == nil {
		return result
	}
	_, ready := s.alertChannelDeps.Mail.(alert.AttachmentMailSender)
	for _, destination := range s.cfg.ReportEmailDestinations {
		if destination.TenantID == tenant {
			result = append(result, reportDestination{ID: reportEmailDestinationID(destination), Name: destination.Name, Description: strings.Join(destination.Recipients, ", "), Kind: "email", Outbound: true, Ready: ready})
		}
	}
	return result
}
