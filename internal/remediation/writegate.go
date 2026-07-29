// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package remediation

import (
	"context"

	"github.com/imfeelingtheagi/probectl/internal/license"
)

// GateServiceWrites preserves proposal review while denying every proposal or
// decision mutation before it reaches the ee delegate whenever the shared
// license write capability is disabled. REST and MCP both receive this same
// decorated Service from the attach seam.
func GateServiceWrites(delegate Service, writes license.WriteCapability) Service {
	if delegate == nil {
		return nil
	}
	return writeGatedService{delegate: delegate, writes: writes}
}

type writeGatedService struct {
	delegate Service
	writes   license.WriteCapability
}

func (g writeGatedService) Propose(ctx context.Context, tenantID, proposedBy string, in ProposeInput) (Proposal, error) {
	if !g.writes.Enabled() {
		return Proposal{}, license.ErrReadOnly
	}
	return g.delegate.Propose(ctx, tenantID, proposedBy, in)
}

func (g writeGatedService) List(ctx context.Context, tenantID string) ([]Proposal, error) {
	return g.delegate.List(ctx, tenantID)
}

func (g writeGatedService) Get(ctx context.Context, tenantID, id string) (Proposal, error) {
	return g.delegate.Get(ctx, tenantID, id)
}

func (g writeGatedService) Approve(ctx context.Context, tenantID, approver, id, note string) (Proposal, error) {
	if !g.writes.Enabled() {
		return Proposal{}, license.ErrReadOnly
	}
	return g.delegate.Approve(ctx, tenantID, approver, id, note)
}

func (g writeGatedService) Reject(ctx context.Context, tenantID, decider, id, note string) (Proposal, error) {
	if !g.writes.Enabled() {
		return Proposal{}, license.ErrReadOnly
	}
	return g.delegate.Reject(ctx, tenantID, decider, id, note)
}

func (g writeGatedService) ApprovalsEnabled() bool {
	return g.delegate.ApprovalsEnabled()
}
