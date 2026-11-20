// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package remediation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/license"
)

type routingGateDelegate struct {
	remediationDelegateSpy
	ctx    context.Context
	want   string
	called bool
	t      *testing.T
}

func (d *routingGateDelegate) call(ctx context.Context, verb, tenant string, check func(context.Context) error) error {
	d.t.Helper()
	if d.called || verb != d.want || tenant != "owned-tenant" || ctx != d.ctx {
		d.t.Fatal("routing gate forwarded unexpected scope or operation", verb, tenant)
	}
	d.called = true
	return check(ctx)
}

func (d *routingGateDelegate) PreviewFlowSpec(ctx context.Context, tenant string, _ FlowSpecPreviewInput, check func(context.Context) error) (FlowSpecPreview, error) {
	return FlowSpecPreview{}, d.call(ctx, "flowspec preview", tenant, check)
}
func (d *routingGateDelegate) ProposeFlowSpec(ctx context.Context, tenant, _ string, _ FlowSpecProposalInput, check func(context.Context) error) (Proposal, error) {
	return Proposal{}, d.call(ctx, "flowspec propose", tenant, check)
}
func (d *routingGateDelegate) GetFlowSpecReview(ctx context.Context, tenant, _ string, check func(context.Context) error) (FlowSpecReview, error) {
	return FlowSpecReview{}, d.call(ctx, "flowspec review", tenant, check)
}
func (d *routingGateDelegate) QualifyFlowSpec(ctx context.Context, tenant, _ string, _ FlowSpecQualificationInput, check func(context.Context) error) (FlowSpecQualification, error) {
	return FlowSpecQualification{}, d.call(ctx, "flowspec qualify", tenant, check)
}
func (d *routingGateDelegate) ApproveFlowSpec(ctx context.Context, tenant, _ string, _ string, _ FlowSpecApprovalInput, check func(context.Context) error) (Proposal, error) {
	return Proposal{}, d.call(ctx, "flowspec approve", tenant, check)
}
func (d *routingGateDelegate) GetFlowSpecHandoff(ctx context.Context, tenant, _ string, check func(context.Context) error) (FlowSpecHandoffStatus, error) {
	return FlowSpecHandoffStatus{}, d.call(ctx, "flowspec handoff", tenant, check)
}
func (d *routingGateDelegate) WithdrawFlowSpecHandoff(ctx context.Context, tenant, _ string, _ string, publication RTBHImpactPublication) (FlowSpecHandoffStatus, error) {
	return FlowSpecHandoffStatus{}, d.call(ctx, "flowspec withdraw", tenant, func(context.Context) error { return errors.New(publication.Scope) })
}
func (d *routingGateDelegate) PreviewDiversion(ctx context.Context, tenant string, _ DiversionPreviewInput, check func(context.Context) error) (DiversionPreview, error) {
	return DiversionPreview{}, d.call(ctx, "diversion preview", tenant, check)
}
func (d *routingGateDelegate) ProposeDiversion(ctx context.Context, tenant, _ string, _ DiversionProposalInput, check func(context.Context) error, _ RTBHImpactPublication) (Proposal, error) {
	return Proposal{}, d.call(ctx, "diversion propose", tenant, check)
}
func (d *routingGateDelegate) GetDiversionReview(ctx context.Context, tenant, _ string, check func(context.Context) error) (DiversionReview, error) {
	return DiversionReview{}, d.call(ctx, "diversion review", tenant, check)
}
func (d *routingGateDelegate) ApproveDiversion(ctx context.Context, tenant, _ string, _ string, _ DiversionApprovalInput, check func(context.Context) error, _ RTBHImpactPublication) (DiversionReceipt, error) {
	return DiversionReceipt{}, d.call(ctx, "diversion approve", tenant, check)
}

func TestRoutingReviewWritesRequireLicenseAndReadsRetainAuthority(t *testing.T) {
	const tenant, actor, id = "owned-tenant", "reviewer", "proposal"
	ctx := t.Context()
	authorityErr := errors.New("current authority unavailable")
	check := func(context.Context) error { return authorityErr }
	publication := RTBHImpactPublication{Scope: authorityErr.Error()}
	for _, test := range []struct {
		name   string
		writes bool
		invoke func(writeGatedService) error
	}{
		{"flowspec preview", false, func(g writeGatedService) error {
			_, err := g.PreviewFlowSpec(ctx, tenant, FlowSpecPreviewInput{}, check)
			return err
		}},
		{"flowspec propose", true, func(g writeGatedService) error {
			_, err := g.ProposeFlowSpec(ctx, tenant, actor, FlowSpecProposalInput{}, check)
			return err
		}},
		{"flowspec review", false, func(g writeGatedService) error {
			_, err := g.GetFlowSpecReview(ctx, tenant, id, check)
			return err
		}},
		{"flowspec qualify", false, func(g writeGatedService) error {
			_, err := g.QualifyFlowSpec(ctx, tenant, id, FlowSpecQualificationInput{}, check)
			return err
		}},
		{"flowspec approve", true, func(g writeGatedService) error {
			_, err := g.ApproveFlowSpec(ctx, tenant, actor, id, FlowSpecApprovalInput{}, check)
			return err
		}},
		{"flowspec handoff", false, func(g writeGatedService) error {
			_, err := g.GetFlowSpecHandoff(ctx, tenant, id, check)
			return err
		}},
		{"flowspec withdraw", true, func(g writeGatedService) error {
			_, err := g.WithdrawFlowSpecHandoff(ctx, tenant, actor, id, publication)
			return err
		}},
		{"diversion preview", false, func(g writeGatedService) error {
			_, err := g.PreviewDiversion(ctx, tenant, DiversionPreviewInput{}, check)
			return err
		}},
		{"diversion propose", true, func(g writeGatedService) error {
			_, err := g.ProposeDiversion(ctx, tenant, actor, DiversionProposalInput{}, check, publication)
			return err
		}},
		{"diversion review", false, func(g writeGatedService) error {
			_, err := g.GetDiversionReview(ctx, tenant, id, check)
			return err
		}},
		{"diversion approve", true, func(g writeGatedService) error {
			_, err := g.ApproveDiversion(ctx, tenant, actor, id, DiversionApprovalInput{}, check, publication)
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			spy := &routingGateDelegate{ctx: ctx, want: test.name, t: t}
			readOnly := writeGatedService{delegate: spy, writes: license.WriteCapability(func() bool { return false })}
			err := test.invoke(readOnly)
			if test.writes {
				if !errors.Is(err, license.ErrReadOnly) || spy.called {
					t.Fatal("read-only license permitted a routing write", err)
				}
				enabled := writeGatedService{delegate: spy, writes: license.WriteCapability(func() bool { return true })}
				err = test.invoke(enabled)
			}
			if err == nil || err.Error() != authorityErr.Error() || !spy.called {
				t.Fatal("the delegated authority failure was lost", err)
			}
			unavailable := writeGatedService{delegate: &remediationDelegateSpy{}, writes: license.WriteCapability(func() bool { return true })}
			var typed Error
			if err := test.invoke(unavailable); !errors.As(err, &typed) || typed.Code != "not_found" {
				t.Fatal("missing routing service did not fail closed", err)
			}
		})
	}
}

func TestFlowSpecHandoffStateUsesExclusiveExpiryAndWithdrawalIntent(t *testing.T) {
	expires := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	active := FlowSpecHandoff{ExpiresAt: expires}
	if active.State(expires.Add(-time.Nanosecond)) != FlowSpecAuthorized || active.State(expires) != FlowSpecExpired {
		t.Fatal("handoff did not expire at its exact authorized boundary")
	}
	active.WithdrawRequested = &expires
	if active.State(expires.Add(time.Second)) != FlowSpecWithdrawalRequested {
		t.Fatal("withdrawal intent was lost when the authorization expired")
	}
}
