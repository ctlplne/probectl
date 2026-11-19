// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"context"
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/license"
	rem "github.com/ctlplne/probectl/internal/remediation"
)

type prefixImpactSourceFunc func(context.Context, string, rem.PrefixImpactInput, func(context.Context) error) (rem.PrefixImpact, error)

func (f prefixImpactSourceFunc) ObservePrefixImpact(ctx context.Context, tenant string, input rem.PrefixImpactInput,
	check func(context.Context) error) (rem.PrefixImpact, error) {
	return f(ctx, tenant, input, check)
}

func TestRTBHPreviewRequiresPolicyAndKeepsTheProposalLedgerReadOnly(t *testing.T) {
	ctx := remediationTestActor(t.Context(), testTenant, testProposerID)
	var reads int
	memory := NewMemStore()
	source := prefixImpactSourceFunc(func(ctx context.Context, tenant string, _ rem.PrefixImpactInput, check func(context.Context) error) (rem.PrefixImpact, error) {
		if tenant != testTenant {
			t.Fatal("the preview source received a different tenant", tenant)
		}
		if err := check(ctx); err != nil {
			return rem.PrefixImpact{}, err
		}
		reads++
		return rem.PrefixImpact{Prefix: "192.0.2.0/24", Matched: rem.PrefixTraffic{Bytes: "9007199254740993", Packets: "80"},
			KnownBenign: rem.PrefixTraffic{Bytes: "300", Packets: "3"}}, nil
	})
	svc := rem.GateServiceWrites(New(memory, nil, nil, Config{PrefixImpact: source}), license.WriteCapability(func() bool { return false }))
	previewer, ok := svc.(rem.RTBHPreviewer)
	if !ok {
		t.Fatal("the read-only license seam lost traffic preview")
	}
	verify := func(ctx context.Context) error { return ctx.Err() }
	for _, input := range []rem.RTBHPreviewInput{
		{Community: "64512:100"},
		{Community: "064512:100", RoutingPolicyAgreed: true},
		{Community: "64512:65536", RoutingPolicyAgreed: true},
	} {
		if _, err := previewer.PreviewRTBH(ctx, testTenant, input, verify); err == nil || reads != 0 {
			t.Fatal("an unconfirmed or invalid policy reached the source", err)
		}
	}
	input := rem.RTBHPreviewInput{Community: "64512:100", RoutingPolicyAgreed: true}
	if _, err := previewer.PreviewRTBH(ctx, testTenantB, input, verify); !errors.Is(err, rem.ErrApprovalActorUnavailable) || reads != 0 {
		t.Fatal("a foreign tenant selected the collateral source", err)
	}
	got, err := previewer.PreviewRTBH(ctx, testTenant, input, verify)
	if err != nil || got.Announcement != (rem.RTBHAnnouncement{Family: "ipv4", Prefix: "192.0.2.0/24", Community: "64512:100"}) ||
		got.Impact.Matched.Bytes != "9007199254740993" || got.Impact.KnownBenign.Bytes != "300" || reads != 1 {
		t.Fatal("the reviewed observation and route attributes did not stay together", got, err)
	}
	if proposals, err := memory.List(ctx, testTenant); err != nil || len(proposals) != 0 {
		t.Fatal("an evidence preview wrote a proposal", err)
	}
}
