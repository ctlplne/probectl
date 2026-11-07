// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// BGPRoutingDecodeProfile carries only the current operator's wire grammar and
// complete permitted families. It contains no tenant or canonical target grant.
type BGPRoutingDecodeProfile struct {
	Format   string
	Families []uint16
}

// StagePeerWithDecoderInScope selects the wire grammar before decoding under
// the same tenant-account and source locks as staging and operator replacement.
// A caller cannot retain a profile across a configuration/credential change.
// The bounded fixed Peer Up key selects configuration, never canonical IDs.
func (store BGPRouting) StagePeerWithDecoderInScope(ctx context.Context, sc tenancy.Scope, input BGPRoutingPeerUpInput, budget BGPRoutingBudget,
	decode func(BGPRoutingDecodeProfile) ([]BGPRoutingViewDefinition, error)) (BGPRoutingStageResult, error) {
	if decode == nil || len(input.Definitions) != 0 {
		return BGPRoutingStageResult{}, ErrBGPRoutingView
	}
	base, err := routingStageSource(ctx, sc, input, budget)
	if err != nil {
		return BGPRoutingStageResult{}, err
	}
	// Match the operator writer's lock order; holding a source row first would
	// deadlock against a replacement already holding this tenant account.
	if err := lockBGPRoutingState(ctx, sc); err != nil {
		return BGPRoutingStageResult{}, err
	}
	profile, err := routingDecodeProfile(ctx, sc, base, input.RefusedPeer, budget)
	if err != nil {
		if routingMetadataRefusal(err) {
			return store.StagePeerInScope(ctx, sc, input, budget)
		}
		return BGPRoutingStageResult{}, err
	}
	definitions, err := decode(profile)
	if err == nil {
		input.Definitions = definitions
	}
	// A failed complete decode can only retire known state. StagePeerInScope
	// rechecks current credentials, epoch, selector and every family atomically.
	return store.StagePeerInScope(ctx, sc, input, budget)
}

func routingDecodeProfile(ctx context.Context, sc tenancy.Scope, base BGPRoutingSource, peer *BGPRoutingPeer, budget BGPRoutingBudget) (BGPRoutingDecodeProfile, error) {
	metadata, err := routingBaseAuthority(ctx, sc, base)
	if err != nil {
		return BGPRoutingDecodeProfile{}, err
	}
	config, err := loadRoutingSourceConfiguration(ctx, sc, base.CollectorAgentID, base.SourceRef, budget)
	if err != nil {
		return BGPRoutingDecodeProfile{}, err
	}
	if config.Manifest == nil {
		if metadata.Epoch != "" || peer != nil && peer.Distinguisher != ([8]byte{}) {
			return BGPRoutingDecodeProfile{}, errBGPRoutingContextBinding
		}
		return BGPRoutingDecodeProfile{}, nil
	}
	if peer == nil {
		return BGPRoutingDecodeProfile{}, ErrBGPRoutingView
	}
	if config.BaseContextID != base.ContextID || config.BaseRouterID != base.RouterID ||
		config.Manifest.Epoch != metadata.Epoch || !config.Manifest.AssignedAt.Equal(metadata.AssignedAt) {
		return BGPRoutingDecodeProfile{}, errBGPRoutingContextBinding
	}
	selected, err := selectRoutingSourceByPeer(ctx, sc, config, *peer)
	if err != nil {
		return BGPRoutingDecodeProfile{}, err
	}
	if selected.Binding.SourceFormat == "" {
		return BGPRoutingDecodeProfile{}, nil
	}
	return BGPRoutingDecodeProfile{Format: selected.Binding.SourceFormat, Families: append([]uint16(nil), selected.Binding.Families...)}, nil
}
