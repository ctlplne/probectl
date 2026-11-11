// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type publicSnapshotWriteState struct {
	state                                                               string
	observedNanos, lastClock, nextSequence, lastSequence, expectedViews int64
	manifestDigest, lastDigest                                          []byte
	sourceClock                                                         *int64
	sourceRecord                                                        []byte
	until                                                               time.Time
}

type publicSnapshotMessageDecoder func(context.Context, tenancy.Scope, BGPPublicRoutingSource, publicSnapshotWriteState) ([]BGPPublicSnapshotBatch, error)

// The shipping MRT adapter supplies complete source framing/EOF validation;
// peer-up or subscription alone never grants completeness. All errors abort;
// invalidated is a committed refusal. Published snapshots retain original data
// age and complete peer sets until replacement. Tests also exercise the same
// transaction with prepared batches and no raw decoder.
func (store BGPRouting) applyPublicSnapshotMessage(ctx context.Context, sc tenancy.Scope, input BGPPublicSnapshotMessage, profile BGPRoutingBudget, maxAge time.Duration, decode publicSnapshotMessageDecoder) (BGPRoutingApplyResult, error) {
	none := BGPRoutingApplyResult{}
	if err := routingConfigurationScope(ctx, sc); err != nil {
		return none, err
	}
	if !input.Reset && maxAge <= 0 {
		return none, ErrBGPRoutingBudget
	}
	if id, err := validRegistryUUID(input.SnapshotID); err != nil || id != input.SnapshotID {
		return none, ErrBGPRoutingView
	}
	if err := lockBGPRoutingState(ctx, sc); err != nil {
		return none, err
	}
	source, err := resolvePublicSnapshotSource(ctx, sc, BGPPublicSnapshotInput{CollectorAgentID: input.CollectorAgentID, SenderSerial: input.SenderSerial, SourceRef: input.SourceRef, ObservedAt: input.ObservedAt})
	if err != nil {
		return none, err
	}
	authority, err := store.publicSourceAuthorityInScope(ctx, sc, source, true)
	if err != nil {
		return none, err
	}
	header, err := loadPublicSnapshotWriteState(ctx, sc, source, input.SnapshotID, profile, !input.Reset)
	if err != nil {
		return none, err
	}
	birth := source
	birth.ObservedAt = time.Unix(0, header.observedNanos)
	if _, err := store.publicSourceAuthorityInScope(ctx, sc, birth, true); err != nil {
		return none, err
	}
	refuse := func(reason string) (BGPRoutingApplyResult, error) {
		return refusePublicSnapshotMessage(ctx, sc, source, input.SnapshotID, reason, false)
	}
	if input.Reset {
		if err := validatePublicSnapshotMessage(input); err != nil {
			return refuse("invalid-reset")
		}
		return refuse("source-reset")
	}
	if header.state == "invalid" || !header.until.After(authority.AsOf) {
		return refuse("inactive-snapshot")
	}
	if decode != nil {
		input.Batches, err = decode(ctx, sc, source, header)
		if err != nil {
			if ctx.Err() != nil {
				return none, ctx.Err()
			}
			if publicMRTFrameRefusal(err) {
				return refuse("invalid-source-frame")
			}
			return none, err
		}
	}
	prepared, digest, err := preparePublicSnapshotMessage(ctx, input, profile)
	if err != nil {
		if ctx.Err() != nil {
			return none, ctx.Err()
		}
		return refuse("invalid-message")
	}
	if input.ObservedAt.UnixNano() < header.lastClock {
		return refuse("regressed-source-message")
	}
	if input.Sequence == header.lastSequence && bytes.Equal(digest[:], header.lastDigest) {
		if header.state == "current" {
			if _, err := publicSnapshotDataLease(header.sourceClock, authority.AsOf, header.until, authority.ValidUntil, maxAge); err != nil {
				return refuse("stale-public-data")
			}
		}
		return BGPRoutingApplyResult{Status: "replayed"}, nil
	}
	if input.Sequence != header.nextSequence || header.state != "staging" {
		return refuse("sequence-gap-or-conflict")
	}
	return store.persistPublicSnapshotMessage(ctx, sc, source, input, header, prepared, digest, profile, maxAge)
}

func (store BGPRouting) persistPublicSnapshotMessage(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource, input BGPPublicSnapshotMessage, header publicSnapshotWriteState, prepared []preparedPublicBatch, digest [32]byte, profile BGPRoutingBudget, maxAge time.Duration) (BGPRoutingApplyResult, error) {
	none := BGPRoutingApplyResult{}
	birth := source
	birth.ObservedAt = time.Unix(0, header.observedNanos)
	if _, err := sc.Q.Exec(ctx, "SAVEPOINT public_snapshot_message"); err != nil {
		return none, err
	}
	for _, batch := range prepared {
		if err := persistPublicSnapshotBatch(ctx, sc, source, input.SnapshotID, batch, profile); err != nil {
			if errors.Is(err, ErrBGPRoutingView) || errors.Is(err, ErrBGPRoutingBatch) || errors.Is(err, ErrBGPRoutingBudget) || errors.Is(err, ErrBGPRoutingSourceUnavailable) {
				return refusePublicSnapshotMessage(ctx, sc, source, input.SnapshotID, "invalid-batch", true)
			}
			return none, err
		}
	}
	until := header.until
	if input.Complete {
		if err := verifyPublicSnapshotManifest(ctx, sc, birth, input.SnapshotID, header, profile); err != nil {
			if ctx.Err() != nil {
				return none, ctx.Err()
			}
			return refusePublicSnapshotMessage(ctx, sc, source, input.SnapshotID, "incomplete-manifest", true)
		}
	}
	current, err := store.publicSourceAuthorityInScope(ctx, sc, birth, true)
	if err != nil {
		return none, err
	}
	if input.Complete {
		until, err = publicSnapshotDataLease(header.sourceClock, current.AsOf, header.until, current.ValidUntil, maxAge)
		if err != nil {
			return refusePublicSnapshotMessage(ctx, sc, source, input.SnapshotID, "stale-public-data", true)
		}
	}
	if !until.After(current.AsOf) {
		return refusePublicSnapshotMessage(ctx, sc, source, input.SnapshotID, "expired-during-write", true)
	}
	if err := finishPublicSnapshotMessage(ctx, sc, source, input, header, digest, until); err != nil {
		return none, err
	}
	final, err := store.publicSourceAuthorityInScope(ctx, sc, birth, true)
	if err != nil {
		return none, err
	}
	if !until.After(final.AsOf) {
		return refusePublicSnapshotMessage(ctx, sc, source, input.SnapshotID, "expired-during-publication", true)
	}
	if _, err := sc.Q.Exec(ctx, "RELEASE SAVEPOINT public_snapshot_message"); err != nil {
		return none, err
	}
	return BGPRoutingApplyResult{Status: "applied"}, nil
}

func loadPublicSnapshotWriteState(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource, id string, profile BGPRoutingBudget, includeRecord bool) (publicSnapshotWriteState, error) {
	var header publicSnapshotWriteState
	var hasSourceRecord bool
	err := sc.Q.QueryRow(ctx, `SELECT state,observed_unix_nanos,last_message_unix_nanos,next_sequence,last_sequence,expected_views,manifest_digest,last_digest,source_observed_unix_nanos,valid_until
 ,source_record IS NOT NULL,CASE WHEN $8 AND octet_length(source_record)<=$7 THEN source_record ELSE NULL END
 FROM bgp_public_snapshots WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND collector_agent_id=$4 AND source_ref=$5 AND sender_serial=$6 FOR UPDATE`, source.TenantID, source.ContextID, id, source.CollectorAgentID, source.SourceRef, source.SenderSerial, profile.MemoryBytes/128, includeRecord).Scan(&header.state, &header.observedNanos, &header.lastClock, &header.nextSequence, &header.lastSequence, &header.expectedViews, &header.manifestDigest, &header.lastDigest, &header.sourceClock, &header.until, &hasSourceRecord, &header.sourceRecord)
	if errors.Is(err, pgx.ErrNoRows) {
		return publicSnapshotWriteState{}, ErrBGPRoutingSourceUnavailable
	}
	if err == nil && includeRecord && hasSourceRecord && header.sourceRecord == nil {
		return publicSnapshotWriteState{}, ErrBGPRoutingBudget
	}
	return header, err
}

func refusePublicSnapshotMessage(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource, id, reason string, rollback bool) (BGPRoutingApplyResult, error) {
	if rollback {
		if _, err := sc.Q.Exec(ctx, "ROLLBACK TO SAVEPOINT public_snapshot_message"); err != nil {
			return BGPRoutingApplyResult{}, err
		}
	}
	_, err := invalidatePublicSnapshot(ctx, sc, source, id)
	if err != nil {
		return BGPRoutingApplyResult{}, err
	}
	return BGPRoutingApplyResult{Status: "invalidated", Reason: reason}, nil
}
