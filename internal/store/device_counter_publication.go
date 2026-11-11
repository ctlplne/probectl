// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// PublishUnderWitness joins the existing tenant writer/lifecycle fence before
// external counter history IO. Source rebind, revocation and erasure cannot
// overtake the bounded publication. Exact retries retain the same point IDs;
// a backend success followed by a transaction error must be retried, never
// acknowledged as a missing or partially stored original poll.
func (s *DeviceCounterCaptures) PublishUnderWitness(ctx context.Context, sender string, digest [32]byte, input entity.CounterCaptureInput, retentionDays int,
	publish func(context.Context, DeviceCounterCapture) error) error {
	key, err := s.key(ctx, sender, digest, input)
	if err != nil {
		return err
	}
	if publish == nil {
		return ErrCounterCaptureUnavailable
	}
	ctx = tenancy.WithSiloTableLock(ctx)
	return tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		generation, err := sourceepoch.SourceGenerationInScope(ctx, sc)
		if err != nil {
			return err
		}
		if err := tenancy.LockTenantAuditStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
			return err
		}
		if err := sourceepoch.MatchSourceGenerationInScope(ctx, sc, generation); err != nil {
			return err
		}
		current, err := lookupDeviceCounterWitness(ctx, sc, key, true)
		if err != nil {
			return err
		}
		if err := counterPollWithinRetention(ctx, sc, input, retentionDays); err != nil {
			return err
		}
		if err := publish(ctx, current); err != nil {
			return err
		}
		// The row locks prevent mutation; a second statement also observes
		// wall-clock expiry during IO without treating the old read as a grant.
		after, err := lookupDeviceCounterWitness(ctx, sc, key, true)
		if err != nil {
			return err
		}
		if after.Scope != current.Scope || after.DeviceID != current.DeviceID || after.SenderSerial != current.SenderSerial ||
			!after.CapturedAt.Equal(current.CapturedAt) || !after.SourceAssignedAt.Equal(current.SourceAssignedAt) || !after.AgentAssignedAt.Equal(current.AgentAssignedAt) {
			return ErrCounterCaptureUnavailable
		}
		if err := counterPollWithinRetention(ctx, sc, input, retentionDays); err != nil {
			return err
		}
		return sourceepoch.MatchSourceGenerationInScope(ctx, sc, generation)
	})
}

func counterPollWithinRetention(ctx context.Context, sc tenancy.Scope, input entity.CounterCaptureInput, defaultDays int) error {
	if defaultDays < 0 {
		return ErrCounterCaptureUnavailable
	}
	var configured *int
	err := sc.Q.QueryRow(ctx, `SELECT flow_retention_days FROM tenant_retention WHERE tenant_id=$1`, sc.Tenant.String()).Scan(&configured)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	days := defaultDays
	if configured != nil {
		days = *configured
	}
	if days == 0 {
		return nil
	}
	if days < 0 {
		return ErrCounterCaptureUnavailable
	}
	var accepted bool
	err = sc.Q.QueryRow(ctx, `SELECT $1::timestamptz >= clock_timestamp()-($2::bigint*interval '1 day')`, input.PollStartedAt, days).Scan(&accepted)
	if err != nil {
		return err
	}
	if !accepted {
		return ErrCounterCaptureUnavailable
	}
	return nil
}
