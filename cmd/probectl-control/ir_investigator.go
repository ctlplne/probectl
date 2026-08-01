// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build !probectl_core

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/crypto"
)

type irInvestigator struct {
	pool      *pgxpool.Pool
	sidecar   *audit.IRStagePG
	revealer  *audit.IRRevealer
	lifecycle *audit.IRKeyLifecycle
}

var _ control.IRInvestigator = (*irInvestigator)(nil)

func buildIRInvestigator(
	ctx context.Context,
	cfg *config.Config,
	log *slog.Logger,
	pool *pgxpool.Pool,
	worm *audit.WormExporter,
) (*audit.IRStagePG, *irInvestigator, error) {
	irKeys, err := audit.NewLocalIRPublicKeyResolver(cfg.IRPublicKeyDir)
	if err != nil {
		return nil, nil, fmt.Errorf("provider IR public keyring: %w", err)
	}
	wormPrivate, wormPublic, generated, err := audit.ResolveWormSigningKey(
		cfg.WormSigningKey,
		cfg.WormSigningKeyFile,
		cfg.RequireAtRestEncryption,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("provider IR chain signing key: %w", err)
	}
	if generated {
		log.Warn(
			"generated provider IR/WORM signing key; preserve it for cross-restart verification",
			"key_file",
			cfg.WormSigningKeyFile,
		)
	}
	sidecar, err := audit.NewIRStagePG(
		pool,
		irKeys,
		wormPrivate,
		wormPublic,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("provider IR sidecar: %w", err)
	}
	if err := attachProviderIRDurability(ctx, worm, sidecar); err != nil {
		return nil, nil, err
	}
	var (
		openKeys  audit.IROpenKeyResolver
		destroyer crypto.KeyArtifactDestroyer
	)
	if cfg.IRPrivateKeyDir != "" {
		unlock, err := crypto.NewStaticKeyProviderFromBase64(
			cfg.IRUnlockKeyID,
			cfg.IRUnlockKey,
		)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"provider IR private-artifact unlock key: %w",
				err,
			)
		}
		openKeys, err = audit.NewLocalIRPrivateKeyResolver(
			cfg.IRPrivateKeyDir,
			unlock,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("provider IR private keyring: %w", err)
		}
		destroyer, err = audit.NewLocalIRKeyArtifactDestroyer(
			cfg.IRPublicKeyDir,
			cfg.IRPrivateKeyDir,
		)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"provider IR key destruction capability: %w",
				err,
			)
		}
	}
	revealer, err := audit.NewIRRevealer(worm, sidecar, openKeys)
	if err != nil {
		return nil, nil, fmt.Errorf("provider IR revealer: %w", err)
	}
	lifecycle, err := audit.NewIRKeyLifecycle(worm, sidecar, destroyer)
	if err != nil {
		return nil, nil, fmt.Errorf("provider IR key lifecycle: %w", err)
	}
	if err := lifecycle.VerifyIRKeyShredLedger(ctx); err != nil {
		return nil, nil, fmt.Errorf(
			"provider IR key-destruction startup verification: %w",
			err,
		)
	}
	if err := lifecycle.VerifyIRPostShredAttemptLedger(ctx); err != nil {
		return nil, nil, fmt.Errorf(
			"provider post-shred IR-attempt startup verification: %w",
			err,
		)
	}
	return sidecar, &irInvestigator{
		pool: pool, sidecar: sidecar, revealer: revealer,
		lifecycle: lifecycle,
	}, nil
}

func (i *irInvestigator) Plan(
	ctx context.Context,
	tenantID, actor string,
) (string, error) {
	if i == nil || i.lifecycle == nil {
		return "", errors.New("IR key lifecycle is unavailable")
	}
	return i.lifecycle.Plan(ctx, tenantID, actor)
}

func (i *irInvestigator) Execute(
	ctx context.Context,
	tenantID, actor, planID string,
) error {
	if i == nil || i.lifecycle == nil {
		return errors.New("IR key lifecycle is unavailable")
	}
	return i.lifecycle.Execute(ctx, tenantID, actor, planID)
}

func (i *irInvestigator) RecordFailure(
	ctx context.Context,
	tenantID, actor, planID, failure string,
) error {
	if i == nil || i.lifecycle == nil {
		return errors.New("IR key lifecycle is unavailable")
	}
	return i.lifecycle.RecordFailure(
		ctx,
		tenantID,
		actor,
		planID,
		failure,
	)
}

func (i *irInvestigator) RecordAttempt(
	ctx context.Context,
	receipt control.IRInvestigationReceipt,
) error {
	if i == nil || i.pool == nil || i.sidecar == nil {
		return errors.New("IR investigation audit runtime is unavailable")
	}
	target, data, attribution, err := irInvestigationAuditProjection(receipt)
	if err != nil {
		return err
	}
	_, err = audit.ProviderAppendBreakGlass(
		ctx,
		i.pool,
		i.sidecar,
		receipt.Actor,
		audit.ActionIRAttributionReveal,
		target,
		data,
		attribution,
	)
	return err
}

func (i *irInvestigator) RecordPostShredAttempt(
	ctx context.Context,
	tenantID, actor string,
) error {
	if i == nil || i.sidecar == nil {
		return errors.New("IR post-shred audit runtime is unavailable")
	}
	return i.sidecar.RecordIRPostShredRevealAttempt(ctx, tenantID, actor)
}

func (i *irInvestigator) Reveal(
	ctx context.Context,
	tenantID, eventRef string,
) (control.IRAttribution, error) {
	if i == nil || i.revealer == nil {
		return control.IRAttribution{}, control.ErrIRKeyUnavailable
	}
	attribution, err := i.revealer.Reveal(ctx, tenantID, eventRef)
	if err != nil {
		switch {
		case errors.Is(err, audit.ErrIRAttributionNotFound):
			return control.IRAttribution{}, control.ErrIRAttributionNotFound
		case errors.Is(err, audit.ErrIRKeyUnavailable):
			return control.IRAttribution{}, control.ErrIRKeyUnavailable
		default:
			return control.IRAttribution{}, err
		}
	}
	defer clearAuditIRAttribution(&attribution)
	return control.IRAttribution{
		Operator: attribution.Operator,
		TenantID: attribution.TenantID,
		Grant:    attribution.Grant,
		Surface:  attribution.Surface,
		Consent:  attribution.Consent,
		Outcome:  attribution.Outcome,
		Reason:   attribution.Reason,
		EventRef: attribution.EventRef,
		TS:       attribution.TS,
	}, nil
}

func irInvestigationAuditProjection(
	receipt control.IRInvestigationReceipt,
) (string, map[string]any, audit.IRAttribution, error) {
	if strings.TrimSpace(receipt.TenantID) == "" ||
		strings.TrimSpace(receipt.Actor) == "" ||
		strings.TrimSpace(receipt.Reason) == "" ||
		!validIRAttemptOutcome(receipt.Outcome) ||
		!validIRAttemptErrorClass(receipt.ErrorClass) {
		return "", nil, audit.IRAttribution{}, errors.New(
			"IR investigation receipt is invalid",
		)
	}
	target := receipt.EventRef
	if target == "" {
		target = "unresolved-ir-event"
	}
	consent := "ir-investigator-authorized"
	if receipt.Outcome == control.IRAttemptDenied {
		consent = "denied"
	}
	outcome := string(receipt.Outcome)
	data := map[string]any{
		"tenant":              receipt.TenantID,
		"surface":             "audit.ir.reveal",
		"consent":             consent,
		"outcome":             outcome,
		"reason":              receipt.Reason,
		"requested_event_ref": target,
	}
	if receipt.ErrorClass != "" {
		data["error_class"] = receipt.ErrorClass
	}
	return target, data, audit.IRAttribution{
		Operator: receipt.Actor,
		TenantID: receipt.TenantID,
		Grant:    target,
		Surface:  "audit.ir.reveal",
		Consent:  consent,
		Outcome:  outcome,
		Reason:   receipt.Reason,
	}, nil
}

func validIRAttemptOutcome(outcome control.IRAttemptOutcome) bool {
	switch outcome {
	case control.IRAttemptDenied,
		control.IRAttemptIntent,
		control.IRAttemptOpenFailed,
		control.IRAttemptSucceeded:
		return true
	default:
		return false
	}
}

func validIRAttemptErrorClass(errorClass string) bool {
	switch errorClass {
	case "",
		"tenant_lifecycle",
		"mfa_required",
		"rbac_denied",
		"abac_unavailable",
		"abac_denied",
		"invalid_event_ref",
		"invalid_request",
		"reason_required",
		"reason_too_long",
		"not_found",
		"key_unavailable",
		"open_failed",
		"scope_or_shape_mismatch":
		return true
	default:
		return false
	}
}

func clearAuditIRAttribution(attribution *audit.IRAttribution) {
	if attribution == nil {
		return
	}
	*attribution = audit.IRAttribution{}
}
