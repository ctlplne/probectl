// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	probectlc "github.com/imfeelingtheagi/probectl/internal/crypto"
)

const (
	defaultBMPRevocationRefresh = 30 * time.Second
	defaultBMPRevocationTimeout = 5 * time.Second
)

type bmpRevocationSource interface {
	List(context.Context) (serials, spiffeIDs []string, err error)
}

type bmpRevocationFeed struct {
	source  bmpRevocationSource
	target  *probectlc.RevocationList
	refresh time.Duration
	timeout time.Duration
	log     *slog.Logger
}

func newBMPRevocationFeed(
	source bmpRevocationSource,
	target *probectlc.RevocationList,
	refresh, timeout time.Duration,
	log *slog.Logger,
) (*bmpRevocationFeed, error) {
	if source == nil {
		return nil, errors.New("BMP revocation source is required")
	}
	if target == nil {
		return nil, errors.New("BMP revocation target is required")
	}
	if refresh <= 0 {
		return nil, errors.New("BMP revocation refresh must be positive")
	}
	if timeout <= 0 {
		return nil, errors.New("BMP revocation timeout must be positive")
	}
	if log == nil {
		log = slog.Default()
	}
	return &bmpRevocationFeed{
		source:  source,
		target:  target,
		refresh: refresh,
		timeout: timeout,
		log:     log,
	}, nil
}

// loadInitialRevocations is the startup gate: the listener must not bind until
// one complete authoritative snapshot has replaced the empty in-memory list.
func (f *bmpRevocationFeed) loadInitialRevocations(ctx context.Context) error {
	if err := f.replace(ctx); err != nil {
		return fmt.Errorf("initial BMP revocation snapshot: %w", err)
	}
	return nil
}

// Run refreshes bounded snapshots. A failed refresh deliberately leaves the
// last valid list installed; it never replaces known revocations with an empty
// or partial result.
func (f *bmpRevocationFeed) Run(ctx context.Context) error {
	ticker := time.NewTicker(f.refresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := f.replace(ctx); err != nil {
				f.log.Warn(
					"BMP revocation refresh failed; retaining last valid snapshot",
					"error",
					err,
				)
			}
		}
	}
}

func (f *bmpRevocationFeed) replace(ctx context.Context) error {
	refreshCtx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	serials, spiffeIDs, err := f.source.List(refreshCtx)
	if err != nil {
		return err
	}
	f.target.Replace(serials, spiffeIDs)
	return nil
}

func validateBMPDatabaseURLs(identityRegistry, revocation string) error {
	if err := validateBMPDatabaseURL("identity registry", identityRegistry); err != nil {
		return err
	}
	return validateBMPDatabaseURL("revocation", revocation)
}

func validateBMPRevocationDatabaseURL(raw string) error {
	return validateBMPDatabaseURL("revocation", raw)
}

func validateBMPDatabaseURL(role, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("BMP %s database URL is malformed", role)
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return fmt.Errorf("BMP %s database URL must use postgres:// or postgresql://", role)
	}
	if u.Host == "" {
		return fmt.Errorf("BMP %s database URL must include a host", role)
	}
	query := u.Query()
	if _, present := query["host"]; present {
		return fmt.Errorf("BMP %s database URL must use its authority host; query host overrides are not allowed", role)
	}
	sslModes := query["sslmode"]
	if len(sslModes) != 1 || sslModes[0] != "verify-full" {
		return fmt.Errorf("BMP %s database URL requires sslmode=verify-full", role)
	}
	return nil
}
