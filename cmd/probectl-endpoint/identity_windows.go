// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/endpoint"
)

func endpointEnrollmentStore(dir string) agent.EnrollmentStore {
	return agent.NewWindowsEnrollmentStore(dir)
}

func loadEndpointIdentity(cfg *endpoint.Config) (*endpointIdentity, error) {
	store := agent.NewWindowsEnrollmentStore(cfg.Control.IdentityDir)
	device, err := store.Load()
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer crypto.Zeroize(device.PrivateKey)
	identity, _, _, err := crypto.StoredWindowsAgentIdentity(device.Certificate, device.PrivateKey)
	if err != nil {
		return nil, err
	}
	if identity.TenantID != cfg.TenantID {
		return nil, errors.New("enroll: existing identity does not match the expected tenant")
	}
	if _, err := crypto.CertPoolFromPEM(device.ServerCA); err != nil {
		return nil, errors.New("existing endpoint identity has no usable control-plane CA")
	}
	return &endpointIdentity{
		id: identity, serverCA: device.ServerCA,
		dial: func(addr string) (*agent.Client, error) {
			return store.Dial(addr, identity, device.ServerCA)
		},
		rotate: func(ctx context.Context, log *slog.Logger) {
			rotateWindowsEndpoint(ctx, log, cfg.Control.EnrollmentURL, store, identity)
		},
	}, nil
}

func rotateWindowsEndpoint(ctx context.Context, log *slog.Logger, server string, store agent.EnrollmentStore, expected crypto.SPIFFEID) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			device, err := store.Load()
			if err != nil {
				log.Warn("endpoint identity rotation could not load the current identity", "error", err)
				continue
			}
			id, starts, expires, err := crypto.StoredWindowsAgentIdentity(device.Certificate, device.PrivateKey)
			crypto.Zeroize(device.PrivateKey)
			if err != nil || id != expected {
				log.Warn("endpoint identity rotation refused the current identity", "error", err)
				continue
			}
			if !agent.RotationDue(starts, expires, now) {
				continue
			}
			expiry, err := agent.RotateStoredIdentity(ctx, server, store, expected)
			if err != nil {
				log.Warn("endpoint certificate rotation failed", "error", err)
				continue
			}
			log.Info("endpoint SVID rotated", "not_after", expiry.UTC())
		}
	}
}
