// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build !windows

package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/endpoint"
)

func endpointEnrollmentStore(string) agent.EnrollmentStore { return nil }

func loadEndpointIdentity(cfg *endpoint.Config) (*endpointIdentity, error) {
	control := cfg.Control
	ready, err := agent.CheckExistingEnrollment(control.IdentityDir, cfg.TenantID)
	if err != nil || !ready {
		return nil, err
	}
	cert := filepath.Join(control.IdentityDir, agent.IdentityCertFile)
	key := filepath.Join(control.IdentityDir, agent.IdentityKeyFile)
	serverCA := filepath.Join(control.IdentityDir, agent.IdentityServerCAFile)
	caPEM, err := os.ReadFile(serverCA)
	if err != nil {
		return nil, errors.New("existing endpoint identity has no usable control-plane CA")
	}
	if _, err := crypto.CertPoolFromPEM(caPEM); err != nil {
		return nil, errors.New("existing endpoint identity has no usable control-plane CA")
	}
	identity, err := crypto.SPIFFEIDFromCertFile(cert)
	if err != nil || identity.TenantID != cfg.TenantID {
		return nil, errors.New("endpoint: enrolled identity does not match the configured tenant")
	}
	return &endpointIdentity{
		id: identity, serverCA: caPEM,
		dial: func(addr string) (*agent.Client, error) {
			return agent.Dial(addr, cert, key, serverCA, "")
		},
		rotate: func(ctx context.Context, log *slog.Logger) {
			agent.RotationLoop(ctx, log, control.EnrollmentURL, cert, key, serverCA, time.Minute)
		},
	}, nil
}
