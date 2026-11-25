// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/endpoint"
	"github.com/ctlplne/probectl/internal/version"
)

// runEndpointEnroll uses the same parameters that will govern runtime dialing
// and renewal. The one-time secret is only accepted through stdin.
func runEndpointEnroll(args []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("probectl-endpoint enroll", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // FlagSet errors may quote untrusted arguments.
	config := flags.String("config", os.Getenv("PROBECTL_ENDPOINT_CONFIG"), "managed endpoint YAML configuration")
	caFile := flags.String("ca-file", "", "PEM CA bundle for the control plane")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *config == "" {
		return errors.New("usage: probectl-endpoint enroll --config FILE --ca-file CONTROL_CA_PEM (token on stdin)")
	}
	cfg, err := endpoint.Load(*config)
	if err != nil {
		return err
	}
	if cfg.Control.Address == "" {
		return errors.New("endpoint enrollment requires configured control transport")
	}
	if err := crypto.RunPowerOnSelfTest(nil); err != nil {
		return err
	}
	control := cfg.Control
	identity, err := loadEndpointIdentity(cfg)
	if err != nil {
		return err
	}
	if identity != nil {
		if *caFile != "" {
			bundle, err := os.ReadFile(*caFile)
			if err != nil {
				return fmt.Errorf("read enrollment control-plane CA: %w", err)
			}
			if !crypto.SameCertificateTrust(identity.serverCA, bundle) {
				return errors.New("enroll: supplied CA bundle differs from the enrolled device's control-plane trust")
			}
		}
		_, err := fmt.Fprintln(output, "Existing endpoint identity matches the configured tenant.")
		return err
	}
	if *caFile == "" {
		return errors.New("endpoint enrollment requires --ca-file for this device")
	}
	if _, err := crypto.LoadCertPool(*caFile); err != nil {
		return fmt.Errorf("validate enrollment control-plane CA: %w", err)
	}
	token, err := agent.ReadEnrollmentToken(input)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, expiry, err := agent.Enroll(ctx, agent.EnrollOptions{
		Server: control.EnrollmentURL, Token: token, ExpectedTenant: cfg.TenantID,
		Dir: control.IdentityDir, Hostname: cfg.AgentID, Version: version.Get().Version, CAFile: *caFile,
		Store: endpointEnrollmentStore(control.IdentityDir),
	})
	if err != nil {
		var rejection *agent.EnrollStatusError
		if errors.As(err, &rejection) {
			return fmt.Errorf("endpoint enrollment returned HTTP %d", rejection.StatusCode)
		}
		return err
	}
	_, err = fmt.Fprintln(output, "Endpoint enrolled until", expiry.UTC().Format(time.RFC3339))
	return err
}
