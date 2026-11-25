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
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/endpoint"
	"github.com/ctlplne/probectl/internal/endpoint/wire"
)

func stageEndpointUpdate(args []string, output io.Writer) error {
	fs := flag.NewFlagSet("probectl-endpoint stage-update", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv("PROBECTL_ENDPOINT_CONFIG"), "path to the enrolled endpoint YAML config (defaults to the managed configuration)")
	rollout := fs.String("rollout", "", "released endpoint rollout ID")
	destination := fs.String("output", "", "new local installer file on a filesystem supporting hard links")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rollout == "" || len(*rollout) > 64 || *destination == "" || fs.NArg() != 0 {
		return errors.New("stage-update requires --rollout and --output")
	}
	platform := runtime.GOOS + "/" + runtime.GOARCH
	if !wire.IsManagedPlatform(platform) {
		return errors.New("stage-update requires a managed macOS or Windows endpoint")
	}
	if *configPath == "" {
		path, err := managedEndpointConfigPath()
		if err != nil {
			return err
		}
		*configPath = path
	}
	cfg, err := endpoint.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.Control.Address == "" {
		return errors.New("stage-update requires an enrolled control-plane address")
	}
	if err := crypto.RunPowerOnSelfTest(slog.Default()); err != nil {
		return err
	}
	identity, err := loadEndpointIdentity(cfg)
	if err != nil {
		return err
	}
	if identity == nil {
		return errors.New("stage-update requires an enrolled device identity")
	}
	client, err := identity.dial(cfg.Control.Address)
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	metadata, err := client.DownloadEndpointPackage(ctx, *rollout, platform, *destination)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Staged %s (%s) at %s\n", metadata.GetVersion(), metadata.GetPackageDigest(), *destination)
	return err
}
