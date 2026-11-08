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
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/logging"
)

func runImportMRT(args []string) (err error) {
	fs := flag.NewFlagSet("import-mrt", flag.ContinueOnError)
	path := fs.String("file", "", "local complete MRT, gzip or bzip2 file")
	ref := fs.String("source", "", "exact operator-assigned feed/format/collector reference")
	addr := fs.String("control-addr", "", "existing evidence mTLS listener address")
	identityDir := fs.String("identity-dir", "", "enrolled evidence-purpose identity directory")
	serverName := fs.String("server-name", "", "expected server certificate name")
	defaults := agent.DefaultPublicMRTOptions("")
	fs.Int64Var(&defaults.RecordBytes, "record-bytes", defaults.RecordBytes, "whole original record byte admission; raise with listener wire policy")
	fs.Int64Var(&defaults.MemoryBytes, "memory-bytes", defaults.MemoryBytes, "per-record decoder memory admission")
	fs.Int64Var(&defaults.WorkUnits, "work-units", defaults.WorkUnits, "per-record decoder work admission")
	fs.DurationVar(&defaults.RPCTimeout, "rpc-timeout", defaults.RPCTimeout, "finite deadline for each evidence RPC")
	fs.DurationVar(&defaults.RetryDelay, "retry-delay", defaults.RetryDelay, "delay before retrying an ambiguous RPC")
	fs.IntVar(&defaults.RetryAttempts, "retry-attempts", defaults.RetryAttempts, "finite attempts retaining the same source/record identity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *path == "" || *ref == "" || *addr == "" || *identityDir == "" {
		return errors.New("import-mrt requires file, source, control-addr and identity-dir")
	}
	log := logging.New(os.Stdout, envOr("PROBECTL_AGENT_LOG_LEVEL", "info"), envOr("PROBECTL_AGENT_LOG_FORMAT", "json"))
	if err := crypto.RunPowerOnSelfTest(log); err != nil {
		return err
	}
	client, err := agent.DialEntityEvidence(*addr, filepath.Join(*identityDir, agent.IdentityCertFile), filepath.Join(*identityDir, agent.IdentityKeyFile), filepath.Join(*identityDir, agent.IdentityServerCAFile), *serverName)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	source, err := agent.OpenPublicMRTFile(*path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defaults.ConfiguredRef = *ref
	result, err := client.ImportPublicMRT(ctx, source, defaults)
	if err != nil {
		return err
	}
	log.Info("public routing source imported", "source_ref", *ref, "snapshot_id", result.SnapshotID, "records", result.Records, "bytes", result.Bytes, "record_bytes", defaults.RecordBytes, "memory_bytes", defaults.MemoryBytes, "work_units", defaults.WorkUnits)
	return nil
}
