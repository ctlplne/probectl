// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// This test binary runs the production tracer in one owned FRR container.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/ctlplne/probectl/internal/path"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var cfg path.Config
	if len(os.Args) != 2 || json.Unmarshal([]byte(os.Args[1]), &cfg) != nil {
		return errors.New("expected the served path request")
	}
	address, err := netip.ParseAddr(cfg.Target)
	if err != nil || !netip.MustParsePrefix("198.19.0.0/16").Contains(address) ||
		!cfg.Privileged || cfg.Mode != "icmp" {
		return errors.New("expected an owned IPv4 raw ICMP lab request")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	got, err := path.Run(ctx, cfg)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(got)
}
