// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/ctlplne/probectl/internal/opendata"
)

func runPublicMRTFetch(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("public-mrt-fetch", flag.ContinueOnError)
	directory := flags.String("cache-dir", "", "Absolute deployment-wide archive cache directory")
	source := flags.String("source", "routeviews", "Published collector source")
	collector := flags.String("collector", "", "Published collector identifier")
	kind := flags.String("kind", "", "Archive kind: baseline or updates")
	clock := flags.String("at", "", "Published archive clock in RFC 3339")
	limit := flags.Int64("max-bytes", 512<<20, "Maximum original compressed archive bytes")
	if err := flags.Parse(args); err != nil {
		return err
	}
	at, err := time.Parse(time.RFC3339, *clock)
	if err != nil || flags.NArg() != 0 {
		return errors.New("public MRT fetch requires a source, collector, archive kind and exact RFC 3339 clock")
	}
	cache, err := opendata.NewPublicMRTCache(*directory, *limit, nil)
	if err != nil {
		return err
	}
	receipt, err := cache.Fetch(ctx, opendata.PublicMRTArchiveRef{Source: *source, Collector: *collector,
		Kind: opendata.PublicMRTArchiveKind(*kind), At: at})
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(receipt)
}
