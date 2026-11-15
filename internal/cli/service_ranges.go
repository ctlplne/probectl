// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/opendata"
)

func cmdOpenData(cfg Config, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		printSurfaceUsage(stdout, surfaceCommands["opendata"])
		fmt.Fprintln(stdout, "  fetch-ranges --publishers aws,google,google_cloud --output <local-cache> [--memory-bytes N] [--max-age 24h]")
		return 0
	}
	if args[0] != "fetch-ranges" {
		return cmdSurfaceWithStdin(cfg, surfaceCommands["opendata"], args, stdin, stdout, stderr)
	}
	return cmdFetchServiceRanges(cfg, args[1:], stdout, stderr, opendata.FetchServiceRangeCacheWithOptions)
}

type serviceRangeFetch func(context.Context, string, []string, time.Duration, int64, opendata.ServiceRangeFetchOptions, opendata.Doer) error

func cmdFetchServiceRanges(cfg Config, args []string, stdout, stderr io.Writer, fetch serviceRangeFetch) int {
	flags := flag.NewFlagSet("opendata fetch-ranges", flag.ContinueOnError)
	flags.SetOutput(stderr)
	publishers := flags.String("publishers", "", "explicit comma-separated publishers: aws,google,google_cloud,cloudflare,salesforce,zoom,m365 bundles or documented individual IDs")
	m365Client := flags.String("m365-client-request-id", "", "operator-supplied stable per-machine GUID required only for explicit Microsoft365 bulk downloads")
	output := flags.String("output", "", "local offline cache to atomically replace after complete validation")
	memory := flags.Int64("memory-bytes", 256<<20, "positive raiseable complete download/decoder/index memory admission")
	maxAge := flags.Duration("max-age", 24*time.Hour, "positive freshness profile used to validate the complete cache")
	timeout := flags.Duration("timeout", time.Minute, "positive per-publisher TLS download budget")
	if wantsHelp(args) {
		flags.SetOutput(stdout)
		flags.PrintDefaults()
		return 0
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *publishers == "" || *output == "" || *memory <= 0 || *maxAge <= 0 || *timeout <= 0 {
		fmt.Fprintln(stderr, "fetch-ranges: explicit publishers, output and positive memory/freshness are required")
		return 2
	}
	selected := strings.Split(*publishers, ",")
	for i := range selected {
		selected[i] = strings.TrimSpace(selected[i])
	}
	options := opendata.ServiceRangeFetchOptions{Microsoft365ClientRequestID: *m365Client}
	if err := fetch(context.Background(), *output, selected, *maxAge, *memory, options, crypto.HardenedHTTPClient(*timeout)); err != nil {
		fmt.Fprintln(stderr, "fetch-ranges:", err)
		return 1
	}
	if cfg.JSON {
		return printJSON(stdout, map[string]any{"status": "complete", "publishers": selected, "restart_required": true})
	}
	fmt.Fprintln(stdout, "Complete published range cache refreshed. Restart the control plane to load it.")
	return 0
}
