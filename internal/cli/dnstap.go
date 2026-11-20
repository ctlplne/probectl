// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/threat/dnstap"
)

type dnstapCaptureOptions struct {
	capture, source, from, to       string
	evidenceAddr, identity, key, ca string
	serverName                      string
}

func cmdDNSTap(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "submit" {
		fmt.Fprintln(stderr, "usage: probectl dnstap submit --help")
		return 2
	}
	flags := flag.NewFlagSet("probectl dnstap submit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var options dnstapCaptureOptions
	flags.StringVar(&options.capture, "capture-file", "", "closed local dnstap file")
	flags.StringVar(&options.source, "source", "", "exact operator-configured resolver source reference")
	flags.StringVar(&options.from, "from", "", "inclusive RFC3339 minute start")
	flags.StringVar(&options.to, "to", "", "exclusive RFC3339 minute end")
	flags.StringVar(&options.evidenceAddr, "evidence-addr", "", "agent evidence mTLS address")
	flags.StringVar(&options.identity, "evidence-cert", "", "enrolled evidence certificate path")
	flags.StringVar(&options.key, "evidence-key", "", "enrolled evidence key path")
	flags.StringVar(&options.ca, "evidence-ca", "", "control-plane CA path")
	flags.StringVar(&options.serverName, "evidence-server-name", "", "optional certificate server name")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	from, fromErr := time.Parse(time.RFC3339, options.from)
	to, toErr := time.Parse(time.RFC3339, options.to)
	if flags.NArg() != 0 || fromErr != nil || toErr != nil || options.capture == "" || !dnstap.ValidSourceRef(options.source) ||
		options.evidenceAddr == "" || options.identity == "" || options.key == "" || options.ca == "" {
		fmt.Fprintln(stderr, "dnstap submit: closed file, exact source, interval and mTLS identity are required")
		return 2
	}
	result, err := submitDNSTapFile(options, from, to)
	if err != nil {
		fmt.Fprintln(stderr, "dnstap submit:", err)
		return 1
	}
	return printJSON(stdout, result)
}

type dnstapSubmitResult struct {
	Intervals        uint32 `json:"intervals"`
	PressureSignals  uint32 `json:"pressure_signals"`
	EvidenceDigest   string `json:"evidence_sha256"`
	CaptureCoverage  string `json:"coverage"`
	ClippedResponses uint32 `json:"clipped_responses"`
}

func submitDNSTapFile(options dnstapCaptureOptions, from, to time.Time) (dnstapSubmitResult, error) {
	empty := dnstapSubmitResult{}
	info, err := os.Stat(options.capture)
	if err != nil || !info.Mode().IsRegular() {
		return empty, errors.New("capture must be a readable regular file")
	}
	if info.Size() > dnstap.MaximumCaptureBytes {
		return empty, dnstap.ErrCaptureLimit
	}
	file, err := os.Open(options.capture)
	if err != nil {
		return empty, errors.New("capture could not be opened")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return empty, errors.New("capture changed before it could be read")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	capture, err := dnstap.ReduceClosedCapture(ctx, file, from, to)
	if err != nil {
		return empty, err
	}
	final, err := file.Stat()
	if err != nil || final.Size() != opened.Size() || !final.ModTime().Equal(opened.ModTime()) {
		return empty, errors.New("capture changed during the read")
	}
	if err := capture.Validate(time.Now()); err != nil {
		return empty, err
	}
	client, err := agent.DialEntityEvidence(options.evidenceAddr, options.identity, options.key, options.ca, options.serverName)
	if err != nil {
		return empty, errors.New("verified resolver evidence identity is unavailable")
	}
	defer client.Close()
	receipt, err := client.SubmitResolverDNS(ctx, options.source, capture)
	if err != nil {
		return empty, err
	}
	return dnstapSubmitResult{
		Intervals: receipt.Intervals, PressureSignals: receipt.PressureSignals, EvidenceDigest: hex.EncodeToString(receipt.EvidenceDigest),
		CaptureCoverage: "closed_file_captured_responses", ClippedResponses: capture.Outside,
	}, nil
}
