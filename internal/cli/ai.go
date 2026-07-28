// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cli

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/i18n"
)

func cmdAI(cfg Config, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "ask" || !containsExactArg(args[1:], "--handoff") {
		return cmdSurface(cfg, surfaceCommands["ai"], args, stdout, stderr)
	}
	return aiAskHandoff(cfg, args[1:], stdout, stderr)
}

// aiAskHandoff calls the same tenant-scoped Ask endpoint exactly once, then
// renders that response locally. It adds no export route, server persistence,
// browser state, connector, or egress.
func aiAskHandoff(cfg Config, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ai ask", flag.ContinueOnError)
	fs.SetOutput(stderr)
	bodyRaw := fs.String("body", "", i18n.T(cfg.Locale, "cli.ai.handoff.body_help", nil))
	handoff := fs.Bool("handoff", false, i18n.T(cfg.Locale, "cli.ai.handoff.flag_help", nil))
	query := queryFlag{}
	fs.Var(&query, "query", i18n.T(cfg.Locale, "cli.ai.handoff.query_help", nil))
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !*handoff {
		return cmdSurface(cfg, surfaceCommands["ai"], append([]string{"ask"}, args...), stdout, stderr)
	}
	if cfg.JSON {
		fmt.Fprintln(stderr, i18n.T(cfg.Locale, "cli.ai.handoff.json_conflict", nil))
		return 2
	}
	if len(query) > 0 {
		fmt.Fprintln(stderr, i18n.T(cfg.Locale, "cli.ai.handoff.query_conflict", nil))
		return 2
	}
	if len(fs.Args()) > 0 {
		fmt.Fprintln(stderr, i18n.T(cfg.Locale, "cli.ai.handoff.unexpected", map[string]string{
			"args": strings.Join(fs.Args(), " "),
		}))
		return 2
	}
	if strings.TrimSpace(*bodyRaw) == "" {
		fmt.Fprintln(stderr, i18n.T(cfg.Locale, "cli.ai.handoff.body_required", nil))
		return 2
	}
	body, err := parseBody(*bodyRaw)
	if err != nil {
		fmt.Fprintln(stderr, i18n.T(cfg.Locale, "cli.ai.handoff.invalid_body", map[string]string{
			"error": err.Error(),
		}))
		return 2
	}
	request, ok := body.(map[string]any)
	if !ok {
		fmt.Fprintln(stderr, i18n.T(cfg.Locale, "cli.ai.handoff.object_required", nil))
		return 2
	}
	question, ok := request["question"].(string)
	if !ok || strings.TrimSpace(question) == "" {
		fmt.Fprintln(stderr, i18n.T(cfg.Locale, "cli.ai.handoff.question_required", nil))
		return 2
	}

	var answer ai.Answer
	if err := newClient(cfg).do(http.MethodPost, "/v1/ai/ask", request, &answer); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprint(stdout, ai.RenderHandoff(answer, cfg.Locale))
	return 0
}

func containsExactArg(args []string, name string) bool {
	for _, arg := range args {
		if arg == name {
			return true
		}
	}
	return false
}
