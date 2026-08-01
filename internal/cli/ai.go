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

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/i18n"
)

func cmdAI(cfg Config, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "ask" {
		return cmdSurface(cfg, surfaceCommands["ai"], args, stdout, stderr)
	}
	return aiAsk(cfg, args[1:], stdout, stderr)
}

// aiAsk parses every Ask invocation once so the ordinary and local-handoff
// paths accept the same boolean spellings without leaking a specialized flag
// into the generic parser. Either successful path calls the same tenant-scoped
// endpoint exactly once.
func aiAsk(cfg Config, args []string, stdout, stderr io.Writer) int {
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
		if len(fs.Args()) > 0 {
			fmt.Fprintf(stderr, "unexpected args: %s\n", strings.Join(fs.Args(), " "))
			return 2
		}
		body, err := parseBody(*bodyRaw)
		if err != nil {
			fmt.Fprintln(stderr, "invalid --body: "+err.Error())
			return 2
		}
		var out any
		if err := newClient(cfg).do(
			http.MethodPost,
			withQueryValues("/v1/ai/ask", query),
			body,
			&out,
		); err != nil {
			return fail(stderr, err)
		}
		return printGeneric(stdout, out, cfg.JSON, http.MethodPost)
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
