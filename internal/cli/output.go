// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
)

// clean renders a server-supplied string safe for an operator's terminal
// (GAP-07): every control rune — C0 (incl. \n and \t, which would also break a
// table row/column), DEL, and C1 — is replaced with a visible \xNN / \uNNNN
// escape, so an agent-reported hostname, name, version, capability or test
// field cannot inject ANSI escape sequences (cursor moves, screen clears, title
// rewrites) into the CLI output. Printable text (including multibyte UTF-8) is
// untouched.
func clean(s string) string {
	if !strings.ContainsFunc(s, unicode.IsControl) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case !unicode.IsControl(r):
			b.WriteRune(r)
		case r <= 0xff:
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			fmt.Fprintf(&b, "\\u%04x", r)
		}
	}
	return b.String()
}

// cleanAll applies clean to each element (for capability lists).
func cleanAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = clean(s)
	}
	return out
}

func printJSON(w io.Writer, v any) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return 1
	}
	return 0
}

func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func printTests(w io.Writer, tests []Test) {
	if len(tests) == 0 {
		fmt.Fprintln(w, "No tests.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tTYPE\tTARGET\tINTERVAL\tENABLED")
	for _, t := range tests {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%ds\t%t\n",
			clean(short(t.ID)), clean(t.Name), clean(t.Type), clean(t.Target), t.IntervalSeconds, t.Enabled)
	}
	_ = tw.Flush()
}

func printTest(w io.Writer, t Test) {
	fmt.Fprintf(w, "id:        %s\n", clean(t.ID))
	fmt.Fprintf(w, "name:      %s\n", clean(t.Name))
	fmt.Fprintf(w, "type:      %s\n", clean(t.Type))
	fmt.Fprintf(w, "target:    %s\n", clean(t.Target))
	fmt.Fprintf(w, "interval:  %ds\n", t.IntervalSeconds)
	fmt.Fprintf(w, "timeout:   %ds\n", t.TimeoutSeconds)
	fmt.Fprintf(w, "enabled:   %t\n", t.Enabled)
	if len(t.Params) > 0 {
		var kv []string
		for k, v := range t.Params {
			kv = append(kv, clean(k)+"="+clean(v))
		}
		fmt.Fprintf(w, "params:    %s\n", strings.Join(kv, " "))
	}
}

func printAgents(w io.Writer, agents []Agent) {
	if len(agents) == 0 {
		fmt.Fprintln(w, "No agents.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tHOSTNAME\tSTATUS\tIDENTITY\tCAPABILITIES")
	for _, a := range agents {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			clean(short(a.ID)), clean(a.Name), clean(a.Hostname), clean(a.Status), identityCell(a), strings.Join(cleanAll(a.Capabilities), ","))
	}
	_ = tw.Flush()
}

// identityCell states the credential lifetime in one column. "unknown" is
// printed as "-" rather than guessed: an agent enrolled before this deployment
// recorded issuance has no window to read (DPR-176).
func identityCell(a Agent) string {
	switch a.IdentityState {
	case "":
		return "-"
	case "unknown":
		return "unknown"
	case "current":
		if a.IdentityExpiresAt != nil {
			return "valid until " + a.IdentityExpiresAt.UTC().Format(time.RFC3339)
		}
		return "valid"
	case "renewal_overdue":
		return "RENEWAL OVERDUE"
	case "expired":
		return "EXPIRED"
	default:
		return clean(a.IdentityState)
	}
}

func printAgent(w io.Writer, a Agent) {
	fmt.Fprintf(w, "id:            %s\n", clean(a.ID))
	fmt.Fprintf(w, "name:          %s\n", clean(a.Name))
	fmt.Fprintf(w, "hostname:      %s\n", clean(a.Hostname))
	fmt.Fprintf(w, "agent_version: %s\n", clean(a.AgentVersion))
	fmt.Fprintf(w, "status:        %s\n", clean(a.Status))
	fmt.Fprintf(w, "capabilities:  %s\n", strings.Join(cleanAll(a.Capabilities), ", "))
	fmt.Fprintf(w, "identity:      %s\n", identityCell(a))
	if a.IdentityReason != "" {
		fmt.Fprintf(w, "identity_note: %s\n", clean(a.IdentityReason))
	}
}
