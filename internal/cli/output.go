package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

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
			short(t.ID), t.Name, t.Type, t.Target, t.IntervalSeconds, t.Enabled)
	}
	_ = tw.Flush()
}

func printTest(w io.Writer, t Test) {
	fmt.Fprintf(w, "id:        %s\n", t.ID)
	fmt.Fprintf(w, "name:      %s\n", t.Name)
	fmt.Fprintf(w, "type:      %s\n", t.Type)
	fmt.Fprintf(w, "target:    %s\n", t.Target)
	fmt.Fprintf(w, "interval:  %ds\n", t.IntervalSeconds)
	fmt.Fprintf(w, "timeout:   %ds\n", t.TimeoutSeconds)
	fmt.Fprintf(w, "enabled:   %t\n", t.Enabled)
	if len(t.Params) > 0 {
		var kv []string
		for k, v := range t.Params {
			kv = append(kv, k+"="+v)
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
	fmt.Fprintln(tw, "ID\tNAME\tHOSTNAME\tSTATUS\tCAPABILITIES")
	for _, a := range agents {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			short(a.ID), a.Name, a.Hostname, a.Status, strings.Join(a.Capabilities, ","))
	}
	_ = tw.Flush()
}

func printAgent(w io.Writer, a Agent) {
	fmt.Fprintf(w, "id:            %s\n", a.ID)
	fmt.Fprintf(w, "name:          %s\n", a.Name)
	fmt.Fprintf(w, "hostname:      %s\n", a.Hostname)
	fmt.Fprintf(w, "agent_version: %s\n", a.AgentVersion)
	fmt.Fprintf(w, "status:        %s\n", a.Status)
	fmt.Fprintf(w, "capabilities:  %s\n", strings.Join(a.Capabilities, ", "))
}
