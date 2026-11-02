// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/nmsimport"
)

var deviceCredentialName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)

func cmdNMSImport(cfg Config, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "config-export" {
		return cmdNMSImportConfigExport(cfg, args[1:], stdout, stderr)
	}
	if len(args) == 0 || args[0] == "help" {
		printSurfaceUsage(stderr, surfaceCommands["nms-import"])
		fmt.Fprintln(stderr, "  config-export  write one reviewed, exact agent-target YAML with a separate owner-only credential-name file")
		return 2
	}
	return cmdSurfaceWithStdin(cfg, surfaceCommands["nms-import"], args, stdin, stdout, stderr)
}

// config-export reads only a credential name from the owner's local file.
// The server returns a credential-free exact binding; neither source IP nor
// a vendor credential can select or activate an agent target.
func cmdNMSImportConfigExport(cfg Config, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nms-import config-export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	contextID := fs.String("context-id", "", "routing-context UUID")
	sourceID := fs.String("source-id", "", "configured source UUID")
	itemID := fs.String("item-id", "", "reviewed Zabbix SNMP item UUID")
	agentID := fs.String("agent-id", "", "currently bound device-agent ID")
	target := fs.String("target-address", "", "exact configured device target")
	transport := fs.String("transport", "", "explicit snmpv2c or snmpv3 transport")
	credentialFile := fs.String("credential-name-file", "", "0600 file containing a local device credential name")
	expectedPlan := fs.String("expected-plan-id", "", "reviewed proposal's current plan UUID")
	expectedRevision := fs.Int64("expected-revision", 0, "reviewed proposal's current revision")
	output := fs.String("out", "", "new 0600 device-agent YAML file")
	if wantsHelp(args) {
		fmt.Fprintln(stdout, "usage: probectl nms-import config-export --context-id UUID --source-id UUID --item-id UUID --agent-id ID --target-address ADDRESS --transport snmpv2c|snmpv3 --credential-name-file 0600-FILE --expected-plan-id UUID --expected-revision N --out NEW-FILE")
		return 0
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 || *contextID == "" || *sourceID == "" || *itemID == "" ||
		*agentID == "" || *target == "" || *credentialFile == "" || *output == "" ||
		*expectedRevision < 1 || (*transport != device.TransportSNMPv2c && *transport != device.TransportSNMPv3) {
		fmt.Fprintln(stderr, "nms-import config-export: exact selection, reviewed revision, transport, credential-name-file and out are required")
		return 2
	}
	for _, id := range []string{*contextID, *sourceID, *expectedPlan} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			fmt.Fprintln(stderr, "nms-import config-export: context, source and plan IDs must be canonical UUIDs")
			return 2
		}
	}
	rawName, err := readOwnerOnlyCLIFile(*credentialFile, 64)
	if err != nil {
		fmt.Fprintf(stderr, "nms-import config-export: credential-name-file: %v\n", err)
		return 2
	}
	defer clearBytes(rawName)
	name := strings.TrimSpace(string(rawName))
	if !deviceCredentialName.MatchString(name) || len(name) != len(strings.TrimSuffix(string(rawName), "\n")) {
		fmt.Fprintln(stderr, "nms-import config-export: invalid device credential name")
		return 2
	}
	var preview nmsimport.PollTargetPreview
	request := map[string]string{"context_id": *contextID, "source_id": *sourceID,
		"item_external_id": *itemID, "agent_id": *agentID, "target_address": *target}
	if err := newClient(cfg).do(http.MethodPost, "/v1/nms-imports/poll-target-preview", request, &preview); err != nil {
		return fail(stderr, err)
	}
	if preview.TenantID == "" || preview.ContextID != *contextID || preview.SourceID != *sourceID ||
		preview.ItemID != *itemID || preview.AgentID != *agentID || preview.TargetAddress != *target ||
		preview.PlanID != *expectedPlan || preview.Revision != *expectedRevision ||
		preview.PollSeconds < 15 || preview.PollSeconds > 86400 ||
		(cfg.Tenant != "" && cfg.Tenant != preview.TenantID) {
		fmt.Fprintln(stderr, "nms-import config-export: reviewed proposal or exact agent target changed")
		return 1
	}
	// Use the shipped YAML keys and parser. A generated file is complete for
	// one target and remains inert until an operator installs it on the agent.
	document := struct {
		APIVersion string `yaml:"apiVersion"`
		TenantID   string `yaml:"tenant_id"`
		AgentID    string `yaml:"agent_id"`
		Devices    []struct {
			Address    string `yaml:"address"`
			Transport  string `yaml:"transport"`
			Credential string `yaml:"credential"`
			Interval   string `yaml:"interval"`
		} `yaml:"devices"`
	}{APIVersion: device.ConfigAPIVersion, TenantID: preview.TenantID, AgentID: preview.AgentID}
	document.Devices = append(document.Devices, struct {
		Address    string `yaml:"address"`
		Transport  string `yaml:"transport"`
		Credential string `yaml:"credential"`
		Interval   string `yaml:"interval"`
	}{Address: preview.TargetAddress, Transport: *transport, Credential: name,
		Interval: (time.Duration(preview.PollSeconds) * time.Second).String()})
	fragment, err := yaml.Marshal(document)
	if err != nil {
		fmt.Fprintln(stderr, "nms-import config-export: cannot encode device config")
		return 1
	}
	if _, err := device.Parse(fragment); err != nil {
		fmt.Fprintf(stderr, "nms-import config-export: generated device config refused: %v\n", err)
		return 1
	}
	if err := writeExclusiveCLIFile(*output, fragment, 0o600); err != nil {
		fmt.Fprintf(stderr, "nms-import config-export: cannot create output: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote reviewed device-agent config to %s (tenant %s, agent %s, %ds; install explicitly)\n",
		*output, preview.TenantID, preview.AgentID, preview.PollSeconds)
	return 0
}
