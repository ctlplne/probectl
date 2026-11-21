// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"slices"
	"strconv"
	"strings"
)

type ConfigPolicyTemplate string

const (
	ConfigPolicyIOSNTP     ConfigPolicyTemplate = "ios_ntp_server"
	ConfigPolicyIOSSNMPv3  ConfigPolicyTemplate = "ios_snmpv3_only"
	ConfigPolicyIOSVTYSSH  ConfigPolicyTemplate = "ios_vty_ssh_only"
	ConfigPolicyIOSAAA     ConfigPolicyTemplate = "ios_aaa_login"
	ConfigPolicyIOSLogging ConfigPolicyTemplate = "ios_remote_logging"
	ConfigPolicyFRRLogging ConfigPolicyTemplate = "frr_configured_logging"
	ConfigPolicyChronyNTP  ConfigPolicyTemplate = "chrony_ntp_source"
)

func (t ConfigPolicyTemplate) dialect() string {
	switch t {
	case ConfigPolicyIOSNTP, ConfigPolicyIOSSNMPv3, ConfigPolicyIOSVTYSSH, ConfigPolicyIOSAAA, ConfigPolicyIOSLogging:
		return "ios"
	case ConfigPolicyFRRLogging:
		return "frr"
	case ConfigPolicyChronyNTP:
		return "chrony"
	default:
		return ""
	}
}

type configTemplateEvidence struct {
	template          ConfigPolicyTemplate
	header, end       bool
	unknown, conflict bool
	aaa, defaultLogin bool
	bannerDelimiter   string
	vty               bool
	vtyTransport      bool
	vtyRanges         [256]bool
}

func (e *configTemplateEvidence) observe(v *ConfigPolicyVerdict, number int, line string, words []string) {
	if len(words) == 0 {
		return
	}
	switch e.template.dialect() {
	case "chrony":
		e.observeChrony(v, words)
	case "frr":
		e.observeFRR(v, line, words)
	case "ios":
		e.observeIOS(v, number, line, words)
	}
}

func (e *configTemplateEvidence) observeChrony(v *ConfigPolicyVerdict, words []string) {
	switch strings.ToLower(words[0]) {
	case "server", "pool", "peer":
		e.header = true
		if len(words) >= 2 {
			v.Matches++
		} else {
			e.unknown = true
		}
	case "include", "confdir", "sourcedir":
		// The archive represents one file. A source may be in another file
		// that the operator has not supplied.
		e.header, e.unknown = true, true
	case "driftfile", "makestep", "rtcsync", "logdir", "minsources":
		e.header = true
	}
}

func (e *configTemplateEvidence) observeFRR(v *ConfigPolicyVerdict, line string, words []string) {
	if strings.TrimLeft(line, " \t") != line {
		return
	}
	switch {
	case configCommand(words, "frr", "version") && len(words) >= 3:
		e.header = true
	case configCommand(words, "log", "syslog"), configCommand(words, "log", "file") && len(words) >= 3:
		v.Matches++
	}
}

func (e *configTemplateEvidence) observeIOS(v *ConfigPolicyVerdict, number int, line string, words []string) {
	if e.skipIOSBanner(line, words) {
		return
	}
	topLevel := strings.TrimLeft(line, " \t") == line
	if topLevel || words[0] == "!" || words[0] == "exit" {
		e.closeVTY()
	}
	if !topLevel {
		if e.vty {
			e.observeVTYTransport(v, number, line, words)
		}
		return
	}
	switch {
	case configCommand(words, "version") && len(words) == 2 && configIOSVersion(words[1]):
		e.header = true
	case configCommand(words, "macro", "name"):
		// An opaque multiline macro can contain complete, inactive
		// commands at the same indentation as the running configuration.
		e.conflict = true
	case len(words) == 1 && words[0] == "end":
		e.end = true
	case e.end && words[0] != "!":
		e.conflict = true
	}
	switch e.template {
	case ConfigPolicyIOSNTP:
		if configCommand(words, "ntp", "server") && len(words) >= 3 &&
			(words[2] != "vrf" || len(words) >= 5) {
			v.Matches++
		}
	case ConfigPolicyIOSSNMPv3:
		e.observeIOSSNMP(v, number, line, words)
	case ConfigPolicyIOSVTYSSH:
		if configCommand(words, "line", "vty") {
			e.openVTY(words[2:])
		}
	case ConfigPolicyIOSAAA:
		e.observeIOSAAA(v, number, line, words)
	case ConfigPolicyIOSLogging:
		if configCommand(words, "logging", "host") && len(words) >= 3 {
			v.Matches++
		}
	}
}

func (e *configTemplateEvidence) skipIOSBanner(line string, words []string) bool {
	if e.bannerDelimiter != "" {
		if strings.Contains(line, e.bannerDelimiter) {
			e.bannerDelimiter = ""
		}
		return true
	}
	if words[0] != "banner" || strings.TrimLeft(line, " \t") != line {
		return false
	}
	if len(words) < 3 {
		e.conflict = true
		return true
	}
	body := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(line, "banner")), words[1]))
	n := 1
	if len(body) >= 2 && body[0] == '^' {
		n++
	}
	e.bannerDelimiter = body[:n]
	if strings.Contains(body[n:], e.bannerDelimiter) {
		e.bannerDelimiter = ""
	}
	return true
}

func (e *configTemplateEvidence) observeIOSAAA(v *ConfigPolicyVerdict, number int, line string, words []string) {
	if configCommand(words, "aaa", "new-model") && len(words) == 2 {
		e.aaa = true
	}
	if !configCommand(words, "aaa", "authentication", "login", "default") {
		return
	}
	if e.defaultLogin || len(words) < 5 {
		e.conflict = true
	}
	e.defaultLogin = true
	if slices.Contains(words[4:], "none") {
		v.addOffendingLine(number, line)
	}
}

func (e *configTemplateEvidence) observeIOSSNMP(v *ConfigPolicyVerdict, number int, line string, words []string) {
	switch {
	case configCommand(words, "snmp-server", "community"):
		v.addOffendingLine(number, line)
	case configCommand(words, "snmp-server", "group") && len(words) >= 4:
		switch words[3] {
		case "v3":
			v.Matches++
		case "v1", "v2c":
			v.addOffendingLine(number, line)
		default:
			e.unknown = true
		}
	case configCommand(words, "snmp-server", "host") && len(words) >= 4:
		options := words[3:]
		i := slices.Index(options, "version")
		if i == -1 || i+1 < len(options) && (options[i+1] == "1" || options[i+1] == "2c") {
			v.addOffendingLine(number, line)
		} else if i+1 >= len(options) || options[i+1] != "3" {
			e.unknown = true
		}
	}
}

func (e *configTemplateEvidence) openVTY(bounds []string) {
	if len(bounds) == 0 || len(bounds) > 2 {
		e.conflict = true
		return
	}
	first, firstErr := strconv.ParseUint(bounds[0], 10, 8)
	last, lastErr := strconv.ParseUint(bounds[len(bounds)-1], 10, 8)
	if firstErr != nil || lastErr != nil || last < first {
		e.conflict = true
		return
	}
	for i := first; i <= last; i++ {
		if e.vtyRanges[i] {
			e.conflict = true
		}
		e.vtyRanges[i] = true
	}
	e.vty, e.vtyTransport = true, false
}

func (e *configTemplateEvidence) observeVTYTransport(v *ConfigPolicyVerdict, number int, line string, words []string) {
	if configCommand(words, "no", "transport", "input") {
		e.conflict = e.conflict || e.vtyTransport
		e.vtyTransport, e.unknown = true, true
		return
	}
	if !configCommand(words, "transport", "input") {
		return
	}
	e.conflict = e.conflict || e.vtyTransport
	e.vtyTransport = true
	if len(words) < 3 {
		e.unknown = true
		return
	}
	if len(words) == 3 && (words[2] == "ssh" || words[2] == "none") {
		v.Matches++
		return
	}
	v.addOffendingLine(number, line)
}

func (e *configTemplateEvidence) closeVTY() {
	if e.vty && !e.vtyTransport {
		e.unknown = true
	}
	e.vty = false
}

func (e *configTemplateEvidence) finish(v *ConfigPolicyVerdict) {
	e.closeVTY()
	if !e.header || e.conflict || e.template.dialect() == "ios" && (!e.end || e.bannerDelimiter != "") {
		v.Matches, v.OffendingLines = 0, nil
		return
	}
	if e.template == ConfigPolicyIOSAAA && e.aaa && e.defaultLogin && len(v.OffendingLines) == 0 {
		v.Matches = 1
	}
	switch {
	case len(v.OffendingLines) > 0:
		v.State = "violation"
	case e.unknown && (e.template != ConfigPolicyChronyNTP || v.Matches == 0):
		v.Matches = 0
	case v.Matches > 0:
		v.State = "pass"
	case e.template != ConfigPolicyIOSVTYSSH:
		v.State = "violation"
	}
}

func configCommand(words []string, command ...string) bool {
	return len(words) >= len(command) && slices.Equal(words[:len(command)], command)
}

func configIOSVersion(value string) bool {
	major, minor, ok := strings.Cut(value, ".")
	if !ok || major == "" || minor == "" || strings.Contains(minor, ".") {
		return false
	}
	_, majorErr := strconv.ParseUint(major, 10, 8)
	_, minorErr := strconv.ParseUint(minor, 10, 8)
	return majorErr == nil && minorErr == nil
}
