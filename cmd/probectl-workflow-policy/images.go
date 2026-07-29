// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var literalDigestImagePattern = regexp.MustCompile(`^[^@[:space:]]+@sha256:[0-9a-fA-F]{64}$`)

type dockerOptionSet struct {
	longValues  map[string]struct{}
	longFlags   map[string]struct{}
	shortValues string
	shortFlags  string
}

var (
	dockerGlobalOptions = dockerOptionSet{
		longValues: stringSet(
			"config", "context", "host", "log-level",
			"tlscacert", "tlscert", "tlskey",
		),
		longFlags:   stringSet("debug", "tls", "tlsverify", "version"),
		shortValues: "cHl",
		shortFlags:  "Dv",
	}
	dockerRunOptions = dockerOptionSet{
		longValues: stringSet(
			"add-host", "annotation", "attach", "blkio-weight",
			"blkio-weight-device", "cap-add", "cap-drop", "cgroup-parent",
			"cgroupns", "cidfile", "cpu-period", "cpu-quota", "cpu-rt-period",
			"cpu-rt-runtime", "cpu-shares", "cpus", "cpuset-cpus", "cpuset-mems",
			"detach-keys", "device", "device-cgroup-rule", "device-read-bps",
			"device-read-iops", "device-write-bps", "device-write-iops", "dns",
			"dns-option", "dns-search", "domainname", "entrypoint", "env",
			"env-file", "expose", "gpus", "group-add", "health-cmd",
			"health-interval", "health-retries", "health-start-interval",
			"health-start-period", "health-timeout", "hostname", "ip", "ip6",
			"ipc", "isolation", "kernel-memory", "label", "label-file", "link",
			"link-local-ip", "log-driver", "log-opt", "mac-address", "memory",
			"memory-reservation", "memory-swap", "memory-swappiness", "mount",
			"name", "network", "network-alias", "oom-score-adj", "pid",
			"pids-limit", "platform", "publish", "pull", "restart", "runtime",
			"security-opt", "shm-size", "stop-signal", "stop-timeout",
			"storage-opt", "sysctl", "tmpfs", "ulimit", "user", "userns", "uts",
			"volume", "volume-driver", "volumes-from", "workdir",
		),
		longFlags: stringSet(
			"detach", "init", "interactive", "no-healthcheck",
			"oom-kill-disable", "privileged", "publish-all", "quiet",
			"read-only", "rm", "sig-proxy", "tty",
		),
		shortValues: "acehlmpuvw",
		shortFlags:  "diPqt",
	}
	dockerPullOptions = dockerOptionSet{
		longValues:  stringSet("platform"),
		longFlags:   stringSet("all-tags", "disable-content-trust", "quiet"),
		shortValues: "",
		shortFlags:  "aq",
	}
)

type imageFinding struct {
	line   int
	key    string
	value  string
	reason string
}

type shellWord struct {
	value       string
	line        int
	redirection bool
	dynamic     bool
}

func runImages(paths []string, stdout, stderr io.Writer) int {
	files, err := workflowFiles(paths)
	if err != nil {
		fmt.Fprintf(stderr, "workflow-policy: %v\n", err)
		return 1
	}
	if len(files) == 0 {
		fmt.Fprintln(stderr, "workflow-policy: no .yml or .yaml workflows found")
		return 1
	}

	failed := false
	for _, path := range files {
		root, err := loadWorkflow(path)
		if err != nil {
			fmt.Fprintf(stderr, "workflow-policy: %v\n", err)
			failed = true
			continue
		}
		findings, err := workflowImageFindings(root)
		if err != nil {
			fmt.Fprintf(stderr, "workflow-policy: %s: %v\n", path, err)
			failed = true
			continue
		}
		for _, finding := range findings {
			fmt.Fprintln(stdout, "MUTABLE workflow image (container/service/matrix/docker run/pull must use a literal @sha256 digest; SUPPLY-002/SUPPLY-4ca4490d):")
			fmt.Fprintf(stdout, "  %s:%d:%s: %q (%s)\n", path, finding.line, finding.key, finding.value, finding.reason)
			failed = true
		}
	}
	if failed {
		return 1
	}
	return 0
}

func workflowFiles(paths []string) ([]string, error) {
	seen := make(map[string]struct{})
	var files []string
	addFile := func(path string) error {
		if _, ok := seen[path]; ok {
			return nil
		}
		if len(files) >= maxWorkflowFiles {
			return fmt.Errorf("workflow file count exceeds %d-file limit", maxWorkflowFiles)
		}
		seen[path] = struct{}{}
		files = append(files, path)
		return nil
	}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("inspect %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s: workflow path must not be a symlink", path)
		}
		if !info.IsDir() {
			if !isWorkflowYAML(path) {
				return nil, fmt.Errorf("%s: workflow path must end in .yml or .yaml", path)
			}
			if err := addFile(path); err != nil {
				return nil, err
			}
			continue
		}
		err = filepath.WalkDir(path, func(candidate string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !isWorkflowYAML(candidate) {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("%s: workflow must be a regular file", candidate)
			}
			return addFile(candidate)
		})
		if err != nil {
			return nil, fmt.Errorf("walk %s: %w", path, err)
		}
	}
	sort.Strings(files)
	return files, nil
}

func isWorkflowYAML(path string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	return extension == ".yml" || extension == ".yaml"
}

func workflowImageFindings(root *yaml.Node) ([]imageFinding, error) {
	jobs, ok := mappingValue(root, "jobs")
	if !ok {
		return nil, fmt.Errorf("$.jobs: required mapping is missing")
	}
	if jobs.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("$.jobs: must be a mapping")
	}

	var findings []imageFinding
	walkWorkflowImages(jobs, &findings)
	return findings, nil
}

func walkWorkflowImages(node *yaml.Node, findings *[]imageFinding) {
	switch node.Kind {
	case yaml.MappingNode:
		for index := 0; index < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			switch key.Value {
			case "container":
				if value.Kind == yaml.MappingNode {
					if _, ok := mappingValue(value, "image"); !ok {
						*findings = append(*findings, imageFinding{
							line:   value.Line,
							key:    key.Value,
							value:  nodeDescription(value),
							reason: "container mapping has no direct literal image",
						})
					}
					walkWorkflowImages(value, findings)
					continue
				}
				if finding := inspectImageValue(key.Value, value); finding != nil {
					*findings = append(*findings, *finding)
				}
			case "image":
				if finding := inspectImageValue(key.Value, value); finding != nil {
					*findings = append(*findings, *finding)
				}
			case "steps":
				walkWorkflowSteps(value, findings)
			default:
				walkWorkflowImages(value, findings)
			}
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			walkWorkflowImages(child, findings)
		}
	}
}

func walkWorkflowSteps(node *yaml.Node, findings *[]imageFinding) {
	if node.Kind != yaml.SequenceNode {
		walkWorkflowImages(node, findings)
		return
	}
	for _, step := range node.Content {
		if step.Kind == yaml.MappingNode {
			if run, ok := mappingValue(step, "run"); ok {
				*findings = append(*findings, inspectDockerRunScript(run)...)
			}
		}
		walkWorkflowImages(step, findings)
	}
}

func inspectDockerRunScript(node *yaml.Node) []imageFinding {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return nil
	}

	// This is deliberately static: tokenize literal shell text, never execute
	// it or expand expressions, and reject an ambiguous Docker option layout.
	var findings []imageFinding
	for _, command := range staticShellCommands(node.Value) {
		dockerIndex := dockerExecutableIndex(command)
		if dockerIndex < 0 {
			continue
		}
		subcommand, optionStart, targeted, reason := dockerImageSubcommand(command, dockerIndex)
		if !targeted {
			continue
		}
		if reason != "" {
			findings = append(findings, dockerCommandFinding(node, command[dockerIndex], subcommand, commandDescription(command), reason))
			continue
		}

		options := dockerRunOptions
		if subcommand == "pull" {
			options = dockerPullOptions
		}
		operandIndex, stop, reason := firstDockerArgument(command, optionStart, options)
		if stop {
			continue
		}
		if reason != "" {
			findings = append(findings, dockerCommandFinding(node, command[dockerIndex], subcommand, commandDescription(command), reason))
			continue
		}

		operand := command[operandIndex]
		if operand.dynamic || strings.Contains(operand.value, "${{") {
			findings = append(findings, dockerCommandFinding(
				node,
				operand,
				subcommand,
				operand.value,
				"docker image operand contains an unresolved shell or GitHub expression",
			))
			continue
		}
		if !literalDigestImagePattern.MatchString(operand.value) {
			findings = append(findings, dockerCommandFinding(
				node,
				operand,
				subcommand,
				operand.value,
				"docker image operand is not a literal digest reference",
			))
		}
	}
	return findings
}

func dockerImageSubcommand(words []shellWord, dockerIndex int) (string, int, bool, string) {
	subcommandIndex, stop, reason := firstDockerArgument(words, dockerIndex+1, dockerGlobalOptions)
	if stop {
		return "", 0, false, ""
	}
	if reason != "" {
		for index := dockerIndex + 1; index < len(words); index++ {
			if words[index].redirection {
				index++
				continue
			}
			if words[index].value == "run" || words[index].value == "pull" {
				return words[index].value, 0, true, "docker options before the subcommand are ambiguous: " + reason
			}
		}
		return "", 0, false, ""
	}

	subcommandWord := words[subcommandIndex]
	if unresolvedShellWord(subcommandWord) {
		return "run/pull", 0, true, "docker subcommand contains an unresolved shell or GitHub expression"
	}
	subcommand := subcommandWord.value
	optionStart := subcommandIndex + 1
	if subcommand == "container" || subcommand == "image" {
		namespacedIndex := nextShellArgument(words, optionStart)
		if namespacedIndex < 0 {
			return "", 0, false, ""
		}
		namespacedWord := words[namespacedIndex]
		if unresolvedShellWord(namespacedWord) {
			candidate := "run"
			if subcommand == "image" {
				candidate = "pull"
			}
			return candidate, 0, true, "namespaced docker subcommand contains an unresolved shell or GitHub expression"
		}
		namespaced := namespacedWord.value
		if (subcommand == "container" && namespaced != "run") ||
			(subcommand == "image" && namespaced != "pull") {
			return "", 0, false, ""
		}
		subcommand = namespaced
		optionStart = namespacedIndex + 1
	}
	if subcommand != "run" && subcommand != "pull" {
		return "", 0, false, ""
	}
	return subcommand, optionStart, true, ""
}

func unresolvedShellWord(word shellWord) bool {
	return word.dynamic || strings.Contains(word.value, "${{")
}

func firstDockerArgument(words []shellWord, start int, options dockerOptionSet) (int, bool, string) {
	for index := nextShellArgument(words, start); index >= 0; index = nextShellArgument(words, index+1) {
		value := words[index].value
		if value == "--" {
			operand := nextShellArgument(words, index+1)
			if operand < 0 {
				return -1, false, "docker command has no image operand after --"
			}
			return operand, false, ""
		}
		if value == "--help" || strings.HasPrefix(value, "--help=") {
			return -1, true, ""
		}
		if !strings.HasPrefix(value, "-") || value == "-" {
			return index, false, ""
		}

		if strings.HasPrefix(value, "--") {
			name, _, hasValue := strings.Cut(strings.TrimPrefix(value, "--"), "=")
			if _, ok := options.longFlags[name]; ok {
				continue
			}
			if _, ok := options.longValues[name]; ok {
				if hasValue {
					continue
				}
				optionValue := nextShellArgument(words, index+1)
				if optionValue < 0 {
					return -1, false, fmt.Sprintf("docker option %s has no value", value)
				}
				index = optionValue
				continue
			}
			return -1, false, fmt.Sprintf("unknown docker option %s prevents static image parsing", value)
		}

		consumeNext, ok := parseShortDockerOptions(value, options)
		if !ok {
			return -1, false, fmt.Sprintf("unknown docker option %s prevents static image parsing", value)
		}
		if consumeNext {
			optionValue := nextShellArgument(words, index+1)
			if optionValue < 0 {
				return -1, false, fmt.Sprintf("docker option %s has no value", value)
			}
			index = optionValue
		}
	}
	return -1, false, "docker command has no statically identifiable image operand"
}

func parseShortDockerOptions(value string, options dockerOptionSet) (bool, bool) {
	if len(value) < 2 || value[0] != '-' || value[1] == '-' {
		return false, false
	}
	for index := 1; index < len(value); index++ {
		option := value[index]
		if strings.ContainsRune(options.shortFlags, rune(option)) {
			continue
		}
		if strings.ContainsRune(options.shortValues, rune(option)) {
			return index == len(value)-1, true
		}
		return false, false
	}
	return false, true
}

func dockerExecutableIndex(words []shellWord) int {
	for index := 0; index < len(words); {
		if words[index].redirection {
			index += 2
			continue
		}
		value := words[index].value
		if isShellAssignment(value) || isShellCommandPrefix(value) {
			index++
			continue
		}

		var valueOptions map[string]struct{}
		switch value {
		case "command":
			valueOptions = stringSet()
		case "env":
			valueOptions = stringSet("-C", "--chdir", "-S", "--split-string", "-u", "--unset")
		case "exec":
			valueOptions = stringSet("-a")
		case "sudo":
			valueOptions = stringSet(
				"-C", "--close-from", "-D", "--chdir", "-g", "--group",
				"-h", "--host", "-p", "--prompt", "-R", "--chroot",
				"-T", "--command-timeout", "-u", "--user",
			)
		case "time":
			valueOptions = stringSet("-f", "--format", "-o", "--output")
		default:
			if filepath.Base(value) == "docker" {
				return index
			}
			return -1
		}
		index = skipShellWrapper(words, index+1, valueOptions)
	}
	return -1
}

func skipShellWrapper(words []shellWord, start int, valueOptions map[string]struct{}) int {
	for index := start; index < len(words); {
		if words[index].redirection {
			index += 2
			continue
		}
		value := words[index].value
		if value == "--" {
			return index + 1
		}
		if isShellAssignment(value) {
			index++
			continue
		}
		if !strings.HasPrefix(value, "-") || value == "-" {
			return index
		}
		name, _, attached := strings.Cut(value, "=")
		if _, needsValue := valueOptions[name]; needsValue && !attached {
			optionValue := nextShellArgument(words, index+1)
			if optionValue < 0 {
				return len(words)
			}
			index = optionValue + 1
			continue
		}
		index++
	}
	return len(words)
}

func isShellAssignment(value string) bool {
	name, _, ok := strings.Cut(value, "=")
	if !ok || name == "" {
		return false
	}
	for index, character := range name {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			character == '_' ||
			(index > 0 && character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return true
}

func isShellCommandPrefix(value string) bool {
	switch value {
	case "!", "{", "do", "elif", "else", "if", "then", "until", "while":
		return true
	default:
		return false
	}
}

func nextShellArgument(words []shellWord, start int) int {
	for index := start; index < len(words); index++ {
		if !words[index].redirection {
			return index
		}
		index++
	}
	return -1
}

func dockerCommandFinding(node *yaml.Node, word shellWord, subcommand, value, reason string) imageFinding {
	line := node.Line + word.line - 1
	if node.Style == yaml.LiteralStyle || node.Style == yaml.FoldedStyle {
		line++
	}
	return imageFinding{
		line:   line,
		key:    "docker " + subcommand,
		value:  boundedDiagnostic(value),
		reason: reason,
	}
}

func boundedDiagnostic(value string) string {
	const maxBytes = 256
	if len(value) <= maxBytes {
		return value
	}
	return value[:maxBytes] + "..."
}

func commandDescription(words []shellWord) string {
	values := make([]string, 0, len(words))
	for _, word := range words {
		values = append(values, word.value)
	}
	return strings.Join(values, " ")
}

func staticShellCommands(script string) [][]shellWord {
	// Recognize only shell word boundaries needed to locate direct Docker
	// commands. Quotes and continuations are decoded lexically; nothing is
	// evaluated, and expansion-bearing image words remain marked dynamic.
	var (
		commands    [][]shellWord
		command     []shellWord
		word        strings.Builder
		wordLine    = 1
		line        = 1
		quote       byte
		wordStarted bool
		wordDynamic bool
	)

	startWord := func() {
		if !wordStarted {
			wordStarted = true
			wordLine = line
		}
	}
	flushWord := func() {
		if !wordStarted {
			return
		}
		command = append(command, shellWord{
			value:   word.String(),
			line:    wordLine,
			dynamic: wordDynamic,
		})
		word.Reset()
		wordStarted = false
		wordDynamic = false
	}
	flushCommand := func() {
		flushWord()
		if len(command) == 0 {
			return
		}
		commands = append(commands, command)
		command = nil
	}

	for index := 0; index < len(script); index++ {
		character := script[index]
		if quote != 0 {
			if character == quote {
				quote = 0
				continue
			}
			if quote == '"' && character == '\\' && index+1 < len(script) {
				next := script[index+1]
				if next == '\n' {
					index++
					line++
					continue
				}
				startWord()
				word.WriteByte(next)
				index++
				continue
			}
			startWord()
			if quote == '"' && (character == '$' || character == '`') {
				wordDynamic = true
			}
			word.WriteByte(character)
			if character == '\n' {
				line++
			}
			continue
		}

		switch character {
		case '\\':
			if index+1 >= len(script) {
				startWord()
				word.WriteByte(character)
				continue
			}
			next := script[index+1]
			if next == '\n' {
				index++
				line++
				continue
			}
			startWord()
			word.WriteByte(next)
			index++
		case '\'', '"':
			startWord()
			quote = character
		case ' ', '\t', '\r':
			flushWord()
		case '\n':
			flushCommand()
			line++
		case '#':
			if wordStarted {
				word.WriteByte(character)
				continue
			}
			for index+1 < len(script) && script[index+1] != '\n' {
				index++
			}
		case ';', '|', '&', '(', ')', '`':
			flushCommand()
			if index+1 < len(script) && script[index+1] == character &&
				(character == ';' || character == '|' || character == '&') {
				index++
			}
		case '<', '>':
			if wordStarted && decimalWord(word.String()) {
				word.Reset()
				wordStarted = false
				wordDynamic = false
			} else {
				flushWord()
			}
			redirection := shellWord{value: string(character), line: line, redirection: true}
			if index+1 < len(script) {
				next := script[index+1]
				if next == character || next == '&' || (character == '<' && next == '>') {
					redirection.value += string(next)
					index++
				}
			}
			command = append(command, redirection)
		default:
			startWord()
			if character == '$' || character == '*' || character == '?' ||
				character == '[' || character == '{' {
				wordDynamic = true
			}
			word.WriteByte(character)
		}
	}
	flushCommand()
	return commands
}

func decimalWord(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func stringSet(values ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func inspectImageValue(key string, node *yaml.Node) *imageFinding {
	finding := &imageFinding{
		line:  node.Line,
		key:   key,
		value: nodeDescription(node),
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		finding.reason = "image value must be a string"
		return finding
	}
	finding.value = node.Value
	if node.Style == yaml.LiteralStyle || node.Style == yaml.FoldedStyle || strings.ContainsAny(node.Value, "\r\n") {
		finding.reason = "multiline image values are not allowed"
		return finding
	}
	if strings.Contains(node.Value, "${{") {
		finding.reason = "GitHub expression is unresolved"
		return finding
	}
	if !literalDigestImagePattern.MatchString(node.Value) {
		finding.reason = "image is not a literal digest reference"
		return finding
	}
	return nil
}

func nodeDescription(node *yaml.Node) string {
	if node.Kind == yaml.ScalarNode {
		return node.Value
	}
	switch node.Kind {
	case yaml.MappingNode:
		return "<mapping>"
	case yaml.SequenceNode:
		return "<sequence>"
	case yaml.AliasNode:
		return "<alias>"
	default:
		return "<non-string>"
	}
}
