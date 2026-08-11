// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unicode/utf8"
)

const maxIRRevealReasonBytes = 512

func cmdAudit(
	cfg Config,
	args []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) int {
	if len(args) == 0 || args[0] == "help" {
		printSurfaceUsage(stderr, surfaceCommands["audit"])
		fmt.Fprintln(
			stderr,
			"  seal-private-key <tenant-id>  create one offline encrypted IR private-key artifact",
		)
		return 2
	}
	if len(args) > 0 && args[0] == "seal-private-key" {
		return cmdSealIRPrivateKey(args[1:], stdout, stderr)
	}
	if args[0] != "reveal" {
		return cmdSurface(
			cfg,
			surfaceCommands["audit"],
			args,
			stdout,
			stderr,
		)
	}
	if len(args) < 2 {
		fmt.Fprintln(stderr, "audit reveal: missing <event-ref>")
		return 2
	}
	eventRef := args[1]
	if !validCLIIREventRef(eventRef) {
		fmt.Fprintln(
			stderr,
			"audit reveal: <event-ref> must be exactly 64 lowercase hexadecimal characters",
		)
		return 2
	}
	fs := flag.NewFlagSet("audit reveal", flag.ContinueOnError)
	fs.SetOutput(stderr)
	reasonFile := fs.String(
		"reason-file",
		"-",
		"read the investigation reason from stdin (-) or an owner-only file",
	)
	sessionCookieFile := fs.String(
		"session-cookie-file",
		cfg.SessionCookieFile,
		"read an MFA-bearing probectl session cookie from an owner-only file",
	)
	if err := fs.Parse(args[2:]); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintf(
			stderr,
			"audit reveal: unexpected args: %s\n",
			strings.Join(fs.Args(), " "),
		)
		return 2
	}
	reason, err := readIRRevealReason(*reasonFile, stdin)
	if err != nil {
		fmt.Fprintln(stderr, "audit reveal: "+err.Error())
		return 2
	}
	if strings.TrimSpace(*sessionCookieFile) == "" {
		fmt.Fprintln(
			stderr,
			"audit reveal: --session-cookie-file or PROBECTL_SESSION_COOKIE_FILE is required because bearer tokens do not attest MFA",
		)
		return 2
	}
	sessionRaw, err := readOwnerOnlyCLIFile(*sessionCookieFile, 4096)
	if err != nil {
		fmt.Fprintln(stderr, "audit reveal: read session cookie: "+err.Error())
		return 2
	}
	defer clearBytes(sessionRaw)
	cfg.SessionCookie = strings.TrimSpace(string(sessionRaw))
	if cfg.SessionCookie == "" ||
		strings.IndexFunc(cfg.SessionCookie, func(char rune) bool {
			return char <= ' ' || char == 0x7f
		}) >= 0 {
		fmt.Fprintln(stderr, "audit reveal: session cookie is empty or malformed")
		return 2
	}
	var out any
	if err := newClient(cfg).do(
		surfaceCommands["audit"].Ops["reveal"].Method,
		strings.ReplaceAll(
			surfaceCommands["audit"].Ops["reveal"].Path,
			"{event_ref}",
			eventRef,
		),
		map[string]string{"reason": reason},
		&out,
	); err != nil {
		return fail(stderr, err)
	}
	return printJSON(stdout, out)
}

func readIRRevealReason(filename string, stdin io.Reader) (string, error) {
	reader := stdin
	if filename != "-" {
		raw, err := readOwnerOnlyCLIFile(
			filename,
			maxIRRevealReasonBytes+2,
		)
		if err != nil {
			return "", fmt.Errorf("reason file: %w", err)
		}
		defer clearBytes(raw)
		reader = bytes.NewReader(raw)
	}
	raw, err := io.ReadAll(
		io.LimitReader(reader, maxIRRevealReasonBytes+3),
	)
	if err != nil {
		return "", fmt.Errorf("read investigation reason: %w", err)
	}
	if len(raw) > maxIRRevealReasonBytes+2 {
		return "", fmt.Errorf(
			"investigation reason exceeds %d bytes",
			maxIRRevealReasonBytes,
		)
	}
	reason := strings.TrimSpace(string(raw))
	if reason == "" {
		return "", errors.New("investigation reason is required")
	}
	if !utf8.ValidString(reason) {
		return "", errors.New("investigation reason must be valid UTF-8")
	}
	if len(reason) > maxIRRevealReasonBytes {
		return "", fmt.Errorf(
			"investigation reason exceeds %d bytes",
			maxIRRevealReasonBytes,
		)
	}
	return reason, nil
}

func readOwnerOnlyCLIFile(filename string, maxBytes int64) ([]byte, error) {
	return readOwnerOnlyCLIFileWithHook(filename, maxBytes, nil)
}

func readOwnerOnlyCLIFileWithHook(filename string, maxBytes int64, afterInitialLstat func()) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, fmt.Errorf("inspect file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("file must be a real regular file")
	}
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf(
			"file permissions are %04o, want 0600",
			info.Mode().Perm(),
		)
	}
	if info.Size() < 1 || info.Size() > maxBytes {
		return nil, fmt.Errorf("file must contain 1..%d bytes", maxBytes)
	}
	if afterInitialLstat != nil {
		afterInitialLstat()
	}
	// Nonblocking open turns a raced regular-file -> FIFO replacement into a
	// bounded error instead of hanging a credential-bearing CLI command.
	file, err := os.OpenFile(filename, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	linkedAfterOpen, linkedErr := os.Lstat(filename)
	if err != nil {
		return nil, fmt.Errorf("inspect opened file: %w", err)
	}
	if linkedErr != nil || !os.SameFile(info, opened) || !os.SameFile(opened, linkedAfterOpen) ||
		!opened.Mode().IsRegular() || !linkedAfterOpen.Mode().IsRegular() ||
		linkedAfterOpen.Mode()&os.ModeSymlink != 0 || opened.Mode().Perm() != 0o600 || linkedAfterOpen.Mode().Perm() != 0o600 {
		return nil, errors.New("file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	if int64(len(raw)) < 1 || int64(len(raw)) > maxBytes {
		clearBytes(raw)
		return nil, fmt.Errorf("file changed size while reading")
	}
	openedAfterRead, statErr := file.Stat()
	linkedAfterRead, lstatErr := os.Lstat(filename)
	if statErr != nil || lstatErr != nil || !os.SameFile(opened, openedAfterRead) || !os.SameFile(opened, linkedAfterRead) ||
		!openedAfterRead.Mode().IsRegular() || !linkedAfterRead.Mode().IsRegular() ||
		linkedAfterRead.Mode()&os.ModeSymlink != 0 || openedAfterRead.Mode().Perm() != 0o600 || linkedAfterRead.Mode().Perm() != 0o600 ||
		openedAfterRead.Size() != int64(len(raw)) || !openedAfterRead.ModTime().Equal(opened.ModTime()) {
		clearBytes(raw)
		return nil, errors.New("file changed while reading")
	}
	return raw, nil
}

func clearBytes(raw []byte) {
	for index := range raw {
		raw[index] = 0
	}
}

func validCLIIREventRef(eventRef string) bool {
	if len(eventRef) != 64 {
		return false
	}
	for _, char := range eventRef {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}
