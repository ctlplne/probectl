// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package wire

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	ManagedProcessCapability = "agent.endpoint_process.v1"
	ManagedProcessMetadata   = "x-probectl-endpoint-process-v1"
	EndpointPackageLimit     = 64 << 20
	EndpointPackageChunk     = 64 << 10
	EndpointPackageDeadline  = 2 * time.Minute
)

// ManagedProcess is carried by the authenticated Register and Heartbeat RPCs.
// RunID identifies an invocation and Sequence number 0 opens its registration.
// Neither value carries tenant, agent, or authorization authority.
type ManagedProcess struct {
	Platform           string `json:"platform"`
	RunID              string `json:"run_id"`
	Sequence           int64  `json:"sequence"`
	ExecutableIdentity string `json:"executable_identity,omitempty"`
}

func IsManagedPlatform(platform string) bool {
	switch platform {
	case "darwin/amd64", "darwin/arm64", "windows/amd64", "windows/arm64":
		return true
	default:
		return false
	}
}

var (
	cdhash = regexp.MustCompile(`^cdhash:[0-9a-f]{40}$`)
	sha256 = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func ValidExecutableIdentity(platform, value string) bool {
	switch platform {
	case "darwin/amd64", "darwin/arm64":
		return cdhash.MatchString(value)
	case "windows/amd64", "windows/arm64":
		return sha256.MatchString(value)
	default:
		return false
	}
}

func (p ManagedProcess) Valid() bool {
	nonce, err := uuid.Parse(p.RunID)
	return err == nil && nonce.String() == p.RunID && nonce.Version() == 4 && nonce.Variant() == uuid.RFC4122 &&
		IsManagedPlatform(p.Platform) && p.Sequence >= 0 && (p.ExecutableIdentity == "" ||
		(p.Sequence > 0 && ValidExecutableIdentity(p.Platform, p.ExecutableIdentity)))
}

func (p ManagedProcess) HeaderValue() string {
	return strings.Join([]string{p.Platform, p.RunID, strconv.FormatInt(p.Sequence, 10), p.ExecutableIdentity}, "|")
}

func ParseManagedProcess(raw string) (ManagedProcess, error) {
	if len(raw) > 160 {
		return ManagedProcess{}, errors.New("endpoint process metadata exceeds its bound")
	}
	fields := strings.Split(raw, "|")
	if len(fields) != 4 {
		return ManagedProcess{}, errors.New("invalid endpoint process metadata")
	}
	sequence, err := strconv.ParseInt(fields[2], 10, 64)
	process := ManagedProcess{Platform: fields[0], RunID: fields[1], Sequence: sequence, ExecutableIdentity: fields[3]}
	if err != nil || strconv.FormatInt(sequence, 10) != fields[2] || !process.Valid() {
		return ManagedProcess{}, errors.New("invalid endpoint process metadata")
	}
	return process, nil
}
