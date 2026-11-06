// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	guuid "github.com/google/uuid"
)

// These types are used ONLY for server-created role metadata loaded after
// tenant/current-user authorization. Their JSON values are unchanged. Escaped
// separators/digits prevent a random identifier or revision's numeric prefix
// being mistaken for PII by text redaction. No arbitrary text, sender IDs or
// operator rule patterns receive this encoding; their full redaction remains.
type NativeRoleUUID string

type NativeRoleRevision string

// NativeRoleDigest encodes a server-computed SHA-256 provenance identity.
// It is never a sender-controlled identifier or a substitute for authorization.
type NativeRoleDigest string

func (digest NativeRoleDigest) MarshalJSON() ([]byte, error) {
	decoded, err := hex.DecodeString(string(digest))
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != string(digest) {
		return nil, errors.New("invalid server role metadata digest")
	}
	var out strings.Builder
	out.WriteByte('"')
	for _, character := range string(digest) {
		if character >= '0' && character <= '9' {
			out.WriteString(`\u003`)
		}
		out.WriteRune(character)
	}
	out.WriteByte('"')
	return []byte(out.String()), nil
}

func (id NativeRoleUUID) MarshalJSON() ([]byte, error) {
	if id == "" {
		return []byte(`""`), nil
	}
	parsed, err := guuid.Parse(string(id))
	if err != nil || parsed == guuid.Nil || parsed.String() != string(id) {
		return nil, errors.New("invalid server role metadata UUID")
	}
	raw, err := json.Marshal(string(id))
	if err != nil {
		return nil, err
	}
	return []byte(strings.ReplaceAll(string(raw), "-", `\u002d`)), nil
}

func (revision NativeRoleRevision) MarshalJSON() ([]byte, error) {
	value, err := strconv.ParseInt(string(revision), 10, 64)
	if err != nil || value < 0 || strconv.FormatInt(value, 10) != string(revision) {
		return nil, errors.New("invalid server role metadata revision")
	}
	var out strings.Builder
	out.WriteByte('"')
	for _, digit := range string(revision) {
		out.WriteString(`\u003`)
		out.WriteRune(digit)
	}
	out.WriteByte('"')
	return []byte(out.String()), nil
}

// Only configuration references contain exclusively server-created IDs and a
// database revision. Evidence/sender/open-data strings remain untrusted text.
type NativeRoleSource string

func (source NativeRoleSource) MarshalJSON() ([]byte, error) {
	parts := strings.Split(string(source), "/")
	if (len(parts) == 3 && (parts[0] == "policy" || parts[0] == "override")) || (len(parts) == 5 && parts[0] == "policy" && parts[3] == "rule") {
		if parts[1] != "" && parts[2] != "" {
			id, err := NativeRoleUUID(parts[1]).MarshalJSON()
			if err != nil {
				return nil, err
			}
			revision, err := NativeRoleRevision(parts[2]).MarshalJSON()
			if err != nil {
				return nil, err
			}
			encoded := `"` + parts[0] + "/" + string(id[1:len(id)-1]) + "/" + string(revision[1:len(revision)-1])
			if len(parts) == 5 {
				if parts[4] == "" {
					return nil, errors.New("invalid server role metadata rule UUID")
				}
				rule, err := NativeRoleUUID(parts[4]).MarshalJSON()
				if err != nil {
					return nil, err
				}
				encoded += "/rule/" + string(rule[1:len(rule)-1])
			}
			return []byte(encoded + `"`), nil
		}
	}
	return json.Marshal(string(source))
}
