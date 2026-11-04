// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowsnapshot

import (
	"encoding/base64"
	"strings"
)

// The signed payload contains only canonical continuation control metadata.
// Letter encoding keeps random MAC bytes from resembling a credential, phone,
// card or dotted hostname when the complete native result is redacted. No
// result field is exempted from the mandatory redactor.
const cursorEncodingPrefix = "fc2~"
const cursorEncodingLetters = "abcdefghijklmnop"

func encodeCursor(body, mac []byte) string {
	return cursorEncodingPrefix + encodeCursorPart(body) + "~" + encodeCursorPart(mac)
}

func encodeCursorPart(body []byte) string {
	result := make([]byte, 2*len(body))
	for i, value := range body {
		result[2*i] = cursorEncodingLetters[value>>4]
		result[2*i+1] = cursorEncodingLetters[value&15]
	}
	return string(result)
}

func decodeCursorPart(part string) ([]byte, error) {
	if len(part)%2 != 0 {
		return nil, ErrCursor
	}
	result := make([]byte, len(part)/2)
	for i := range result {
		high, low := part[2*i]-'a', part[2*i+1]-'a'
		if high > 15 || low > 15 {
			return nil, ErrCursor
		}
		result[i] = high<<4 | low
	}
	return result, nil
}

func decodeCursorParts(cursor string) ([]byte, []byte, error) {
	if strings.HasPrefix(cursor, cursorEncodingPrefix) {
		encoded, signature, ok := strings.Cut(strings.TrimPrefix(cursor, cursorEncodingPrefix), "~")
		if !ok {
			return nil, nil, ErrCursor
		}
		body, err := decodeCursorPart(encoded)
		if err != nil {
			return nil, nil, err
		}
		mac, err := decodeCursorPart(signature)
		return body, mac, err
	}
	// Existing clients and snapshots can still present intact legacy cursors.
	encoded, signature, ok := strings.Cut(cursor, ".")
	if !ok {
		return nil, nil, ErrCursor
	}
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, ErrCursor
	}
	mac, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return nil, nil, ErrCursor
	}
	return body, mac, nil
}
