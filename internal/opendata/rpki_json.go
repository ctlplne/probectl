// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var errRPKIJSON = errors.New("malformed or incomplete validator export")

type rpkiJSONBudget struct{ memory, work int64 }

type rpkiJSONReader struct {
	ctx     context.Context
	decoder *json.Decoder
	budget  *rpkiJSONBudget
}

func (r *rpkiJSONReader) token(memory *int64) (json.Token, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	if r.budget.work < 128 || *memory < 128 {
		return nil, ErrRPKIVRPBudget
	}
	r.budget.work -= 128
	*memory -= 128
	token, err := r.decoder.Token()
	if err != nil {
		return nil, err
	}
	if text, ok := token.(string); ok {
		if int64(len(text)) > *memory/4 || int64(len(text)) > r.budget.work/4 {
			return nil, ErrRPKIVRPBudget
		}
		*memory -= int64(len(text)) * 4
		r.budget.work -= int64(len(text)) * 4
	}
	return token, nil
}

// Each complete metadata/ROA value has bounded scratch allocation. Persistent
// index growth is charged separately; skipped metadata still fully validates.
func (r *rpkiJSONReader) value(memory *int64) (any, error) {
	token, err := r.token(memory)
	if err != nil {
		return nil, err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return token, nil
	}
	switch delimiter {
	case '{':
		out := map[string]any{}
		for r.decoder.More() {
			key, err := r.token(memory)
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, errRPKIJSON
			}
			if _, found := out[name]; found {
				return nil, errRPKIJSON
			}
			out[name], err = r.value(memory)
			if err != nil {
				return nil, err
			}
		}
		closing, err := r.token(memory)
		if err != nil || closing != json.Delim('}') {
			return nil, errors.Join(errRPKIJSON, err)
		}
		return out, nil
	case '[':
		out := []any{}
		for r.decoder.More() {
			value, err := r.value(memory)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
		}
		closing, err := r.token(memory)
		if err != nil || closing != json.Delim(']') {
			return nil, errors.Join(errRPKIJSON, err)
		}
		return out, nil
	default:
		return nil, errRPKIJSON
	}
}

func decodeRPKIExport(ctx context.Context, raw []byte, budget *rpkiJSONBudget) (RPKISnapshot, error) {
	none := RPKISnapshot{}
	if !utf8.Valid(raw) {
		return none, errRPKIJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	r := rpkiJSONReader{ctx: ctx, decoder: decoder, budget: budget}
	scratch := budget.memory
	start, err := r.token(&scratch)
	if err != nil {
		return none, err
	}
	out := RPKISnapshot{byPrefix: map[netip.Prefix][]RPKIVRP{}}
	switch start {
	case json.Delim('['):
		if err := r.roas(&out); err != nil {
			return none, err
		}
	case json.Delim('{'):
		found := false
		seen := map[string]bool{}
		for decoder.More() {
			scratch = budget.memory
			key, err := r.token(&scratch)
			if err != nil {
				return none, err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return none, errRPKIJSON
			}
			if int64(len(name)) > budget.memory/4 || budget.memory-int64(len(name))*4 < 256 {
				return none, ErrRPKIVRPBudget
			}
			budget.memory -= 256 + int64(len(name))*4
			seen[name] = true
			if name == "roas" {
				begin, err := r.token(&scratch)
				if err != nil || begin != json.Delim('[') {
					return none, errors.Join(errRPKIJSON, err)
				}
				if err := r.roas(&out); err != nil {
					return none, err
				}
				found = true
			} else {
				value, err := r.value(&scratch)
				if err != nil {
					return none, err
				}
				if name == "metadata" {
					out.ObservedAt, err = rpkiGeneration(value)
					if err != nil {
						return none, err
					}
				}
			}
		}
		closing, err := r.token(&scratch)
		if err != nil || closing != json.Delim('}') || !found {
			return none, errors.Join(errRPKIJSON, err)
		}
	default:
		return none, errRPKIJSON
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return none, errRPKIJSON
	}
	canonicalRPKIIndex(&out)
	out.complete = true
	return out, nil
}

func (r *rpkiJSONReader) roas(snapshot *RPKISnapshot) error {
	for r.decoder.More() {
		scratch := r.budget.memory
		value, err := r.value(&scratch)
		if err != nil {
			return err
		}
		vrp, err := decodeRPKIVRP(value)
		if err != nil {
			return err
		}
		if r.budget.memory < 512 {
			return ErrRPKIVRPBudget
		}
		r.budget.memory -= 512
		snapshot.byPrefix[vrp.Prefix] = append(snapshot.byPrefix[vrp.Prefix], vrp)
		snapshot.Records++
	}
	scratch := r.budget.memory
	closing, err := r.token(&scratch)
	if err != nil || closing != json.Delim(']') {
		return errors.Join(errRPKIJSON, err)
	}
	return nil
}

func decodeRPKIVRP(value any) (RPKIVRP, error) {
	none := RPKIVRP{}
	row, ok := value.(map[string]any)
	if !ok {
		return none, errRPKIJSON
	}
	text, ok := row["prefix"].(string)
	if !ok {
		return none, errRPKIJSON
	}
	prefix, err := netip.ParsePrefix(text)
	if err != nil || prefix.Addr().Zone() != "" {
		return none, errRPKIJSON
	}
	asn, err := rpkiUnsigned(row["asn"], true)
	if err != nil {
		return none, err
	}
	length := uint64(prefix.Bits())
	if maximum, exists := row["maxLength"]; exists {
		length, err = rpkiUnsigned(maximum, false)
	}
	if err != nil || length < uint64(prefix.Bits()) || length > uint64(prefix.Addr().BitLen()) {
		return none, errRPKIJSON
	}
	return RPKIVRP{Prefix: prefix.Masked(), MaxLength: int(length), ASN: uint32(asn)}, nil
}

func rpkiUnsigned(value any, asn bool) (uint64, error) {
	var text string
	switch v := value.(type) {
	case json.Number:
		text = string(v)
	case string:
		text = strings.TrimSpace(v)
	default:
		return 0, errRPKIJSON
	}
	if asn {
		text = strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(text), "AS"))
	}
	text = strings.TrimPrefix(text, "+")
	if text == "" {
		return 0, errRPKIJSON
	}
	n, err := strconv.ParseUint(text, 10, 32)
	if err != nil {
		return 0, errRPKIJSON
	}
	return n, nil
}

func rpkiGeneration(value any) (time.Time, error) {
	metadata, ok := value.(map[string]any)
	if !ok {
		return time.Time{}, errRPKIJSON
	}
	var observed time.Time
	if numeric, exists := metadata["generated"]; exists {
		number, ok := numeric.(json.Number)
		if !ok {
			return time.Time{}, errRPKIJSON
		}
		seconds, err := number.Int64()
		if err != nil || seconds < 0 || seconds > math.MaxInt64/1_000_000_000 {
			return time.Time{}, errRPKIJSON
		}
		observed = time.Unix(seconds, 0).UTC()
	}
	if encoded, exists := metadata["generatedTime"]; exists {
		text, ok := encoded.(string)
		if !ok {
			return time.Time{}, errRPKIJSON
		}
		at, err := time.Parse(time.RFC3339Nano, text)
		if err != nil || at.UnixNano() < 0 || !observed.IsZero() && observed.Unix() != at.Unix() {
			return time.Time{}, errRPKIJSON
		}
		observed = at.UTC()
	}
	return observed, nil
}
