// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package completeness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	denominatorPolicySchema  = "probectl.completeness-denominator/v1"
	noneByDesignPolicySchema = "probectl.completeness-none-by-design/v1"
)

type denominatorPolicy struct {
	Schema       string `json:"schema"`
	FeatureRange struct {
		Prefix string `json:"prefix"`
		First  int    `json:"first"`
		Last   int    `json:"last"`
	} `json:"feature_range"`
	GovernedClaims []string `json:"governed_claims"`
}

type noneByDesignPolicy struct {
	Schema string   `json:"schema"`
	Cells  []string `json:"cells"`
}

func (v *Validator) loadCompletenessPolicies() error {
	denominatorPath, err := v.resolveWithinRoot(DenominatorPolicyPath)
	if err != nil {
		return fmt.Errorf("read completeness denominator policy: %w", err)
	}
	denominatorData, err := os.ReadFile(denominatorPath)
	if err != nil {
		return fmt.Errorf("read completeness denominator policy: %w", err)
	}
	var denominator denominatorPolicy
	if err := decodeStrictJSON(denominatorData, &denominator); err != nil {
		return fmt.Errorf("decode completeness denominator policy: %w", err)
	}
	if denominator.Schema != denominatorPolicySchema {
		return fmt.Errorf("decode completeness denominator policy: schema must be %q", denominatorPolicySchema)
	}
	if denominator.FeatureRange.Prefix == "" || denominator.FeatureRange.First < 1 || denominator.FeatureRange.Last < denominator.FeatureRange.First {
		return fmt.Errorf("decode completeness denominator policy: feature_range must have a prefix and a positive inclusive range")
	}
	expected := map[string]bool{}
	for number := denominator.FeatureRange.First; number <= denominator.FeatureRange.Last; number++ {
		expected[fmt.Sprintf("%s%d", denominator.FeatureRange.Prefix, number)] = true
	}
	for index, rawID := range denominator.GovernedClaims {
		id := strings.TrimSpace(rawID)
		if id == "" || id != rawID {
			return fmt.Errorf("decode completeness denominator policy: governed claim %d must be a non-empty canonical ID", index)
		}
		if expected[id] {
			return fmt.Errorf("decode completeness denominator policy: duplicate capability ID %q", id)
		}
		expected[id] = true
	}
	if len(expected) == 0 {
		return fmt.Errorf("decode completeness denominator policy: no capabilities are declared")
	}

	noneByDesignPath, err := v.resolveWithinRoot(NoneByDesignPolicyPath)
	if err != nil {
		return fmt.Errorf("read none-by-design policy: %w", err)
	}
	noneByDesignData, err := os.ReadFile(noneByDesignPath)
	if err != nil {
		return fmt.Errorf("read none-by-design policy: %w", err)
	}
	var exclusions noneByDesignPolicy
	if err := decodeStrictJSON(noneByDesignData, &exclusions); err != nil {
		return fmt.Errorf("decode none-by-design policy: %w", err)
	}
	if exclusions.Schema != noneByDesignPolicySchema {
		return fmt.Errorf("decode none-by-design policy: schema must be %q", noneByDesignPolicySchema)
	}
	allowedCells := map[string]bool{}
	for _, cell := range CellNames {
		allowedCells[cell] = true
	}
	allowed := map[string]bool{}
	for index, rawKey := range exclusions.Cells {
		key := strings.TrimSpace(rawKey)
		capability, cell, ok := strings.Cut(key, ".")
		if !ok || capability == "" || cell == "" || strings.Contains(cell, ".") || key != rawKey {
			return fmt.Errorf("decode none-by-design policy: cell %d must be an exact <capability>.<cell> key", index)
		}
		if !expected[capability] {
			return fmt.Errorf("decode none-by-design policy: cell %q names a capability outside the denominator", key)
		}
		if !allowedCells[cell] {
			return fmt.Errorf("decode none-by-design policy: cell %q names an unknown wiring-spine cell", key)
		}
		if allowed[key] {
			return fmt.Errorf("decode none-by-design policy: duplicate cell %q", key)
		}
		allowed[key] = true
	}
	v.expectedCapabilities = expected
	v.noneByDesign = allowed
	return nil
}

func decodeStrictJSON(data []byte, destination any) error {
	if err := rejectDuplicateJSONObjectKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return fmt.Errorf("trailing content: %w", err)
	}
	return nil
}

func rejectDuplicateJSONObjectKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	first, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := walkUniqueJSONValue(decoder, first); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return fmt.Errorf("trailing content: %w", err)
	}
	return nil
}

func walkUniqueJSONValue(decoder *json.Decoder, first json.Token) error {
	delimiter, ok := first.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		return walkUniqueJSONObject(decoder)
	case '[':
		return walkUniqueJSONArray(decoder)
	default:
		return fmt.Errorf("unexpected closing JSON delimiter %q", delimiter)
	}
}

func walkUniqueJSONObject(decoder *json.Decoder) error {
	keys := map[string]bool{}
	for decoder.More() {
		rawKey, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := rawKey.(string)
		if !ok {
			return fmt.Errorf("JSON object key is not a string")
		}
		if keys[key] {
			return fmt.Errorf("duplicate JSON object key %q", key)
		}
		keys[key] = true
		value, err := decoder.Token()
		if err != nil {
			return err
		}
		if err := walkUniqueJSONValue(decoder, value); err != nil {
			return err
		}
	}
	return consumeJSONDelimiter(decoder, '}')
}

func walkUniqueJSONArray(decoder *json.Decoder) error {
	for decoder.More() {
		value, err := decoder.Token()
		if err != nil {
			return err
		}
		if err := walkUniqueJSONValue(decoder, value); err != nil {
			return err
		}
	}
	return consumeJSONDelimiter(decoder, ']')
}

func consumeJSONDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != expected {
		return fmt.Errorf("unexpected JSON delimiter %q; want %q", token, expected)
	}
	return nil
}
