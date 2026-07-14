// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package configschema

import (
	"bytes"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// DecodeStrictYAML decodes one YAML document and rejects unknown struct fields.
// Config files are long-lived conffiles: a typo must fail startup, not silently
// turn a safety knob off.
func DecodeStrictYAML(raw []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple YAML documents are not supported")
		}
		return err
	}
	return nil
}

// ResolveAPIVersion validates the top-level config version marker. apiVersion
// is the forward format; schema_version: 1 is accepted as the compatibility
// alias for early config files.
func ResolveAPIVersion(component, apiVersion string, schemaVersion int, want string) (string, error) {
	if schemaVersion != 0 && schemaVersion != 1 {
		return "", fmt.Errorf("%s config: unsupported schema_version %d (want 1)", component, schemaVersion)
	}
	if apiVersion == "" {
		if schemaVersion == 1 {
			return want, nil
		}
		return "", fmt.Errorf("%s config: apiVersion is required (want %q; schema_version: 1 is accepted as a compatibility alias)", component, want)
	}
	if apiVersion != want {
		return "", fmt.Errorf("%s config: unsupported apiVersion %q (want %q)", component, apiVersion, want)
	}
	return apiVersion, nil
}
