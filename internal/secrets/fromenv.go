// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package secrets

import (
	"fmt"
	"os"
	"time"
)

// FromEnv builds a Resolver with every backend the environment configures
// (env is always available). lease <= 0 takes DefaultLease. Misconfigured
// backends are an ERROR (fail closed), not a silent skip.
func FromEnv(lease time.Duration) (*Resolver, error) {
	getenv := os.Getenv
	backends := []Source{NewEnvSource(getenv)}
	v, err := NewVaultSource(getenv)
	if err != nil {
		return nil, err
	}
	if v != nil {
		backends = append(backends, v)
	}
	ca, err := NewCyberArkSource(getenv)
	if err != nil {
		return nil, err
	}
	if ca != nil {
		backends = append(backends, ca)
	}
	if a := NewAWSSource(getenv); a != nil {
		backends = append(backends, a)
	}
	if az := NewAzureSource(getenv); az != nil {
		backends = append(backends, az)
	}
	g, err := NewGCPSource(getenv, os.ReadFile)
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	if g != nil {
		backends = append(backends, g)
	}
	return NewResolver(lease, backends...)
}
