// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"errors"
	"net/http"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
)

// The per-tenant key / BYOK surface (S-T6, ee-backed): the tenant's security
// settings show its key chain and rotate it (managed re-key or BYOK via an
// S41 secret reference). Hidden (404) when the byok feature is not licensed
// — the keyring simply is not installed. Key MATERIAL never crosses this
// API.

// WithKeyManager attaches the per-tenant keyring's management surface (the
// ee attach seam). nil = the routes answer not_found (hidden-unlicensed).
func (s *Server) WithKeyManager(m tenantcrypto.KeyManager) *Server {
	if m != nil {
		s.keyManager = m
	}
	return s
}

func (s *Server) keysManager() (tenantcrypto.KeyManager, error) {
	if s.keyManager == nil {
		return nil, apierror.NotFound("not found") // hidden-unlicensed
	}
	return s.keyManager, nil
}

func (s *Server) handleKeysStatus(w http.ResponseWriter, r *http.Request) error {
	m, err := s.keysManager()
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	chain, err := m.KeyStatus(r.Context(), tid)
	if err != nil {
		return apierror.Internal("key status failed").Wrap(err)
	}
	if chain == nil {
		chain = []tenantcrypto.KeyInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": chain})
	return nil
}

func (s *Server) handleKeysRotate(w http.ResponseWriter, r *http.Request) error {
	m, err := s.keysManager()
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	var in struct {
		Mode    string `json:"mode"`
		BYOKRef string `json:"byok_ref"`
	}
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if in.Mode == "" {
		in.Mode = "managed"
	}
	if in.Mode != "managed" && in.Mode != "byok" {
		return apierror.Validation("mode must be managed or byok")
	}
	if in.Mode == "byok" && in.BYOKRef == "" {
		return apierror.Validation("byok requires byok_ref (an S41 secret reference, e.g. vault:kv/path#key)")
	}
	kv, err := m.RotateKey(r.Context(), tid, auditActor(r), in.Mode, in.BYOKRef)
	if err != nil {
		if errors.Is(err, license.ErrReadOnly) {
			return apierror.Forbidden(err.Error()).WithCode(string(apierror.CodeLicenseReadOnly))
		}
		if errors.Is(err, tenantcrypto.ErrKeyRotationUnavailable) {
			return apierror.Internal("key rotation failed").Wrap(err)
		}
		// Rotation failures are actionable client problems more often than
		// server faults (dead BYOK refs are rejected by the lockout guard).
		return apierror.Validation(err.Error())
	}
	writeJSON(w, http.StatusOK, kv)
	return nil
}
