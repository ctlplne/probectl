// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"net/http"
	"strings"

	"github.com/ctlplne/probectl/internal/auth"
)

// WithHTTPOrigins installs explicit trusted browser origins at construction.
// No configured origins means every present Origin is refused; native clients
// without Origin remain subject to the existing TLS/token/tenant guards.
// Invalid programmatic configuration refuses all HTTP requests before auth.
func WithHTTPOrigins(origins []string) Option {
	return func(s *Server) {
		s.httpOrigins = make(map[string]struct{}, len(origins))
		s.httpOriginsInvalid = false
		for _, value := range origins {
			origin, err := auth.CanonicalHTTPOrigin(value)
			if err != nil {
				s.httpOriginsInvalid = true
				continue
			}
			s.httpOrigins[origin] = struct{}{}
		}
	}
}

func (s *Server) allowsHTTPOrigin(r *http.Request) bool {
	var values []string
	present := false
	for key, entries := range r.Header {
		if strings.EqualFold(key, "Origin") {
			present = true
			values = append(values, entries...)
		}
	}
	if !present {
		return true
	}
	if len(values) != 1 {
		return false
	}
	origin, err := auth.CanonicalHTTPOrigin(values[0])
	if err != nil {
		return false
	}
	_, allowed := s.httpOrigins[origin]
	return allowed
}
