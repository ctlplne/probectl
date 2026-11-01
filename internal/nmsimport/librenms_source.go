// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/secrets"
)

// ErrSourceUnavailable hides source origin, credential reference, response
// body and transport details from a caller or audit event.
var ErrSourceUnavailable = errors.New("nmsimport: source unavailable")

type sourceTokenResolver interface {
	ResolveBytesUncached(context.Context, string) ([]byte, func(), error)
}

// LibreNMSHTTPSource reads only the five documented inventory endpoints.
// An authorized caller must load origin and credentialRef from a tenant-owned
// source record under FORCE RLS before constructing it. The deployment CIDRs
// are administrator policy, never fields in an export or tenant request.
// Nothing calls this source by default, preserving the no-phone-home boundary.
type LibreNMSHTTPSource struct {
	origin        string
	credentialRef string
	client        *http.Client
	resolver      sourceTokenResolver
}

// allowedRefPrefix is a deployment-owned namespace ending in "/" and
// containing exactly one {tenant} token. An empty prefix disables live fetch.
// A tenant-owned row may select a reference only within its own namespace;
// it cannot resolve the control plane's environment or another tenant's key.
func NewLibreNMSHTTPSource(tenantID, origin string, approved []netip.Prefix, caFile,
	credentialRef, allowedRefPrefix string, resolver sourceTokenResolver,
	timeout time.Duration) (*LibreNMSHTTPSource, error) {
	if resolver == nil || !allowedSourceRef(tenantID, allowedRefPrefix, credentialRef) {
		return nil, ErrSourceUnavailable
	}
	client, err := crypto.PinnedHTTPSClient(origin, approved, caFile, timeout)
	if err != nil {
		return nil, ErrSourceUnavailable
	}
	return &LibreNMSHTTPSource{origin: strings.TrimSuffix(origin, "/"),
		credentialRef: credentialRef, client: client, resolver: resolver}, nil
}

func allowedSourceRef(tenantID, prefix, ref string) bool {
	tenant, err := uuid.Parse(tenantID)
	if err != nil || tenant == uuid.Nil || tenant.String() != tenantID ||
		strings.Count(prefix, "{tenant}") != 1 || !strings.HasSuffix(prefix, "/") ||
		len(ref) > 512 || !secrets.IsRef(ref) || !secrets.IsRef(prefix) ||
		strings.HasPrefix(ref, "env:") || strings.HasPrefix(prefix, "env:") {
		return false
	}
	approvedPrefix := strings.Replace(prefix, "{tenant}", tenantID, 1)
	if !strings.HasPrefix(ref, approvedPrefix) || len(ref) == len(approvedPrefix) {
		return false
	}
	parsed, err := secrets.Parse(ref)
	if err != nil || strings.ContainsAny(parsed.Path, "\\?%") ||
		strings.ContainsAny(parsed.Field, "/\\?%") {
		return false
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// Open returns a streaming response for a fixed resource. The caller closes
// it and feeds the bounded decoder. Non-200 responses are closed without
// reading or echoing their untrusted body.
func (s *LibreNMSHTTPSource) Open(ctx context.Context, resource string) (io.ReadCloser, error) {
	path := ""
	switch resource {
	case "devices":
		path = "/api/v0/devices"
	case "locations":
		path = "/api/v0/resources/locations"
	case "groups":
		path = "/api/v0/devicegroups"
	case "rules":
		path = "/api/v0/rules"
	default:
		return nil, ErrSourceUnavailable
	}
	return s.openPath(ctx, path)
}

// OpenMembership uses only a validated name from the already captured group
// list. Its caller binds that name to the source's canonical group ID before
// storing membership pairs; this function never trusts a response-supplied URL.
func (s *LibreNMSHTTPSource) OpenMembership(ctx context.Context, capturedGroupName string) (io.ReadCloser, error) {
	if capturedGroupName == "" || safeLabel(capturedGroupName) != capturedGroupName ||
		capturedGroupName == "." || capturedGroupName == ".." ||
		strings.ContainsAny(capturedGroupName, "/\\%") {
		return nil, ErrSourceUnavailable
	}
	return s.openPath(ctx, "/api/v0/devicegroups/"+url.PathEscape(capturedGroupName))
}

func (s *LibreNMSHTTPSource) openPath(ctx context.Context, path string) (io.ReadCloser, error) {
	if s == nil || s.client == nil || s.resolver == nil {
		return nil, ErrSourceUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.origin+path, nil)
	if err != nil || request.URL.Scheme != "https" || request.URL.RawQuery != "" ||
		request.URL.Fragment != "" || request.URL.EscapedPath() != path {
		return nil, ErrSourceUnavailable
	}
	token, release, err := s.resolver.ResolveBytesUncached(ctx, s.credentialRef)
	if err != nil || release == nil || len(token) == 0 || len(token) > 8192 || !safeBearerToken(token) {
		if release != nil {
			release()
		}
		return nil, ErrSourceUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+string(token))
	request.Header.Set("Accept", "application/json")
	response, err := s.client.Do(request)
	request.Header.Del("Authorization")
	release()
	if err != nil {
		return nil, ErrSourceUnavailable
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, ErrSourceUnavailable
	}
	return response.Body, nil
}

func safeBearerToken(token []byte) bool {
	for _, b := range token {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}
