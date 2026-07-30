// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

const (
	// IRKeyDomain is distinct from routine envelope, tenant-BYOK, and WORM
	// signing domains. The steady-state writer receives only an operator-owned
	// public wrapping key.
	IRKeyDomain = "probectl-ir-attribution-v1"

	maxIRIdentityBytes   = 320
	maxIRGrantBytes      = 256
	maxIRSurfaceBytes    = 256
	maxIRConsentBytes    = 512
	maxIROutcomeBytes    = 128
	maxIRReasonBytes     = 1024
	maxIRPublicKeyBytes  = 16 << 10
	maxIRWrappedDEKBytes = 4096
	maxIRCiphertextBytes = 32 << 10
)

var canonicalIRTenantID = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
)

// IRAttribution is the complete plaintext retained for an authorized incident
// investigation. It exists in memory only until Envelope.Seal returns.
//
// Operator is the stable provider-operator ID. Consent records the tenant-side
// decision identity/state separately, so a tenant consenter is never
// misrepresented as the provider operator.
type IRAttribution struct {
	Operator string    `json:"operator"`
	TenantID string    `json:"tenant_id"`
	Grant    string    `json:"grant"`
	Surface  string    `json:"surface"`
	Consent  string    `json:"consent"`
	Outcome  string    `json:"outcome"`
	Reason   string    `json:"reason"`
	EventRef string    `json:"event_ref"`
	TS       time.Time `json:"ts"`
}

// IRStageAppender is the narrow same-transaction sidecar seam. Implementations
// must not commit: the provider mutation owns the surrounding transaction.
type IRStageAppender interface {
	AppendIRStageTx(context.Context, tenancy.Querier, Event, IRAttribution) error
}

// IRWrapKeyResolver returns the operator-owned public wrapping capability for
// one tenant. Routine code never receives an opener.
type IRWrapKeyResolver interface {
	WrapProviderForTenant(context.Context, string) (crypto.KeyProvider, error)
}

// LocalIRPublicKeyResolver is an air-gap-safe local keyring. Each tenant key is
// read from <directory>/<canonical-tenant-uuid>.pem. It performs no network
// operations and never loads a private key.
type LocalIRPublicKeyResolver struct {
	directory string
}

// NewLocalIRPublicKeyResolver validates the local operator-owned key directory.
func NewLocalIRPublicKeyResolver(directory string) (*LocalIRPublicKeyResolver, error) {
	directory = filepath.Clean(strings.TrimSpace(directory))
	if directory == "." || !filepath.IsAbs(directory) {
		return nil, errors.New("audit: IR public-key directory must be an absolute path")
	}
	info, err := os.Stat(directory)
	if err != nil {
		return nil, fmt.Errorf("audit: inspect IR public-key directory: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("audit: IR public-key path is not a directory")
	}
	return &LocalIRPublicKeyResolver{directory: directory}, nil
}

// WrapProviderForTenant loads only the tenant's public RSA wrapping key.
func (r *LocalIRPublicKeyResolver) WrapProviderForTenant(
	_ context.Context,
	tenantID string,
) (crypto.KeyProvider, error) {
	if r == nil || r.directory == "" {
		return nil, errors.New("audit: IR public-key resolver is unavailable")
	}
	if !canonicalIRTenantID.MatchString(tenantID) {
		return nil, errors.New("audit: IR tenant id is not a canonical UUID")
	}
	path := filepath.Join(r.directory, tenantID+".pem")
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("audit: open tenant IR public key: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxIRPublicKeyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("audit: read tenant IR public key: %w", err)
	}
	if len(raw) > maxIRPublicKeyBytes {
		return nil, fmt.Errorf("audit: tenant IR public key exceeds %d bytes", maxIRPublicKeyBytes)
	}
	provider, err := crypto.NewRSAOAEPWrapProviderPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("audit: tenant IR public key: %w", err)
	}
	return provider, nil
}

func isProtectedBreakGlassAction(action string) bool {
	return strings.HasPrefix(action, "provider.breakglass_")
}

func validateIRAttribution(actor, action, target string, data map[string]any, a IRAttribution) error {
	if !isProtectedBreakGlassAction(action) {
		return fmt.Errorf("audit: action %q is not an attributed break-glass event", action)
	}
	if !canonicalIRTenantID.MatchString(a.TenantID) {
		return errors.New("audit: IR attribution tenant is not a canonical UUID")
	}
	if strings.TrimSpace(a.Operator) == "" ||
		strings.TrimSpace(a.Grant) == "" ||
		strings.TrimSpace(a.Surface) == "" ||
		strings.TrimSpace(a.Consent) == "" ||
		strings.TrimSpace(a.Outcome) == "" ||
		strings.TrimSpace(a.Reason) == "" {
		return errors.New("audit: IR attribution is incomplete")
	}
	if a.Grant != target {
		return errors.New("audit: IR attribution grant differs from provider event target")
	}
	tenant, ok := data["tenant"].(string)
	if !ok || tenant != a.TenantID {
		return errors.New("audit: IR attribution tenant differs from provider event")
	}
	reason, ok := data["reason"].(string)
	if !ok || reason != a.Reason {
		return errors.New("audit: IR attribution reason differs from provider event")
	}
	if a.EventRef != "" || !a.TS.IsZero() {
		return errors.New("audit: IR event reference and timestamp are assigned by the audit append")
	}
	if len(a.Operator) > maxIRIdentityBytes ||
		len(a.Grant) > maxIRGrantBytes ||
		len(a.Surface) > maxIRSurfaceBytes ||
		len(a.Consent) > maxIRConsentBytes ||
		len(a.Outcome) > maxIROutcomeBytes ||
		len(a.Reason) > maxIRReasonBytes {
		return errors.New("audit: IR attribution exceeds a bounded field limit")
	}
	switch action {
	case "provider.breakglass_request":
		if a.Surface != "provider.breakglass.request" ||
			a.Consent != "pending" ||
			a.Outcome != "requested" {
			return errors.New("audit: IR request attribution differs from provider event")
		}
	case "provider.breakglass_consent":
		if a.Surface != "provider.breakglass.consent" ||
			a.Consent != "tenant-approved:"+actor ||
			a.Outcome != "approved" {
			return errors.New("audit: IR consent attribution differs from provider event")
		}
	case "provider.breakglass_deny":
		if a.Surface != "provider.breakglass.consent" ||
			a.Consent != "tenant-denied:"+actor ||
			a.Outcome != "denied" {
			return errors.New("audit: IR denial attribution differs from provider event")
		}
	case "provider.breakglass_revoke":
		if a.Surface != "provider.breakglass.revoke" ||
			a.Consent != "revoked-by:"+actor ||
			a.Outcome != "revoked" {
			return errors.New("audit: IR revocation attribution differs from provider event")
		}
	case "provider.breakglass_access":
		surface, ok := data["surface"].(string)
		if !ok ||
			a.Surface != surface ||
			!strings.HasPrefix(a.Consent, "tenant-approved:") ||
			a.Outcome != "accessed" {
			return errors.New("audit: IR access attribution differs from provider event")
		}
	default:
		return fmt.Errorf("audit: protected action %q has no IR attribution schema", action)
	}
	return nil
}

func marshalIRAttribution(a IRAttribution) ([]byte, error) {
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("audit: marshal IR attribution: %w", err)
	}
	if len(raw) > maxIRCiphertextBytes/2 {
		return nil, errors.New("audit: IR attribution plaintext exceeds bounded size")
	}
	return raw, nil
}

type irStageAADPayload struct {
	Domain   string `json:"domain"`
	TenantID string `json:"tenant_id"`
	AuditSeq int64  `json:"audit_seq"`
	EventRef string `json:"event_ref"`
}

func irStageAAD(tenantID string, auditSeq int64, eventRef string) []byte {
	raw, _ := json.Marshal(irStageAADPayload{
		Domain: IRKeyDomain, TenantID: tenantID, AuditSeq: auditSeq, EventRef: eventRef,
	})
	return raw
}
