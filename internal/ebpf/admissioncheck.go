// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// RTO-12: Kyverno DELETES its own resource webhooks when its admission
// controller is scaled to zero. From then on nothing in the cluster is
// verified, while the image-integrity ImageValidatingPolicy still reads Ready.
// The chart's install-time gate refuses to roll out in that state; this check
// is the continuous half — the chart runs it as a CronJob in the agent image
// and it fails (Job Failed + an ERROR log line) whenever the policy or the
// webhook that serves it is missing. Observe-only: it only issues GETs and
// never repairs anything (docs/guardrails.md G7-8).

// Defaults for the in-cluster API server credentials and Kyverno's webhook
// configuration name.
const (
	DefaultKyvernoWebhookConfiguration = "kyverno-resource-validating-webhook-cfg"
	DefaultServiceAccountTokenFile     = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101 -- a path, not a credential
	DefaultServiceAccountCAFile        = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	policySHA256Annotation             = "probectl.dev/policy-sha256"
	maxAdmissionCheckBody              = 4 << 20
	admissionCheckTimeout              = 10 * time.Second
)

// AdmissionCheck describes one observe-only Kyverno admission check.
type AdmissionCheck struct {
	// APIServer is the API server base URL (https://host:port).
	APIServer string
	// TokenFile holds the service-account bearer token; read on every Run.
	TokenFile string
	// Policy is the ImageValidatingPolicy name.
	Policy string
	// PolicySHA256, when set, must equal the live policy's
	// probectl.dev/policy-sha256 annotation (the release's rendered spec).
	PolicySHA256 string
	// WebhookConfiguration is Kyverno's ValidatingWebhookConfiguration name.
	WebhookConfiguration string
	// Client talks to the API server (crypto.HardenedHTTPClientWithCAFile).
	Client *http.Client
}

// InClusterAPIServer returns the API server URL from the standard in-cluster
// environment (KUBERNETES_SERVICE_HOST / KUBERNETES_SERVICE_PORT).
func InClusterAPIServer(getenv func(string) string) (string, error) {
	host, port := getenv("KUBERNETES_SERVICE_HOST"), getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return "", errors.New("KUBERNETES_SERVICE_HOST/KUBERNETES_SERVICE_PORT are not set: not running in a cluster (pass --api-server)")
	}
	return "https://" + net.JoinHostPort(host, port), nil
}

// NewAdmissionCheckClient builds the API server client on the hardened TLS
// policy, trusting only caFile.
func NewAdmissionCheckClient(caFile string) (*http.Client, error) {
	return crypto.HardenedHTTPClientWithCAFile(admissionCheckTimeout, caFile)
}

// Run performs the check. It returns the problems found (empty = admission is
// verifying the agent image) or an error when the state could not be read —
// which the caller must treat as a failure too (fail closed).
func (c AdmissionCheck) Run(ctx context.Context) ([]string, error) {
	if c.Policy == "" || c.APIServer == "" || c.Client == nil {
		return nil, errors.New("admission check: policy, API server and client are required")
	}
	if !strings.HasPrefix(c.APIServer, "https://") {
		return nil, fmt.Errorf("admission check: API server %q is not https", c.APIServer)
	}
	cfgName := c.WebhookConfiguration
	if cfgName == "" {
		cfgName = DefaultKyvernoWebhookConfiguration
	}
	token, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("admission check: read service-account token: %w", err)
	}
	bearer := strings.TrimSpace(string(token))
	var problems []string
	var policy ivpolObject
	found, err := c.get(ctx, bearer, "/apis/policies.kyverno.io/v1/imagevalidatingpolicies/"+url.PathEscape(c.Policy), &policy)
	if err != nil {
		return nil, err
	}
	if !found {
		problems = append(problems, fmt.Sprintf("ImageValidatingPolicy %s is not in the cluster", c.Policy))
	} else {
		problems = append(problems, policy.problems(c.Policy, c.PolicySHA256)...)
	}
	var cfg webhookConfigObject
	found, err = c.get(ctx, bearer, "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/"+url.PathEscape(cfgName), &cfg)
	if err != nil {
		return nil, err
	}
	if !found {
		problems = append(problems, fmt.Sprintf("Kyverno's ValidatingWebhookConfiguration %s is missing (Kyverno removes it when its admission controller is scaled to zero)", cfgName))
	} else if !cfg.servesPolicyFailClosed(c.Policy) {
		problems = append(problems, fmt.Sprintf("Kyverno's ValidatingWebhookConfiguration %s has no failurePolicy=Fail webhook serving ImageValidatingPolicy %s", cfgName, c.Policy))
	}
	return problems, nil
}

// get fetches one object. found=false on 404; any other non-200 is an error.
func (c AdmissionCheck) get(ctx context.Context, bearer, path string, into any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.APIServer, "/")+path, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return false, fmt.Errorf("admission check: GET %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAdmissionCheckBody))
	if err != nil {
		return false, fmt.Errorf("admission check: GET %s: %w", path, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		if err := json.Unmarshal(body, into); err != nil {
			return false, fmt.Errorf("admission check: GET %s: decode: %w", path, err)
		}
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("admission check: GET %s: HTTP %d", path, resp.StatusCode)
	}
}

type ivpolObject struct {
	Metadata struct {
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Status struct {
		ConditionStatus struct {
			Ready      *bool `json:"ready"`
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
		} `json:"conditionStatus"`
	} `json:"status"`
}

func (p ivpolObject) problems(name, wantSHA string) []string {
	var out []string
	if got := p.Metadata.Annotations[policySHA256Annotation]; wantSHA != "" && got != wantSHA {
		out = append(out, fmt.Sprintf("ImageValidatingPolicy %s is not the policy this release renders (%s %q, want %q)", name, policySHA256Annotation, got, wantSHA))
	}
	cs := p.Status.ConditionStatus
	webhookConfigured := false
	for _, c := range cs.Conditions {
		if c.Type == "WebhookConfigured" && c.Status == "True" {
			webhookConfigured = true
		}
	}
	if cs.Ready == nil || !*cs.Ready || !webhookConfigured {
		out = append(out, fmt.Sprintf("ImageValidatingPolicy %s is not Ready in Kyverno (conditionStatus.ready and WebhookConfigured)", name))
	}
	return out
}

type webhookConfigObject struct {
	Webhooks []struct {
		Name          string `json:"name"`
		FailurePolicy string `json:"failurePolicy"`
		ClientConfig  struct {
			URL     string `json:"url"`
			Service *struct {
				Path string `json:"path"`
			} `json:"service"`
		} `json:"clientConfig"`
	} `json:"webhooks"`
}

// servesPolicyFailClosed mirrors the chart's lookup gate: an entry with
// failurePolicy=Fail whose path is /ivpol/validate/<policy names joined by />
// and names this policy.
func (w webhookConfigObject) servesPolicyFailClosed(policy string) bool {
	for _, h := range w.Webhooks {
		path := h.ClientConfig.URL
		if h.ClientConfig.Service != nil && h.ClientConfig.Service.Path != "" {
			path = h.ClientConfig.Service.Path
		}
		if h.FailurePolicy == "Fail" && webhookPathServesPolicy(path, policy) {
			return true
		}
	}
	return false
}

func webhookPathServesPolicy(path, policy string) bool {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if !strings.Contains(path, "/ivpol/validate/") {
		return false
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == policy {
			return true
		}
	}
	return false
}
