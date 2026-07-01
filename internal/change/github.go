// SPDX-License-Identifier: LicenseRef-probectl-TBD

package change

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GitHub webhook headers.
const (
	GitHubSignatureHeader = "X-Hub-Signature-256"
	GitHubDeliveryHeader  = "X-GitHub-Delivery"
	githubEventHeader     = "X-GitHub-Event"
)

// githubProvider verifies GitHub's HMAC-SHA256 signature (X-Hub-Signature-256)
// and normalizes push + deployment deliveries.
type githubProvider struct{}

func (githubProvider) Name() string { return ProviderGitHub }

func (githubProvider) Verify(secret string, body []byte, h http.Header, _ time.Time) bool {
	return verifyHMAC(secret, body, h.Get(GitHubSignatureHeader))
}

func (githubProvider) DeliveryID(h http.Header) (string, bool) {
	return deliveryHeader(h, GitHubDeliveryHeader)
}

func (githubProvider) Normalize(body []byte, h http.Header, now time.Time) ([]Event, error) {
	switch strings.ToLower(h.Get(githubEventHeader)) {
	case "push":
		return githubPush(body, now)
	case "deployment", "deployment_status":
		return githubDeployment(body, now)
	default:
		// "ping" (a verified handshake) and event types we don't model yield no
		// change — a verified delivery is never an error just because it's unmodeled.
		return nil, nil
	}
}

type ghPush struct {
	Ref     string `json:"ref"`
	Compare string `json:"compare"`
	Pusher  struct {
		Name string `json:"name"`
	} `json:"pusher"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	HeadCommit struct {
		ID        string    `json:"id"`
		Message   string    `json:"message"`
		URL       string    `json:"url"`
		Timestamp time.Time `json:"timestamp"`
	} `json:"head_commit"`
	Commits []struct {
		ID string `json:"id"`
	} `json:"commits"`
}

func githubPush(body []byte, now time.Time) ([]Event, error) {
	var p ghPush
	if err := json.Unmarshal(body, &p); err != nil || p.Repository.FullName == "" {
		return nil, ErrNormalize
	}
	branch := strings.TrimPrefix(p.Ref, "refs/heads/")
	c := Event{
		Source:     ProviderGitHub,
		Kind:       KindCommit,
		Title:      fmt.Sprintf("push to %s@%s (%d commit(s))", p.Repository.FullName, branch, len(p.Commits)),
		Summary:    firstLine(p.HeadCommit.Message),
		Target:     p.Repository.FullName,
		Actor:      p.Pusher.Name,
		Ref:        p.HeadCommit.ID,
		URL:        firstNonEmpty(p.HeadCommit.URL, p.Compare),
		Attributes: map[string]string{"branch": branch, "repo": p.Repository.FullName},
		OccurredAt: p.HeadCommit.Timestamp,
	}
	c.normalize(ProviderGitHub, now)
	return []Event{c}, nil
}

type ghDeployment struct {
	Deployment struct {
		Environment    string    `json:"environment"`
		Ref            string    `json:"ref"`
		SHA            string    `json:"sha"`
		EnvironmentURL string    `json:"environment_url"`
		CreatedAt      time.Time `json:"created_at"`
		Creator        struct {
			Login string `json:"login"`
		} `json:"creator"`
	} `json:"deployment"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
}

func githubDeployment(body []byte, now time.Time) ([]Event, error) {
	var p ghDeployment
	if err := json.Unmarshal(body, &p); err != nil || p.Deployment.Environment == "" {
		return nil, ErrNormalize
	}
	c := Event{
		Source:     ProviderGitHub,
		Kind:       KindDeploy,
		Title:      fmt.Sprintf("deploy %s to %s", p.Repository.FullName, p.Deployment.Environment),
		Target:     hostFromURL(p.Deployment.EnvironmentURL),
		Actor:      p.Deployment.Creator.Login,
		Ref:        firstNonEmpty(p.Deployment.SHA, p.Deployment.Ref),
		URL:        p.Deployment.EnvironmentURL,
		Attributes: map[string]string{"environment": p.Deployment.Environment, "repo": p.Repository.FullName},
		OccurredAt: p.Deployment.CreatedAt,
	}
	c.normalize(ProviderGitHub, now)
	return []Event{c}, nil
}

// --- shared normalization helpers ---

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// hostFromURL extracts the host of a URL (a correlatable target for a deploy), or
// "" if the URL is empty/unparseable. The input is untrusted.
func hostFromURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
