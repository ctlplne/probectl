package change

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// GitLab webhook headers.
const (
	GitLabTokenHeader = "X-Gitlab-Token"
	gitlabEventHeader = "X-Gitlab-Event"
)

// gitlabProvider verifies GitLab's shared-token scheme (X-Gitlab-Token, compared
// in constant time — GitLab does not HMAC-sign by default) and normalizes push +
// deployment hooks.
type gitlabProvider struct{}

func (gitlabProvider) Name() string { return ProviderGitLab }

func (gitlabProvider) Verify(secret string, _ []byte, h http.Header) bool {
	tok := h.Get(GitLabTokenHeader)
	if secret == "" || tok == "" {
		return false
	}
	return crypto.ConstantTimeEqual([]byte(tok), []byte(secret))
}

func (gitlabProvider) Normalize(body []byte, h http.Header, now time.Time) ([]Event, error) {
	switch strings.ToLower(strings.TrimSpace(h.Get(gitlabEventHeader))) {
	case "push hook":
		return gitlabPush(body, now)
	case "deployment hook":
		return gitlabDeployment(body, now)
	default:
		return nil, nil
	}
}

type glPush struct {
	Ref      string `json:"ref"`
	UserName string `json:"user_name"`
	Project  struct {
		PathWithNamespace string `json:"path_with_namespace"`
		WebURL            string `json:"web_url"`
	} `json:"project"`
	CheckoutSHA string `json:"checkout_sha"`
	Commits     []struct {
		Message string `json:"message"`
		URL     string `json:"url"`
	} `json:"commits"`
}

func gitlabPush(body []byte, now time.Time) ([]Event, error) {
	var p glPush
	if err := json.Unmarshal(body, &p); err != nil || p.Project.PathWithNamespace == "" {
		return nil, ErrNormalize
	}
	branch := strings.TrimPrefix(p.Ref, "refs/heads/")
	c := Event{
		Source:     ProviderGitLab,
		Kind:       KindCommit,
		Title:      fmt.Sprintf("push to %s@%s (%d commit(s))", p.Project.PathWithNamespace, branch, len(p.Commits)),
		Target:     p.Project.PathWithNamespace,
		Actor:      p.UserName,
		Ref:        p.CheckoutSHA,
		URL:        p.Project.WebURL,
		Attributes: map[string]string{"branch": branch, "project": p.Project.PathWithNamespace},
		OccurredAt: now, // a GitLab push payload carries no single push timestamp
	}
	if n := len(p.Commits); n > 0 {
		c.Summary = firstLine(p.Commits[n-1].Message)
		c.URL = firstNonEmpty(c.URL, p.Commits[n-1].URL)
	}
	c.normalize(ProviderGitLab, now)
	return []Event{c}, nil
}

type glDeployment struct {
	Environment   string `json:"environment"`
	DeployableURL string `json:"deployable_url"`
	Status        string `json:"status"`
	ShortSHA      string `json:"short_sha"`
	User          struct {
		Name string `json:"name"`
	} `json:"user"`
	Project struct {
		PathWithNamespace string `json:"path_with_namespace"`
	} `json:"project"`
}

func gitlabDeployment(body []byte, now time.Time) ([]Event, error) {
	var p glDeployment
	if err := json.Unmarshal(body, &p); err != nil || p.Environment == "" {
		return nil, ErrNormalize
	}
	c := Event{
		Source:     ProviderGitLab,
		Kind:       KindDeploy,
		Title:      fmt.Sprintf("deploy %s to %s", p.Project.PathWithNamespace, p.Environment),
		Target:     hostFromURL(p.DeployableURL),
		Actor:      p.User.Name,
		Ref:        p.ShortSHA,
		URL:        p.DeployableURL,
		Attributes: map[string]string{"environment": p.Environment, "project": p.Project.PathWithNamespace, "status": p.Status},
		OccurredAt: now,
	}
	c.normalize(ProviderGitLab, now)
	return []Event{c}, nil
}
