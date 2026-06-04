package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// Getenv is the environment seam (tests inject a fake).
type Getenv func(string) string

// httpDo performs one backend request with a bounded body read; non-2xx maps
// to a redacted error (bodies from secret stores are never echoed).
func httpDo(client *http.Client, req *http.Request) ([]byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, redactURLErr(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read: %v", ErrUnavailable, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return body, nil
}

// redactURLErr strips query strings from transport errors (tokens can ride
// query params in some backends' redirects).
func redactURLErr(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '?'); i >= 0 {
		return s[:i] + "?…"
	}
	return s
}

// --- env ---

// EnvSource resolves env:NAME from the process environment.
type EnvSource struct{ getenv Getenv }

// NewEnvSource builds the env backend (getenv nil -> os.Getenv via FromEnv).
func NewEnvSource(getenv Getenv) *EnvSource { return &EnvSource{getenv: getenv} }

// Scheme implements Source.
func (*EnvSource) Scheme() string { return "env" }

// Fetch implements Source.
func (s *EnvSource) Fetch(_ context.Context, ref Ref) (string, error) {
	v := s.getenv(ref.Path)
	if v == "" {
		return "", fmt.Errorf("environment variable %s is not set", ref.Path)
	}
	return v, nil
}

// --- HashiCorp Vault (KV v2) ---

// VaultSource resolves vault:<mount>/<path>#<field> via the KV v2 read API.
// Auth: a static token (PROBECTL_SECRETS_VAULT_TOKEN) or AppRole login
// (PROBECTL_SECRETS_VAULT_ROLE_ID + _SECRET_ID); optional namespace header.
type VaultSource struct {
	addr      string
	token     string
	roleID    string
	secretID  string
	namespace string
	client    *http.Client

	leaseTok string    // AppRole-issued token (memory only)
	leaseExp time.Time // conservative re-login deadline
}

// NewVaultSource builds the Vault backend from the environment; returns nil
// when PROBECTL_SECRETS_VAULT_ADDR is unset.
func NewVaultSource(getenv Getenv) *VaultSource {
	addr := getenv("PROBECTL_SECRETS_VAULT_ADDR")
	if addr == "" {
		return nil
	}
	return &VaultSource{
		addr:      strings.TrimRight(addr, "/"),
		token:     getenv("PROBECTL_SECRETS_VAULT_TOKEN"),
		roleID:    getenv("PROBECTL_SECRETS_VAULT_ROLE_ID"),
		secretID:  getenv("PROBECTL_SECRETS_VAULT_SECRET_ID"),
		namespace: getenv("PROBECTL_SECRETS_VAULT_NAMESPACE"),
		client:    crypto.HardenedHTTPClient(15 * time.Second),
	}
}

// Scheme implements Source.
func (*VaultSource) Scheme() string { return "vault" }

func (s *VaultSource) authToken(ctx context.Context) (string, error) {
	if s.token != "" {
		return s.token, nil
	}
	if s.leaseTok != "" && time.Now().Before(s.leaseExp) {
		return s.leaseTok, nil
	}
	if s.roleID == "" || s.secretID == "" {
		return "", fmt.Errorf("vault auth not configured (set PROBECTL_SECRETS_VAULT_TOKEN or _ROLE_ID + _SECRET_ID)")
	}
	body, _ := json.Marshal(map[string]string{"role_id": s.roleID, "secret_id": s.secretID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.addr+"/v1/auth/approle/login", strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	s.header(req)
	raw, err := httpDo(s.client, req)
	if err != nil {
		return "", fmt.Errorf("approle login: %w", err)
	}
	var resp struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil || resp.Auth.ClientToken == "" {
		return "", fmt.Errorf("approle login: unexpected response shape")
	}
	s.leaseTok = resp.Auth.ClientToken
	ttl := time.Duration(resp.Auth.LeaseDuration) * time.Second
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	s.leaseExp = time.Now().Add(ttl * 2 / 3) // renew early
	return s.leaseTok, nil
}

func (s *VaultSource) header(req *http.Request) {
	if s.namespace != "" {
		req.Header.Set("X-Vault-Namespace", s.namespace)
	}
}

// Fetch implements Source: GET /v1/<mount>/data/<path>, field from .data.data.
func (s *VaultSource) Fetch(ctx context.Context, ref Ref) (string, error) {
	mount, path, ok := strings.Cut(ref.Path, "/")
	if !ok {
		return "", fmt.Errorf("vault reference needs <mount>/<path>")
	}
	if ref.Field == "" {
		return "", fmt.Errorf("vault reference needs #<field>")
	}
	tok, err := s.authToken(ctx)
	if err != nil {
		return "", err
	}
	u := s.addr + "/v1/" + url.PathEscape(mount) + "/data/" + escapePath(path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", tok)
	s.header(req)
	raw, err := httpDo(s.client, req)
	if err != nil {
		return "", err
	}
	var resp struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", fmt.Errorf("unexpected KV v2 response shape")
	}
	v, ok := resp.Data.Data[ref.Field]
	if !ok || v == "" {
		return "", fmt.Errorf("field %q not present at vault:%s", ref.Field, ref.Path)
	}
	return v, nil
}

// escapePath escapes each segment but keeps the / separators.
func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

// --- CyberArk CCP ---

// CyberArkSource resolves cyberark:<query> via the Central Credential
// Provider web service (AIMWebService). <query> is the Query= expression
// (e.g. "Safe=NetOps;Object=snmp-core"); the response Content is the secret.
// Client-certificate auth is supported via _CERT_FILE/_KEY_FILE.
type CyberArkSource struct {
	base   string
	appID  string
	client *http.Client
}

// NewCyberArkSource builds the CCP backend; nil when _URL or _APP_ID unset.
func NewCyberArkSource(getenv Getenv) (*CyberArkSource, error) {
	base, appID := getenv("PROBECTL_SECRETS_CYBERARK_URL"), getenv("PROBECTL_SECRETS_CYBERARK_APP_ID")
	if base == "" || appID == "" {
		return nil, nil
	}
	client := crypto.HardenedHTTPClient(15 * time.Second)
	if cert, key := getenv("PROBECTL_SECRETS_CYBERARK_CERT_FILE"), getenv("PROBECTL_SECRETS_CYBERARK_KEY_FILE"); cert != "" && key != "" {
		tlsCfg, err := crypto.ClientMTLSConfig(cert, key, getenv("PROBECTL_SECRETS_CYBERARK_CA_FILE"))
		if err != nil {
			return nil, fmt.Errorf("secrets: cyberark client cert: %w", err)
		}
		client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	}
	return &CyberArkSource{base: strings.TrimRight(base, "/"), appID: appID, client: client}, nil
}

// Scheme implements Source.
func (*CyberArkSource) Scheme() string { return "cyberark" }

// Fetch implements Source.
func (s *CyberArkSource) Fetch(ctx context.Context, ref Ref) (string, error) {
	q := url.Values{}
	q.Set("AppID", s.appID)
	q.Set("Query", ref.Path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		s.base+"/AIMWebService/api/Accounts?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	raw, err := httpDo(s.client, req)
	if err != nil {
		return "", err
	}
	var resp struct {
		Content  string `json:"Content"`
		UserName string `json:"UserName"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil || resp.Content == "" {
		return "", fmt.Errorf("unexpected CCP response shape")
	}
	if ref.Field == "username" {
		if resp.UserName == "" {
			return "", fmt.Errorf("CCP response has no UserName")
		}
		return resp.UserName, nil
	}
	return resp.Content, nil
}
