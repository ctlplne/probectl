package secrets

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// Cloud secret-manager backends (S41). All three speak plain HTTPS with
// stdlib-only auth — no cloud SDK dependencies (CLAUDE.md §9: new external
// dependencies need sign-off; none are needed here). Crypto primitives stay
// inside internal/crypto (guardrail 3): SigV4's HMAC chain uses the provider's
// Sign, hashes use Hash, and the GCP service-account JWT is signed by
// crypto.SignRS256.

// --- AWS Secrets Manager (SigV4, hand-rolled) ---

// AWSSource resolves aws:<secret-id>[#<json-field>] via secretsmanager
// GetSecretValue, signed with SigV4 from the standard AWS env credentials.
type AWSSource struct {
	region    string
	accessKey string
	secretKey string
	session   string
	client    *http.Client
	endpoint  string           // test override
	now       func() time.Time // test override
}

// NewAWSSource builds the AWS backend; nil when credentials/region are unset.
func NewAWSSource(getenv Getenv) *AWSSource {
	region := getenv("AWS_REGION")
	if region == "" {
		region = getenv("AWS_DEFAULT_REGION")
	}
	ak, sk := getenv("AWS_ACCESS_KEY_ID"), getenv("AWS_SECRET_ACCESS_KEY")
	if region == "" || ak == "" || sk == "" {
		return nil
	}
	return &AWSSource{
		region: region, accessKey: ak, secretKey: sk, session: getenv("AWS_SESSION_TOKEN"),
		client: crypto.HardenedHTTPClient(15 * time.Second),
		now:    time.Now,
	}
}

// Scheme implements Source.
func (*AWSSource) Scheme() string { return "aws" }

func hmacSHA256(key, data []byte) []byte { return crypto.Default.Sign(key, data) }
func sha256hex(data []byte) string       { return hex.EncodeToString(crypto.Default.Hash(data)) }

// Fetch implements Source.
func (s *AWSSource) Fetch(ctx context.Context, ref Ref) (string, error) {
	host := fmt.Sprintf("secretsmanager.%s.amazonaws.com", s.region)
	endpoint := "https://" + host + "/"
	if s.endpoint != "" { // tests
		endpoint = s.endpoint
		if u, err := url.Parse(endpoint); err == nil {
			host = u.Host
		}
	}
	payload, _ := json.Marshal(map[string]string{"SecretId": ref.Path})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	t := s.now().UTC()
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")
	payloadHash := sha256hex(payload)

	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Host", host)
	req.Host = host
	if s.session != "" {
		req.Header.Set("X-Amz-Security-Token", s.session)
	}

	// SigV4 canonical request (sorted, lowercase headers).
	signed := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	canonHeaders := "content-type:" + req.Header.Get("Content-Type") + "\n" +
		"host:" + host + "\n" +
		"x-amz-date:" + amzDate + "\n" +
		"x-amz-target:" + req.Header.Get("X-Amz-Target") + "\n"
	if s.session != "" {
		// alphabetical order: content-type, host, x-amz-date, x-amz-security-token, x-amz-target
		signed = []string{"content-type", "host", "x-amz-date", "x-amz-security-token", "x-amz-target"}
		canonHeaders = "content-type:" + req.Header.Get("Content-Type") + "\n" +
			"host:" + host + "\n" +
			"x-amz-date:" + amzDate + "\n" +
			"x-amz-security-token:" + s.session + "\n" +
			"x-amz-target:" + req.Header.Get("X-Amz-Target") + "\n"
	}
	signedHeaders := strings.Join(signed, ";")
	canonical := strings.Join([]string{
		http.MethodPost, "/", "", canonHeaders, signedHeaders, payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, s.region, "secretsmanager", "aws4_request"}, "/")
	toSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, sha256hex([]byte(canonical))}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+s.secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(s.region))
	kService := hmacSHA256(kRegion, []byte("secretsmanager"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(toSign)))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.accessKey, scope, signedHeaders, signature))

	raw, err := httpDo(s.client, req)
	if err != nil {
		return "", err
	}
	var resp struct {
		SecretString string `json:"SecretString"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil || resp.SecretString == "" {
		return "", fmt.Errorf("unexpected GetSecretValue response shape")
	}
	if ref.Field == "" {
		return resp.SecretString, nil
	}
	var kv map[string]string
	if err := json.Unmarshal([]byte(resp.SecretString), &kv); err != nil {
		return "", fmt.Errorf("secret is not a JSON object but a #field was requested")
	}
	v, ok := kv[ref.Field]
	if !ok || v == "" {
		return "", fmt.Errorf("field %q not present in aws:%s", ref.Field, ref.Path)
	}
	return v, nil
}

// --- Azure Key Vault (client-credentials grant) ---

// AzureSource resolves azure:<vault-name>/<secret-name> via the Key Vault
// data plane, authenticating with an AAD client-credentials grant.
type AzureSource struct {
	tenantID     string
	clientID     string
	clientSecret string
	client       *http.Client
	tokenURL     string // test override
	vaultBase    string // test override ("" -> https://<vault>.vault.azure.net)

	tok    string
	tokExp time.Time
}

// NewAzureSource builds the Azure backend; nil when AAD env creds are unset.
func NewAzureSource(getenv Getenv) *AzureSource {
	t, c, s := getenv("AZURE_TENANT_ID"), getenv("AZURE_CLIENT_ID"), getenv("AZURE_CLIENT_SECRET")
	if t == "" || c == "" || s == "" {
		return nil
	}
	return &AzureSource{tenantID: t, clientID: c, clientSecret: s,
		client: crypto.HardenedHTTPClient(15 * time.Second)}
}

// Scheme implements Source.
func (*AzureSource) Scheme() string { return "azure" }

func (s *AzureSource) bearer(ctx context.Context) (string, error) {
	if s.tok != "" && time.Now().Before(s.tokExp) {
		return s.tok, nil
	}
	tokenURL := s.tokenURL
	if tokenURL == "" {
		tokenURL = "https://login.microsoftonline.com/" + url.PathEscape(s.tenantID) + "/oauth2/v2.0/token"
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", s.clientID)
	form.Set("client_secret", s.clientSecret)
	form.Set("scope", "https://vault.azure.net/.default")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	raw, err := httpDo(s.client, req)
	if err != nil {
		return "", fmt.Errorf("aad token: %w", err)
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil || resp.AccessToken == "" {
		return "", fmt.Errorf("aad token: unexpected response shape")
	}
	s.tok = resp.AccessToken
	ttl := time.Duration(resp.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	s.tokExp = time.Now().Add(ttl * 2 / 3)
	return s.tok, nil
}

// Fetch implements Source.
func (s *AzureSource) Fetch(ctx context.Context, ref Ref) (string, error) {
	vault, name, ok := strings.Cut(ref.Path, "/")
	if !ok {
		return "", fmt.Errorf("azure reference needs <vault-name>/<secret-name>")
	}
	tok, err := s.bearer(ctx)
	if err != nil {
		return "", err
	}
	base := s.vaultBase
	if base == "" {
		base = "https://" + vault + ".vault.azure.net"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/secrets/"+url.PathEscape(name)+"?api-version=7.4", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	raw, err := httpDo(s.client, req)
	if err != nil {
		return "", err
	}
	var resp struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil || resp.Value == "" {
		return "", fmt.Errorf("unexpected Key Vault response shape")
	}
	return resp.Value, nil
}

// --- GCP Secret Manager (service-account JWT bearer grant) ---

// GCPSource resolves gcp:<project>/<secret>[/<version>] via Secret Manager,
// exchanging a service-account-signed JWT (RS256 via internal/crypto) for an
// access token.
type GCPSource struct {
	email      string
	privatePEM []byte
	client     *http.Client
	tokenURL   string // test override ("" -> https://oauth2.googleapis.com/token)
	apiBase    string // test override ("" -> https://secretmanager.googleapis.com)
	now        func() time.Time

	tok    string
	tokExp time.Time
}

// NewGCPSource builds the GCP backend from a service-account key file
// (GOOGLE_APPLICATION_CREDENTIALS); nil when unset. readFile is the fs seam.
func NewGCPSource(getenv Getenv, readFile func(string) ([]byte, error)) (*GCPSource, error) {
	path := getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if path == "" {
		return nil, nil
	}
	raw, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("secrets: gcp credentials: %w", err)
	}
	var sa struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal(raw, &sa); err != nil || sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, fmt.Errorf("secrets: gcp credentials: unexpected service-account key shape")
	}
	return &GCPSource{email: sa.ClientEmail, privatePEM: []byte(sa.PrivateKey),
		client: crypto.HardenedHTTPClient(15 * time.Second), now: time.Now}, nil
}

// Scheme implements Source.
func (*GCPSource) Scheme() string { return "gcp" }

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (s *GCPSource) bearer(ctx context.Context) (string, error) {
	if s.tok != "" && s.now().Before(s.tokExp) {
		return s.tok, nil
	}
	tokenURL := s.tokenURL
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}
	now := s.now()
	header := b64url([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"iss":   s.email,
		"scope": "https://www.googleapis.com/auth/cloud-platform",
		"aud":   tokenURL,
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
	})
	signingInput := header + "." + b64url(claims)
	sig, err := crypto.SignRS256(s.privatePEM, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("sign sa jwt: %w", err)
	}
	assertion := signingInput + "." + b64url(sig)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	raw, err := httpDo(s.client, req)
	if err != nil {
		return "", fmt.Errorf("gcp token: %w", err)
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil || resp.AccessToken == "" {
		return "", fmt.Errorf("gcp token: unexpected response shape")
	}
	s.tok = resp.AccessToken
	ttl := time.Duration(resp.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	s.tokExp = s.now().Add(ttl * 2 / 3)
	return s.tok, nil
}

// Fetch implements Source.
func (s *GCPSource) Fetch(ctx context.Context, ref Ref) (string, error) {
	parts := strings.Split(ref.Path, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return "", fmt.Errorf("gcp reference needs <project>/<secret>[/<version>]")
	}
	version := "latest"
	if len(parts) == 3 {
		version = parts[2]
	}
	tok, err := s.bearer(ctx)
	if err != nil {
		return "", err
	}
	base := s.apiBase
	if base == "" {
		base = "https://secretmanager.googleapis.com"
	}
	u := fmt.Sprintf("%s/v1/projects/%s/secrets/%s/versions/%s:access",
		base, url.PathEscape(parts[0]), url.PathEscape(parts[1]), url.PathEscape(version))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	raw, err := httpDo(s.client, req)
	if err != nil {
		return "", err
	}
	var resp struct {
		Payload struct {
			Data string `json:"data"` // base64
		} `json:"payload"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil || resp.Payload.Data == "" {
		return "", fmt.Errorf("unexpected Secret Manager response shape")
	}
	decoded, err := base64.StdEncoding.DecodeString(resp.Payload.Data)
	if err != nil {
		return "", fmt.Errorf("secret payload is not valid base64")
	}
	return string(decoded), nil
}
