// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package objectstore

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/httpbody"
)

const (
	defaultS3Region        = "us-east-1"
	maxS3ListResponseBytes = 4 << 20
)

// S3Config configures the self-hosted S3/MinIO-compatible artifact backend.
// Static credentials may be secret references resolved by the caller before
// construction. Endpoint must be verified HTTPS except loopback test doubles.
type S3Config struct {
	Endpoint, Bucket, Region, AccessKey, SecretKey, SessionToken, Prefix string
	Timeout                                                              time.Duration
}

// S3Store is a path-style S3/MinIO Store implementation. It makes no calls
// unless explicitly configured by the operator (no phone-home).
type S3Store struct {
	endpoint     *url.URL
	bucket       string
	region       string
	accessKey    string
	secretKey    []byte
	sessionToken string
	prefix       string
	client       *http.Client
	now          func() time.Time
}

// NewS3 validates config and builds a TLS-verifying S3/MinIO store.
func NewS3(cfg S3Config) (*S3Store, error) {
	return newS3(cfg, crypto.HardenedHTTPClient(firstDuration(cfg.Timeout, 30*time.Second)))
}

func newS3(cfg S3Config, client *http.Client) (*S3Store, error) {
	endpoint, err := url.Parse(strings.TrimSpace(cfg.Endpoint))
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("objectstore: s3 endpoint must be an absolute URL without credentials, query, or fragment")
	}
	if endpoint.Scheme != "https" && (endpoint.Scheme != "http" || !isLoopbackHost(endpoint.Hostname())) {
		return nil, errors.New("objectstore: s3 endpoint must use verified https (http is loopback-test-only)")
	}
	if strings.TrimSpace(cfg.Bucket) == "" || strings.ContainsAny(cfg.Bucket, "/\\\x00") {
		return nil, errors.New("objectstore: s3 bucket is required and must not contain a path")
	}
	if strings.TrimSpace(cfg.AccessKey) == "" || strings.TrimSpace(cfg.SecretKey) == "" {
		return nil, errors.New("objectstore: s3 access key and secret key are required")
	}
	prefix := strings.Trim(cfg.Prefix, "/")
	if prefix != "" {
		if err := validKey(prefix); err != nil {
			return nil, fmt.Errorf("objectstore: s3 prefix: %w", err)
		}
	}
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		region = defaultS3Region
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/")
	if client == nil {
		client = crypto.HardenedHTTPClient(firstDuration(cfg.Timeout, 30*time.Second))
	}
	return &S3Store{
		endpoint: endpoint, bucket: cfg.Bucket, region: region, accessKey: cfg.AccessKey,
		secretKey: []byte(cfg.SecretKey), sessionToken: cfg.SessionToken, prefix: prefix,
		client: client, now: time.Now,
	}, nil
}

func firstDuration(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func (s *S3Store) Put(ctx context.Context, key, contentType string, data []byte) error {
	if err := validKey(key); err != nil {
		return err
	}
	resp, err := s.do(ctx, http.MethodPut, key, nil, contentType, data)
	if err != nil {
		return err
	}
	return closeS3Response(resp, http.StatusOK, http.StatusCreated, http.StatusNoContent)
}

func (s *S3Store) Get(ctx context.Context, key string) (Object, error) {
	return s.get(ctx, key, -1)
}

func (s *S3Store) GetLimited(ctx context.Context, key string, maxBytes int64) (Object, error) {
	if maxBytes < 0 {
		return Object{}, ErrTooLarge
	}
	return s.get(ctx, key, maxBytes)
}

func (s *S3Store) get(ctx context.Context, key string, maxBytes int64) (Object, error) {
	if err := validKey(key); err != nil {
		return Object{}, err
	}
	resp, err := s.do(ctx, http.MethodGet, key, nil, "", nil)
	if err != nil {
		return Object{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Object{}, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return Object{}, s3StatusError(resp)
	}
	if maxBytes >= 0 && resp.ContentLength > maxBytes {
		return Object{}, ErrTooLarge
	}
	reader := io.Reader(resp.Body)
	if maxBytes >= 0 {
		reader = io.LimitReader(resp.Body, maxBytes+1)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		return Object{}, err
	}
	if maxBytes >= 0 && int64(len(body)) > maxBytes {
		return Object{}, ErrTooLarge
	}
	return Object{Data: body, ContentType: resp.Header.Get("Content-Type"), Size: int64(len(body))}, nil
}

func (s *S3Store) Stat(ctx context.Context, key string) (int64, bool, error) {
	if err := validKey(key); err != nil {
		return 0, false, err
	}
	resp, err := s.do(ctx, http.MethodHead, key, nil, "", nil)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return 0, false, s3StatusError(resp)
	}
	return resp.ContentLength, true, nil
}

func (s *S3Store) List(ctx context.Context, prefix string) ([]string, error) {
	return s.list(ctx, prefix, -1)
}

func (s *S3Store) ListLimited(ctx context.Context, prefix string, maxKeys int) ([]string, error) {
	if maxKeys < 0 {
		return nil, ErrTooMany
	}
	return s.list(ctx, prefix, maxKeys)
}

type s3ListResult struct {
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
	Contents              []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
}

func (s *S3Store) list(ctx context.Context, prefix string, maxKeys int) ([]string, error) {
	if err := validListPrefix(prefix); err != nil {
		return nil, err
	}
	fullPrefix := s.fullKey(prefix)
	var out []string
	continuation := ""
	for {
		query := url.Values{"list-type": {"2"}, "prefix": {fullPrefix}}
		if continuation != "" {
			query.Set("continuation-token", continuation)
		}
		resp, err := s.do(ctx, http.MethodGet, "", query, "", nil)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			err := s3StatusError(resp)
			resp.Body.Close()
			return nil, err
		}
		body, err := httpbody.ReadLimited(resp.Body, maxS3ListResponseBytes)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("objectstore: s3 list response: %w", err)
		}
		var page s3ListResult
		if err := xml.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("objectstore: s3 list response: %w", err)
		}
		for _, item := range page.Contents {
			key, ok := s.relativeKey(item.Key)
			if !ok || !strings.HasPrefix(key, prefix) {
				continue
			}
			if maxKeys >= 0 && len(out) >= maxKeys {
				return nil, ErrTooMany
			}
			out = append(out, key)
		}
		if !page.IsTruncated {
			break
		}
		if page.NextContinuationToken == "" || page.NextContinuationToken == continuation {
			return nil, errors.New("objectstore: s3 list pagination made no progress")
		}
		continuation = page.NextContinuationToken
	}
	sort.Strings(out)
	return out, nil
}

func (s *S3Store) DeletePrefix(ctx context.Context, prefix string) (int, error) {
	keys, err := s.List(ctx, prefix)
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, key := range keys {
		resp, err := s.do(ctx, http.MethodDelete, key, nil, "", nil)
		if err != nil {
			return deleted, err
		}
		if err := closeS3Response(resp, http.StatusOK, http.StatusNoContent, http.StatusNotFound); err != nil {
			return deleted, err
		}
		deleted++
	}
	return deleted, nil
}

func (s *S3Store) do(ctx context.Context, method, key string, query url.Values, contentType string, body []byte) (*http.Response, error) {
	u := *s.endpoint
	path := strings.TrimRight(u.Path, "/") + "/" + s.bucket
	if key != "" {
		path += "/" + s.fullKey(key)
	}
	u.Path = path
	u.RawPath = ""
	if query != nil {
		u.RawQuery = query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	s.sign(req, body)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("objectstore: s3 request: %w", err)
	}
	return resp, nil
}

func (s *S3Store) fullKey(key string) string {
	if s.prefix == "" {
		return key
	}
	if key == "" {
		return s.prefix + "/"
	}
	return s.prefix + "/" + key
}

func (s *S3Store) relativeKey(full string) (string, bool) {
	if s.prefix == "" {
		return full, true
	}
	prefix := s.prefix + "/"
	if !strings.HasPrefix(full, prefix) {
		return "", false
	}
	return strings.TrimPrefix(full, prefix), true
}

func (s *S3Store) sign(req *http.Request, body []byte) {
	now := s.now().UTC()
	amzDate, date := now.Format("20060102T150405Z"), now.Format("20060102")
	payloadHash := hex.EncodeToString(crypto.Hash(body))
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if s.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", s.sessionToken)
	}
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if s.sessionToken != "" {
		headers = append(headers, "x-amz-security-token")
	}
	sort.Strings(headers)
	var canonicalHeaders strings.Builder
	for _, name := range headers {
		value := req.Header.Get(name)
		if name == "host" {
			value = req.URL.Host
		}
		canonicalHeaders.WriteString(name + ":" + strings.Join(strings.Fields(value), " ") + "\n")
	}
	signedHeaders := strings.Join(headers, ";")
	canonicalQuery := strings.ReplaceAll(req.URL.Query().Encode(), "+", "%20")
	canonicalRequest := strings.Join([]string{
		req.Method, req.URL.EscapedPath(), canonicalQuery, canonicalHeaders.String(), signedHeaders, payloadHash,
	}, "\n")
	scope := date + "/" + s.region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(crypto.Hash([]byte(canonicalRequest)))
	kDate := crypto.Sign(append([]byte("AWS4"), s.secretKey...), []byte(date))
	kRegion := crypto.Sign(kDate, []byte(s.region))
	kService := crypto.Sign(kRegion, []byte("s3"))
	kSigning := crypto.Sign(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(crypto.Sign(kSigning, []byte(stringToSign)))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.accessKey+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature)
}

func closeS3Response(resp *http.Response, allowed ...int) error {
	defer resp.Body.Close()
	for _, status := range allowed {
		if resp.StatusCode == status {
			return nil
		}
	}
	return s3StatusError(resp)
}

func s3StatusError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("objectstore: s3 status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

var _ Store = (*S3Store)(nil)
