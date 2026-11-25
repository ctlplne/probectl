// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package objectstore

import (
	"bytes"
	"context"
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
	resp, err := s.openObject(ctx, key)
	if err != nil {
		return Object{}, err
	}
	defer resp.Body.Close()
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

func (s *S3Store) CopyLimited(ctx context.Context, key string, dst io.Writer, maxBytes int64) (int64, error) {
	if maxBytes < 0 {
		return 0, ErrTooLarge
	}
	resp, err := s.openObject(ctx, key)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.ContentLength > maxBytes {
		return 0, ErrTooLarge
	}
	return copyObjectLimited(ctx, dst, resp.Body, maxBytes)
}

type S3ReadRevision struct {
	Key, Version, ExpectedOwner, ETag string
}

// CopyS3VersionLimited makes one read-only GetObject request against the
// configured bucket and expected AWS account. An optional version selects
// an immutable revision and ETag pins an unversioned read. The caller
// discards dst if the copy fails.
func CopyS3VersionLimited(ctx context.Context, cfg S3Config, object S3ReadRevision, dst io.Writer, maxBytes int64) (int64, error) {
	s, err := NewS3(cfg)
	if err != nil {
		return 0, err
	}
	defer s.client.CloseIdleConnections()
	defer crypto.Zeroize(s.secretKey)
	return s.copyVersionLimited(ctx, object, dst, maxBytes)
}

func (s *S3Store) copyVersionLimited(ctx context.Context, object S3ReadRevision, dst io.Writer, maxBytes int64) (int64, error) {
	if err := validKey(object.Key); err != nil {
		return 0, err
	}
	if len(object.ExpectedOwner) != 12 || strings.IndexFunc(object.ExpectedOwner, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, errors.New("objectstore: expected S3 bucket account is required")
	}
	if maxBytes < 0 {
		return 0, ErrTooLarge
	}
	query := make(url.Values)
	if object.Version != "" {
		query.Set("versionId", object.Version)
	}
	client := *s.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	headers := make(http.Header)
	headers.Set("X-Amz-Expected-Bucket-Owner", object.ExpectedOwner)
	headers.Set("Accept-Encoding", "gzip") // keep the stored representation in private staging
	if object.ETag != "" {
		headers.Set("If-Match", object.ETag)
	}
	resp, err := s.doWithHeaders(ctx, &client, http.MethodGet, object.Key, query, headers, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return 0, ErrNotFound
	case resp.StatusCode != http.StatusOK:
		return 0, fmt.Errorf("objectstore: S3 GetObject status %d", resp.StatusCode)
	case object.Version != "" && resp.Header.Get("X-Amz-Version-Id") != "" && resp.Header.Get("X-Amz-Version-Id") != object.Version:
		return 0, errors.New("objectstore: unexpected S3 object version")
	case object.ETag != "" && resp.Header.Get("ETag") != object.ETag:
		return 0, errors.New("objectstore: unexpected S3 object entity tag")
	case resp.ContentLength > maxBytes:
		return 0, ErrTooLarge
	}
	n, err := copyObjectLimited(ctx, dst, resp.Body, maxBytes)
	if err == nil && resp.ContentLength >= 0 && resp.ContentLength != n {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

func (s *S3Store) openObject(ctx context.Context, key string) (*http.Response, error) {
	if err := validKey(key); err != nil {
		return nil, err
	}
	resp, err := s.do(ctx, http.MethodGet, key, nil, "", nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusOK {
		return resp, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	return nil, s3StatusError(resp)
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
	headers := make(http.Header)
	if contentType != "" {
		headers.Set("Content-Type", contentType)
	}
	return s.doWithHeaders(ctx, s.client, method, key, query, headers, body)
}

func (s *S3Store) doWithHeaders(ctx context.Context, client *http.Client, method, key string, query url.Values, headers http.Header, body []byte) (*http.Response, error) {
	u := *s.endpoint
	path := strings.TrimRight(u.Path, "/") + "/" + s.bucket
	if key != "" {
		path += "/" + s.fullKey(key)
	}
	u.Path = path
	u.RawPath = ""
	if headers.Get("X-Amz-Expected-Bucket-Owner") != "" {
		// S3's SigV4 canonical form escapes each non-slash reserved character.
		segments := strings.Split(path, "/")
		for i, segment := range segments {
			segments[i] = strings.ReplaceAll(url.QueryEscape(segment), "+", "%20")
		}
		u.RawPath = strings.Join(segments, "/")
	}
	if query != nil {
		u.RawQuery = query.Encode()
		if headers.Get("X-Amz-Expected-Bucket-Owner") != "" {
			u.RawQuery = strings.ReplaceAll(u.RawQuery, "+", "%20")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = headers
	s.sign(req, body)
	resp, err := client.Do(req)
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
	headers := []string{"x-amz-content-sha256"}
	for _, name := range []string{"x-amz-expected-bucket-owner", "if-match"} {
		if req.Header.Get(name) != "" {
			headers = append(headers, name)
		}
	}
	crypto.SignAWSV4(req, body, crypto.AWSV4Credentials{AccessKey: s.accessKey, SecretKey: s.secretKey, SessionToken: s.sessionToken},
		s.region, "s3", s.now(), headers...)
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
