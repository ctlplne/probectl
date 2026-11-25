// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cloudflow

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/secrets"
)

const (
	maxPullBytes        = 64 << 20
	maxCloudCredential  = 32 << 10
	cloudRequestTimeout = 90 * time.Second
)

type copyS3FlowObject func(context.Context, objectstore.S3Config, objectstore.S3ReadRevision, io.Writer, int64) (int64, error)

type cloudObjectTransfer struct {
	client *http.Client
	copyS3 copyS3FlowObject
}

// PullObject imports the exact object selected by this tenant's collector
// configuration. The cloud payload can supply neither credentials nor scope.
func PullObject(ctx context.Context, cfg flow.CloudImportConfig, tenant, agent string, resolver *secrets.Resolver, emitter flow.Emitter) (int, int, error) {
	transfer := newCloudObjectTransfer()
	defer transfer.client.CloseIdleConnections()
	return transfer.pull(ctx, cfg, tenant, agent, resolver, emitter)
}

func newCloudObjectTransfer() cloudObjectTransfer {
	client := crypto.HardenedHTTPClient(cloudRequestTimeout)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return cloudObjectTransfer{client: client, copyS3: objectstore.CopyS3VersionLimited}
}

func (source cloudObjectTransfer) pull(ctx context.Context, cfg flow.CloudImportConfig, tenant, agent string,
	resolver *secrets.Resolver, emitter flow.Emitter) (int, int, error) {
	return source.pullRevision(ctx, cfg, tenant, agent, resolver, emitter, "", time.Now)
}

func (source cloudObjectTransfer) pullRevision(ctx context.Context, cfg flow.CloudImportConfig, tenant, agent string,
	resolver *secrets.Resolver, emitter flow.Emitter, etag string, now func() time.Time) (int, int, error) {
	if tenant == "" {
		return 0, 0, ErrNoTenant
	}
	if resolver == nil || emitter == nil || cfg.Object == nil {
		return 0, 0, errors.New("cloudflow: object, secrets resolver and emitter are required")
	}
	if err := cfg.Validate(); err != nil {
		return 0, 0, err
	}
	if agent == "" {
		agent = "cloud-flow-importer"
	}
	raw, err := os.CreateTemp("", "probectl-cloudflow-download-*")
	if err != nil {
		return 0, 0, err
	}
	defer discardCloudStage(raw)
	provider := Provider(cfg.Provider)
	// Download and verify the bounded wire and decoded bytes before publishing.
	pull, cancel := context.WithTimeout(ctx, cloudRequestTimeout)
	defer cancel()
	if err := source.stage(pull, provider, *cfg.Object, etag, resolver, raw); err != nil {
		return 0, 0, err
	}
	input, closeDecoded, err := verifyCloudCompression(pull, raw)
	if err != nil {
		return 0, 0, err
	}
	defer closeDecoded()
	if err := preflightCloudObject(pull, provider, input); err != nil {
		return 0, 0, err
	}
	return scan(ctx, provider, tenant, agent, input, now, true, emitter.Emit)
}

func (source cloudObjectTransfer) stage(ctx context.Context, provider Provider, spec flow.CloudObjectConfig, etag string,
	resolver *secrets.Resolver, dst *os.File) error {
	credential, release, err := resolver.ResolveBytesUncached(ctx, spec.CredentialRef)
	if err != nil {
		return errors.New("cloudflow: object credential could not be resolved")
	}
	defer release()
	if len(credential) == 0 || len(credential) > maxCloudCredential {
		return errors.New("cloudflow: object credential has an invalid size")
	}
	if provider == ProviderAWSVPC {
		return source.copyAWS(ctx, spec, etag, credential, dst)
	}
	return source.copyBearer(ctx, provider, spec, etag, credential, dst)
}

func (source cloudObjectTransfer) copyAWS(ctx context.Context, spec flow.CloudObjectConfig, etag string, credential []byte, dst io.Writer) error {
	auth, err := crypto.DecodeAWSV4Credentials(credential)
	if err != nil {
		return err
	}
	defer crypto.Zeroize(auth.SecretKey)
	_, err = source.copyS3(ctx, objectstore.S3Config{
		Endpoint: "https://" + crypto.AWSRegionalHost("s3", spec.Region), Bucket: spec.Bucket, Region: spec.Region,
		AccessKey: auth.AccessKey, SecretKey: string(auth.SecretKey), SessionToken: auth.SessionToken, Timeout: cloudRequestTimeout,
	}, objectstore.S3ReadRevision{Key: spec.Key, Version: spec.Version, ExpectedOwner: spec.ExpectedOwner, ETag: etag}, dst, maxPullBytes)
	return err
}

func (source cloudObjectTransfer) copyBearer(ctx context.Context, provider Provider, spec flow.CloudObjectConfig, etag string, credential []byte, dst io.Writer) error {
	token := string(credential)
	if !visibleASCIICredential(token) {
		return errors.New("cloudflow: invalid object access token")
	}
	u := &url.URL{Scheme: "https"}
	query := make(url.Values)
	var versionHeader string
	switch provider {
	case ProviderAzureNSG, ProviderAzureVNet:
		u.Host = spec.Account + ".blob.core.windows.net"
		u.Path = "/" + spec.Bucket + "/" + spec.Key
		if spec.Version != "" {
			query.Set("versionid", spec.Version)
		}
		versionHeader = "X-Ms-Version-Id"
	case ProviderGCPVPC:
		u.Host = "storage.googleapis.com"
		// The media endpoint serves the body directly. This client rejects redirects.
		base := "/download/storage/v1/b/" + spec.Bucket + "/o/"
		u.Path, u.RawPath = base+spec.Key, base+url.PathEscape(spec.Key)
		query.Set("alt", "media")
		if spec.Version != "" {
			query.Set("generation", spec.Version)
		}
		versionHeader = "X-Goog-Generation"
	default:
		return ErrUnknownProvider
	}
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return errors.New("cloudflow: cannot construct the provider object request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept-Encoding", "gzip")
	if etag != "" {
		req.Header.Set("If-Match", etag)
	}
	if provider == ProviderAzureNSG || provider == ProviderAzureVNet {
		req.Header.Set("X-Ms-Version", "2023-11-03")
		req.Header.Set("X-Ms-Date", time.Now().UTC().Format(http.TimeFormat))
	}
	resp, err := source.client.Do(req)
	if err != nil {
		return errors.New("cloudflow: object request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cloudflow: object request returned HTTP %d", resp.StatusCode)
	}
	if actual := resp.Header.Get(versionHeader); spec.Version != "" && actual != "" && actual != spec.Version {
		return errors.New("cloudflow: provider returned a different object version")
	}
	if etag != "" && resp.Header.Get("ETag") != etag {
		return errors.New("cloudflow: provider returned a different object entity tag")
	}
	if resp.ContentLength > maxPullBytes {
		return objectstore.ErrTooLarge
	}
	n, err := copyCloudStage(ctx, dst, resp.Body)
	if err == nil && resp.ContentLength >= 0 && resp.ContentLength != n {
		return io.ErrUnexpectedEOF
	}
	return err
}

func visibleASCIICredential(s string) bool {
	return s != "" && strings.IndexFunc(s, func(r rune) bool { return r < '!' || r > '~' }) < 0
}

func verifyCloudCompression(ctx context.Context, raw *os.File) (io.ReadSeeker, func(), error) {
	if _, err := raw.Seek(0, io.SeekStart); err != nil {
		return nil, nil, err
	}
	input := bufio.NewReader(raw)
	if !gzipStream(input) {
		if _, err := raw.Seek(0, io.SeekStart); err != nil {
			return nil, nil, err
		}
		return raw, func() {}, nil
	}
	gz, err := gzip.NewReader(input)
	if err != nil {
		return nil, nil, fmt.Errorf("cloudflow: open object gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	decoded, err := os.CreateTemp("", "probectl-cloudflow-decoded-*")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { discardCloudStage(decoded) }
	if _, err := copyCloudStage(ctx, decoded, gz); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("cloudflow: verify object gzip: %w", err)
	}
	if _, err := decoded.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, nil, err
	}
	return decoded, cleanup, nil
}

// Preflight only checks file framing. The publish pass handles individual
// malformed records according to the existing importer contract.
func preflightCloudObject(ctx context.Context, provider Provider, input io.ReadSeeker) error {
	src := cloudPullReader{ctx: ctx, r: input}
	if provider == ProviderAzureVNet || provider == ProviderAzureNSG {
		if _, err := scanAzureLogRecords(ctx, src, provider, nil); err != nil {
			return err
		}
	} else {
		scanner := cloudLineScanner(src)
		for scanner.Scan() {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("cloudflow: validate %s object framing: %w", provider, err)
		}
	}
	_, err := input.Seek(0, io.SeekStart)
	return err
}

type cloudPullReader struct {
	ctx context.Context
	r   io.Reader
}

func (r cloudPullReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func copyCloudStage(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	n, err := io.Copy(dst, io.LimitReader(cloudPullReader{ctx: ctx, r: src}, maxPullBytes+1))
	if err == nil && n > maxPullBytes {
		return n, objectstore.ErrTooLarge
	}
	return n, err
}

func discardCloudStage(file *os.File) {
	_ = file.Close()
	_ = os.Remove(file.Name())
}
