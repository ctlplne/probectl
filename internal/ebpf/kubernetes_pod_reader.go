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
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

var (
	errKubernetesSnapshotExpired = errors.New("kubernetes: inventory snapshot expired before completion")
	kubernetesNamespace          = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

type kubernetesPodReader struct {
	client    *http.Client
	apiOrigin string
	endpoint  string
	pageLimit string
	tokenFile string
	namespace string
}

type kubernetesPodSnapshot struct {
	kubernetesCollectionClock
	Pods []kubernetesPodMetadata
}

// newKubernetesPodReader binds a single operator-selected namespace to the
// configured private API. The caller sets a tenant-scoped budget on each read.
func newKubernetesPodReader(apiServer, namespace, tokenFile, caFile string, pageLimit int, pageTimeout time.Duration) (*kubernetesPodReader, error) {
	base, err := url.Parse(apiServer)
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil || base.Opaque != "" ||
		(base.Path != "" && base.Path != "/") || base.RawPath != "" || base.RawQuery != "" || base.ForceQuery || base.Fragment != "" ||
		!kubernetesNamespace.MatchString(namespace) || tokenFile == "" || caFile == "" || pageLimit <= 0 || pageTimeout <= 0 {
		return nil, errors.New("kubernetes: a private API origin, trusted CA, token file and namespace are required")
	}
	client, err := crypto.HardenedHTTPClientWithCAFile(pageTimeout, caFile)
	if err != nil {
		return nil, errors.New("kubernetes: could not load trusted API certificate authority")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("kubernetes: no direct API transport available")
	}
	transport.Proxy = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	base.Path = ""
	reader := &kubernetesPodReader{client: client, apiOrigin: base.String(), namespace: namespace,
		pageLimit: strconv.Itoa(pageLimit), tokenFile: tokenFile}
	return reader.scopedResource(kubernetesPodsResource), nil
}

// snapshot only returns a complete consistent list. Collection versions and
// continuation tokens are opaque and are never used as clock readings.
func (r *kubernetesPodReader) snapshot(ctx context.Context, maxBytes int64) (kubernetesPodSnapshot, error) {
	pods := []kubernetesPodMetadata{}
	clock, err := r.list(ctx, kubernetesPodsResource, maxBytes, func(raw json.RawMessage) (string, string, error) {
		var object kubernetesPodObject
		if err := json.Unmarshal(raw, &object); err != nil ||
			(object.APIVersion != "" && object.APIVersion != "v1") || (object.Kind != "" && object.Kind != "Pod") {
			return "", "", errKubernetesPodList
		}
		pod, err := object.observation(r.namespace)
		if err != nil {
			return "", "", err
		}
		pods = append(pods, pod)
		return pod.UID, pod.Name, nil
	})
	if err != nil {
		return kubernetesPodSnapshot{}, err
	}
	return kubernetesPodSnapshot{kubernetesCollectionClock: clock, Pods: pods}, nil
}

func (r *kubernetesPodReader) get(ctx context.Context, client *http.Client, query url.Values) (*http.Response, error) {
	// Read the volume on each request so a newly projected token can replace
	// the old credential while a paginated snapshot is in progress.
	file, err := os.Open(r.tokenFile)
	if err != nil {
		return nil, errors.New("kubernetes: service account credential unavailable")
	}
	const maxTokenBytes = 64 << 10
	token, err := io.ReadAll(io.LimitReader(file, maxTokenBytes+1))
	_ = file.Close()
	bearer := strings.TrimSpace(string(token))
	if err != nil || len(token) > maxTokenBytes || !validKubernetesMetadataString(bearer) {
		return nil, errors.New("kubernetes: service account credential unavailable")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, r.endpoint+"?"+query.Encode(), nil)
	if err != nil {
		return nil, errors.New("kubernetes: Pod inventory request is invalid")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+bearer)
	response, err := client.Do(request)
	if err != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("kubernetes: Pod inventory transport failed")
	}
	if response.StatusCode == http.StatusOK {
		return response, nil
	}
	_ = response.Body.Close()
	if response.StatusCode == http.StatusGone {
		return nil, errKubernetesSnapshotExpired
	}
	return nil, fmt.Errorf("kubernetes: Pod inventory returned HTTP %d", response.StatusCode)
}
