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
	"io"
	"math"
	"net/url"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
)

type kubernetesResource struct {
	apiVersion, kind, apiPath, plural string
}

var kubernetesPodsResource = kubernetesResource{"v1", "Pod", "/api/v1", "pods"}

type kubernetesCollectionClock struct {
	Namespace, ResourceVersion     string
	ReadStartedAt, ReadCompletedAt time.Time
}

type kubernetesCollectionPage struct {
	ResourceVersion, Continue string
	Items                     []json.RawMessage
	wireBytes                 int64
}

// scopedResource returns the same rotating credential and direct verified
// transport restricted to a different built-in resource of the same namespace.
func (r *kubernetesPodReader) scopedResource(resource kubernetesResource) *kubernetesPodReader {
	clone := *r
	clone.endpoint = r.apiOrigin + resource.apiPath + "/namespaces/" + r.namespace + "/" + resource.plural
	return &clone
}

func (r *kubernetesPodReader) list(ctx context.Context, resource kubernetesResource, maxBytes int64,
	accept func(json.RawMessage) (uid, name string, err error)) (kubernetesCollectionClock, error) {
	if maxBytes <= 0 || maxBytes == math.MaxInt64 {
		return kubernetesCollectionClock{}, errKubernetesPodList
	}
	ctx, cancel := context.WithTimeout(ctx, kubernetesWatchLease)
	defer cancel()
	reader := r.scopedResource(resource)
	clock := kubernetesCollectionClock{Namespace: r.namespace, ReadStartedAt: time.Now().UTC()}
	query := url.Values{"limit": {r.pageLimit}}
	seenUID, seenName, seenCursor := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for {
		page, err := reader.inventoryPage(ctx, resource, query, maxBytes)
		if err != nil {
			return kubernetesCollectionClock{}, err
		}
		if page.wireBytes <= 0 || page.wireBytes > maxBytes ||
			(clock.ResourceVersion != "" && clock.ResourceVersion != page.ResourceVersion) {
			return kubernetesCollectionClock{}, errKubernetesPodList
		}
		maxBytes -= page.wireBytes
		clock.ResourceVersion = page.ResourceVersion
		for _, item := range page.Items {
			uid, name, err := accept(item)
			if err != nil || seenUID[uid] || seenName[name] {
				return kubernetesCollectionClock{}, errKubernetesPodList
			}
			seenUID[uid], seenName[name] = true, true
		}
		if page.Continue == "" {
			clock.ReadCompletedAt = time.Now().UTC()
			if clock.ReadCompletedAt.Before(clock.ReadStartedAt) {
				return kubernetesCollectionClock{}, errKubernetesPodList
			}
			return clock, nil
		}
		if maxBytes == 0 || seenCursor[page.Continue] {
			return kubernetesCollectionClock{}, errKubernetesPodList
		}
		seenCursor[page.Continue] = true
		query.Set("continue", page.Continue)
	}
}

func (r *kubernetesPodReader) inventoryPage(ctx context.Context, resource kubernetesResource, query url.Values,
	maxBytes int64) (kubernetesCollectionPage, error) {
	response, err := r.get(ctx, r.client, query)
	if err != nil {
		return kubernetesCollectionPage{}, err
	}
	defer response.Body.Close()
	return readKubernetesCollectionPage(response.Body, resource, maxBytes)
}

func readKubernetesCollectionPage(body io.Reader, resource kubernetesResource, maxBytes int64) (kubernetesCollectionPage, error) {
	if body == nil || maxBytes <= 0 || maxBytes == math.MaxInt64 {
		return kubernetesCollectionPage{}, errKubernetesPodList
	}
	limited := &io.LimitedReader{R: body, N: maxBytes + 1}
	decoder := json.NewDecoder(limited)
	var page struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			ResourceVersion string          `json:"resourceVersion"`
			Continue        string          `json:"continue"`
			ShardInfo       json.RawMessage `json:"shardInfo"`
		} `json:"metadata"`
		Items []json.RawMessage `json:"items"`
	}
	if err := decoder.Decode(&page); err != nil || page.APIVersion != resource.apiVersion || page.Kind != resource.kind+"List" ||
		!entity.ValidKubernetesResourceVersion(page.Metadata.ResourceVersion) || page.Items == nil || len(page.Metadata.ShardInfo) != 0 ||
		(page.Metadata.Continue != "" && !validKubernetesMetadataString(page.Metadata.Continue)) {
		return kubernetesCollectionPage{}, errKubernetesPodList
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) || limited.N == 0 {
		return kubernetesCollectionPage{}, errKubernetesPodList
	}
	return kubernetesCollectionPage{ResourceVersion: page.Metadata.ResourceVersion, Continue: page.Metadata.Continue,
		Items: page.Items, wireBytes: maxBytes + 1 - limited.N}, nil
}
