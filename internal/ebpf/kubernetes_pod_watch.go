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
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
)

var errKubernetesPodWatch = errors.New("kubernetes: incomplete or invalid Pod watch")

const kubernetesWatchFirstAttempt = 12 * time.Second

// The built-in watch cache can send progress before the requested deadline.
// Give quiet resources a short first chance to settle. If a lease expires
// without progress, replay from the same LIST within the remaining budget.
// The API does not guarantee bookmarks. Only accepted progress closes a window.
func tryKubernetesWatch(ctx context.Context, attempt func(time.Duration) error) error {
	err := attempt(kubernetesWatchFirstAttempt)
	if ctx.Err() != nil || (err != nil && !errors.Is(err, context.DeadlineExceeded)) {
		return err
	}
	// Reserve the first stream's client-side response grace as well.
	return attempt(kubernetesWatchLease - kubernetesWatchFirstAttempt - time.Second)
}

type kubernetesPodChange struct {
	Type            string
	ResourceVersion string
	ReceivedAt      time.Time
	Pod             kubernetesPodMetadata // Empty for a bookkeeping bookmark.
}

// watch resumes an already complete namespace snapshot. A resume point can
// advance only after all events through that revision have been accepted.
// One storage revision may contain more than one object event. A bookmark
// marks completed stream progress and supplies no wall clock of its own.
func (r *kubernetesPodReader) watch(ctx context.Context, resourceVersion string, duration time.Duration,
	maxBytes int64, accept func(kubernetesPodChange) error) error {
	if accept == nil {
		return errKubernetesPodWatch
	}
	return r.watchInventory(ctx, resourceVersion, duration, maxBytes, func(kind string, body []byte) error {
		change, err := readKubernetesPodChange(kind, body, r.namespace)
		if err != nil {
			return err
		}
		return accept(change)
	})
}

func (r *kubernetesPodReader) watchInventory(ctx context.Context, resourceVersion string, duration time.Duration,
	maxBytes int64, accept func(string, []byte) error) error {
	if !entity.ValidKubernetesResourceVersion(resourceVersion) || duration < time.Second || duration > math.MaxInt64-time.Second ||
		maxBytes <= 0 || maxBytes == math.MaxInt64 || accept == nil {
		return errKubernetesPodWatch
	}
	// Give the server time to close the stream before the client deadline.
	ctx, cancel := context.WithTimeout(ctx, duration+time.Second)
	defer cancel()
	query := url.Values{
		"watch":               {"true"},
		"allowWatchBookmarks": {"true"},
		"resourceVersion":     {resourceVersion},
		"timeoutSeconds":      {strconv.FormatInt(int64(duration/time.Second), 10)},
	}
	response, err := r.get(ctx, crypto.StreamingHTTPClientFrom(r.client), query)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	limited := &io.LimitedReader{R: response.Body, N: maxBytes + 1}
	decoder := json.NewDecoder(limited)
	for {
		var event struct {
			Type   string          `json:"type"`
			Object json.RawMessage `json:"object"`
		}
		err := decoder.Decode(&event)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if decoder.InputOffset() > maxBytes || (err != nil && limited.N == 0) {
			return errKubernetesPodWatch
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return errKubernetesPodWatch
		}
		if event.Type == "ERROR" {
			return kubernetesInventoryWatchError(event.Object)
		}
		if err := accept(event.Type, event.Object); err != nil {
			return err
		}
	}
}

func kubernetesInventoryWatchError(body []byte) error {
	var status struct {
		Kind string `json:"kind"`
		Code int    `json:"code"`
	}
	if err := json.Unmarshal(body, &status); err == nil && status.Kind == "Status" && status.Code == http.StatusGone {
		return errKubernetesSnapshotExpired
	}
	return errKubernetesPodWatch
}

func readKubernetesPodChange(kind string, body []byte, namespace string) (kubernetesPodChange, error) {
	var object kubernetesPodObject
	if err := json.Unmarshal(body, &object); err != nil || object.APIVersion != "v1" || object.Kind != "Pod" ||
		!entity.ValidKubernetesResourceVersion(object.Metadata.ResourceVersion) {
		return kubernetesPodChange{}, errKubernetesPodWatch
	}
	change := kubernetesPodChange{Type: kind, ResourceVersion: object.Metadata.ResourceVersion, ReceivedAt: time.Now().UTC()}
	switch kind {
	case "BOOKMARK":
		if object.Metadata.Namespace == "" || object.Metadata.Namespace == namespace {
			return change, nil
		}
	case "ADDED", "MODIFIED", "DELETED":
		pod, err := object.observation(namespace)
		if err == nil {
			change.Pod = pod
			return change, nil
		}
	}
	return kubernetesPodChange{}, errKubernetesPodWatch
}
