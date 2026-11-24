// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func TestKubernetesInventoryCaptureKeepsStableOwnedWindowsAndResumes(t *testing.T) {
	const ns = "inventory-fixture"
	const binding = "11111111-1111-4111-8111-111111111111"
	const creds = "fixture-account-token"
	owner := func(api, kind, uid, name string) string {
		return fmt.Sprintf(`{"apiVersion":%q,"kind":%q,"uid":%q,"name":%q,"controller":true}`, api, kind, uid, name)
	}
	pod := func(uid, name, version, address string) string {
		return fmt.Sprintf(`{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":%q,"uid":%q,"name":%q,"resourceVersion":%q,"ownerReferences":[%s]},"status":{"phase":"Running","podIP":%q}}`,
			ns, uid, name, version, owner("apps/v1", "ReplicaSet", "rs-uid", "web-rs"), address)
	}
	old := pod("pod-old", "old", "10", "10.244.0.5")
	newPod := pod("pod-new", "new", "14", "10.244.0.5")
	stable := pod("pod-stable", "stable", "9", "10.244.0.4")
	supplements := map[string]string{
		"services": fmt.Sprintf(`{"metadata":{"namespace":%q,"uid":"svc-uid","name":"web","resourceVersion":"5"},"spec":{"clusterIP":"10.96.1.2"}}`, ns),
		"endpointslices": fmt.Sprintf(`{"metadata":{"namespace":%q,"uid":"slice-uid","name":"web-slice","resourceVersion":"6","labels":{"kubernetes.io/service-name":"web"},"ownerReferences":[%s]},"addressType":"IPv4","endpoints":[
			{"addresses":["10.244.0.4"],"targetRef":{"kind":"Pod","name":"stable","uid":"pod-stable","namespace":%q}},
			{"addresses":["10.244.0.5"],"targetRef":{"kind":"Pod","name":"old","uid":"pod-old","namespace":%q}}]}`,
			ns, owner("v1", "Service", "svc-uid", "web"), ns, ns),
		"deployments": fmt.Sprintf(`{"metadata":{"namespace":%q,"uid":"deploy-uid","name":"web","resourceVersion":"7"}}`, ns),
		"replicasets": fmt.Sprintf(`{"metadata":{"namespace":%q,"uid":"rs-uid","name":"web-rs","resourceVersion":"8","ownerReferences":[%s]}}`,
			ns, owner("apps/v1", "Deployment", "deploy-uid", "web")),
	}
	var lists, serviceLists, podWatches atomic.Int32
	serviceWatchStarted := make(chan struct{})
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+creds {
			t.Error("inventory escaped its configured namespace or used an invalid access credential")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		for _, resource := range kubernetesSupplementResources {
			if r.URL.Path == resource.apiPath+"/namespaces/"+ns+"/"+resource.plural {
				version := "21"
				if resource.plural == "services" {
					if r.URL.Query().Get("watch") == "true" {
						if r.URL.Query().Get("resourceVersion") != "21" {
							t.Error("Service watch did not resume the original list")
						}
						if r.URL.Query().Get("timeoutSeconds") != "12" {
							t.Error("Service did not receive the short initial watch")
						}
						close(serviceWatchStarted)
						_, _ = io.WriteString(w, `{"type":"BOOKMARK","object":{"apiVersion":"v1","kind":"Service","metadata":{"resourceVersion":"22"}}}`)
						return
					}
					if serviceLists.Add(1) > 1 {
						version = "22"
					}
				}
				_, _ = fmt.Fprintf(w, `{"apiVersion":%q,"kind":%q,"metadata":{"resourceVersion":%q},"items":[%s]}`,
					resource.apiVersion, resource.kind+"List", version, supplements[resource.plural])
				return
			}
		}
		if r.URL.Path != "/api/v1/namespaces/"+ns+"/pods" {
			t.Error("inventory reached an unexpected resource path", r.URL.Path)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Query().Get("watch") == "true" {
			if r.URL.Query().Get("resourceVersion") != "10" {
				t.Error("watch started from a version other than the first complete list")
			}
			select {
			case <-serviceWatchStarted:
			case <-r.Context().Done():
				return
			}
			deleted := pod("pod-old", "old", "13", "10.244.0.5")
			if podWatches.Add(1) == 1 {
				if r.URL.Query().Get("timeoutSeconds") != "12" {
					t.Error("Pod did not receive the short initial watch")
				}
				_, _ = fmt.Fprintf(w, "{\"type\":\"DELETED\",\"object\":%s}\n", deleted)
				return // No progress through the final revision.
			}
			if r.URL.Query().Get("timeoutSeconds") != "62" {
				t.Error("Pod replay did not use the remaining watch budget")
			}
			_, _ = fmt.Fprintf(w, "{\"type\":\"DELETED\",\"object\":%s}\n{\"type\":\"ADDED\",\"object\":%s}\n", deleted, newPod)
			_, _ = io.WriteString(w, `{"type":"BOOKMARK","object":{"apiVersion":"v1","kind":"Pod","metadata":{"resourceVersion":"20"}}}`)
			return
		}
		if lists.Add(1) == 1 {
			_, _ = fmt.Fprintf(w, `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"10"},"items":[%s,%s]}`, old, stable)
			return
		}
		_, _ = fmt.Fprintf(w, `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"20"},"items":[%s,%s]}`, newPod, stable)
	}))
	t.Cleanup(api.Close)
	dir := t.TempDir()
	caFile, tokenFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "token")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte(creds), 0o600); err != nil {
		t.Fatal(err)
	}
	var begins, appends, publishes int
	var generation string
	var digest []byte
	var retainedRows uint64
	send := func(_ context.Context, upload *agentv1.KubernetesInventoryUpload) (*agentv1.KubernetesInventoryReceipt, error) {
		if upload.BindingId != binding || (generation != "" && generation != upload.GenerationId) {
			t.Fatal("retry changed the original scope or generation")
		}
		generation = upload.GenerationId
		switch op := upload.Operation.(type) {
		case *agentv1.KubernetesInventoryUpload_Begin:
			begins++
			if begins == 1 {
				digest = bytes.Clone(op.Begin.PayloadDigest)
				retainedRows = op.Begin.Manifest.Rows
			} else if !bytes.Equal(op.Begin.PayloadDigest, digest) {
				t.Fatal("retry changed the original manifest digest")
			}
			return &agentv1.KubernetesInventoryReceipt{NextPart: uint32(appends), PayloadDigest: digest}, nil
		case *agentv1.KubernetesInventoryUpload_Append:
			appends++
			return nil, status.Error(codes.Unavailable, "fixture acknowledgement interrupted")
		case *agentv1.KubernetesInventoryUpload_Publish:
			publishes++
			return &agentv1.KubernetesInventoryReceipt{NextPart: 1, RetainedRows: retainedRows, PayloadDigest: digest, Published: true}, nil
		default:
			t.Fatal("unexpected upload operation")
			return nil, nil
		}
	}
	collector, err := NewKubernetesInventoryCollector(KubernetesInventoryConfig{Namespace: ns, APIServer: api.URL,
		TokenFile: tokenFile, CAFile: caFile, BindingID: binding, Interval: 5 * time.Millisecond}, send, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	upload, baseline, err := collector.captureInventory(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest := upload.begin.Manifest
	if len(manifest.Windows) != 10 || manifest.Windows[0].WatchProgressVersion != "20" ||
		manifest.Rows != 10 || len(upload.parts) != 1 {
		t.Fatal("capture did not preserve the expected inventory coverage", manifest)
	}
	addresses, relationships := map[string]string{}, map[string]string{}
	for _, row := range upload.parts[0].Rows {
		if address := row.GetAddress(); address != nil {
			addresses[address.Uid] = address.Address
		}
		if edge := row.GetRelationship(); edge != nil {
			relationships[edge.FromUid] = edge.ToUid
		}
	}
	if len(addresses) != 2 || addresses["pod-stable"] != "10.244.0.4" || addresses["svc-uid"] != "10.96.1.2" ||
		len(relationships) != 3 || relationships["svc-uid"] != "pod-stable" ||
		relationships["pod-stable"] != "rs-uid" || relationships["rs-uid"] != "deploy-uid" {
		t.Fatal("capture lost a stable ownership edge or bridged an IP handoff", addresses, relationships)
	}
	if err := upload.deliver(t.Context(), send); status.Code(err) != codes.Unavailable {
		t.Fatal("interrupted acknowledgement unexpectedly published inventory", err)
	}
	if err := upload.deliver(t.Context(), send); err != nil || begins != 2 || appends != 1 || publishes != 1 {
		t.Fatal("retry failed to resume the first retained part", err, begins, appends, publishes)
	}
	next, _, err := collector.captureInventory(ctx, baseline)
	if err != nil {
		t.Fatal(err)
	}
	window := next.begin.Manifest.Windows[0]
	if lists.Load() != 3 || serviceLists.Load() != 3 || podWatches.Load() != 2 || window.FirstListVersion != manifest.Windows[0].LastListVersion ||
		window.FirstReadCompleteUnixNano != baseline.pods.ReadCompletedAt.UnixNano() {
		t.Fatal("the next interval discarded the previous closing list", window)
	}
}
