// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrKubernetesQueryScope = errors.New("current tenant, raw collector and inventory authority are required for Kubernetes attribution")

type KubernetesFlowEndpoint struct {
	Cluster, Namespace    string
	Pod, PodUID           string
	Workload, WorkloadUID string
	Service, ServiceUID   string
}

type KubernetesFlowProjection struct {
	entity.Scope
	Capture             RoutingCaptureRead
	Source, Destination KubernetesFlowEndpoint
}

type kubernetesFlowFields struct {
	timing FlowCaptureTiming
	fields map[string]string
}

type KubernetesQueryData struct {
	tenant, digest string
	byKey          map[routingQueryKey]kubernetesFlowFields
	wire           []byte
}

// NewKubernetesQueryData validates the complete server-authorized projection
// before it can be used by either backend. A stored row must match the original
// capture key, capture clock and all raw event-clock coordinates.
func NewKubernetesQueryData(ctx context.Context, tenant string, rows []KubernetesFlowProjection, memory int64) (*KubernetesQueryData, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenant || !validTagProjectionID(tenant) {
		return nil, ErrKubernetesQueryScope
	}
	if memory < 4096 || int64(len(rows)) > (memory-4096)/2048 {
		return nil, ErrExplorerBudget
	}
	memory -= 4096 + int64(len(rows))*2048
	inputs := slices.Clone(rows)
	slices.SortFunc(inputs, func(a, b KubernetesFlowProjection) int {
		return slices.Compare(a.Capture.Ref.Key[:], b.Capture.Ref.Key[:])
	})
	data := &KubernetesQueryData{tenant: tenant, byKey: make(map[routingQueryKey]kubernetesFlowFields, len(rows))}
	var wire bytes.Buffer
	for _, row := range inputs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key, values, err := validatedKubernetesFlowFields(row, tenant)
		if err != nil {
			return nil, err
		}
		if _, duplicate := data.byKey[key]; duplicate {
			return nil, ErrKubernetesQueryScope
		}
		data.byKey[key] = values
		body, err := encodeKubernetesFlowFields(row.Scope, key, values)
		if err != nil {
			return nil, err
		}
		if int64(len(body)+1) > memory {
			return nil, ErrExplorerBudget
		}
		memory -= int64(len(body) + 1)
		wire.Write(body)
		wire.WriteByte('\n')
	}
	data.wire = wire.Bytes()
	digest, err := crypto.HashReader(io.MultiReader(strings.NewReader("probectl/kubernetes-flow/v1:"+tenant+"\n"), bytes.NewReader(data.wire)))
	if err != nil {
		return nil, err
	}
	data.digest = hex.EncodeToString(digest)
	return data, ctx.Err()
}

func validatedKubernetesFlowFields(row KubernetesFlowProjection, tenant string) (routingQueryKey, kubernetesFlowFields, error) {
	scope, err := row.Normalize()
	if err != nil || scope != row.Scope || scope.TenantID != tenant {
		return routingQueryKey{}, kubernetesFlowFields{}, ErrKubernetesQueryScope
	}
	ref := row.Capture
	key, err := entity.FlowCaptureKey(tenant, ref.Sender, ref.Witness.RawDigest, ref.Witness.Input)
	clock := ref.Ref.CapturedAt.UnixNano()
	if err != nil || key != ref.Ref.Key || clock <= 0 || !time.Unix(0, clock).Equal(ref.Ref.CapturedAt) {
		return routingQueryKey{}, kubernetesFlowFields{}, ErrKubernetesQueryScope
	}
	if _, _, usable := ref.Timing.ObservationRange(ref.Witness.Input.Protocol, 0); !usable {
		return routingQueryKey{}, kubernetesFlowFields{}, ErrKubernetesQueryScope
	}
	fields, err := kubernetesEndpointFields("src", row.Source)
	if err != nil {
		return routingQueryKey{}, kubernetesFlowFields{}, err
	}
	dst, err := kubernetesEndpointFields("dst", row.Destination)
	if err != nil {
		return routingQueryKey{}, kubernetesFlowFields{}, err
	}
	maps.Copy(fields, dst)
	return routingQueryKey{key: key, clock: clock}, kubernetesFlowFields{timing: ref.Timing, fields: fields}, nil
}

func kubernetesEndpointFields(side string, endpoint KubernetesFlowEndpoint) (map[string]string, error) {
	fields := make(map[string]string)
	if endpoint == (KubernetesFlowEndpoint{}) {
		return fields, nil
	}
	if !validTagProjectionID(endpoint.Cluster) || endpoint.Namespace == "" || len(endpoint.Namespace) > 63 ||
		(endpoint.Pod == "") != (endpoint.PodUID == "") || (endpoint.Service == "") != (endpoint.ServiceUID == "") ||
		(endpoint.Workload == "") != (endpoint.WorkloadUID == "") || endpoint.Pod == "" && endpoint.Workload != "" ||
		(endpoint.Pod == "") == (endpoint.Service == "") {
		return nil, ErrKubernetesQueryScope
	}
	for name, value := range map[string]string{"cluster": endpoint.Cluster, "namespace": endpoint.Namespace,
		"pod": endpoint.Pod, "pod_uid": endpoint.PodUID, "workload": endpoint.Workload, "workload_uid": endpoint.WorkloadUID,
		"service": endpoint.Service, "service_uid": endpoint.ServiceUID} {
		if len(value) > 256 {
			return nil, ErrKubernetesQueryScope
		}
		if value != "" {
			fields[side+"_k8s_"+name] = value
		}
	}
	return fields, nil
}

func encodeKubernetesFlowFields(scope entity.Scope, key routingQueryKey, value kubernetesFlowFields) ([]byte, error) {
	return json.Marshal(struct {
		Tenant  string            `json:"kube_tenant"`
		Context string            `json:"kube_context"`
		Key     string            `json:"kube_key"`
		Clock   string            `json:"kube_capture_ns"`
		Start   string            `json:"kube_start_ms"`
		End     string            `json:"kube_end_ms"`
		Basis   int32             `json:"kube_basis"`
		Fields  map[string]string `json:"kube_values"`
	}{scope.TenantID, scope.ContextID, hex.EncodeToString(key.key[:]), strconv.FormatInt(key.clock, 10),
		strconv.FormatInt(value.timing.Start.UnixMilli(), 10), strconv.FormatInt(value.timing.End.UnixMilli(), 10),
		int32(value.timing.Basis), value.fields})
}

func (data *KubernetesQueryData) Digest(ctx context.Context, tenant string) (string, error) {
	bound, present := tenancy.FromContext(ctx)
	if data == nil || !present || bound.String() != tenant || data.tenant != tenant || data.digest == "" {
		return "", ErrKubernetesQueryScope
	}
	return data.digest, ctx.Err()
}

func (data *KubernetesQueryData) valueForRow(row Row, field string) string {
	if data == nil || row.TenantID != data.tenant || row.RoutingCaptureKey == "" {
		return ""
	}
	ref, err := routingReadFromRow(row)
	if err != nil {
		return ""
	}
	found, present := data.byKey[routingQueryKey{key: ref.Ref.Key, clock: row.RoutingCapturedUnixNanos}]
	if !present || row.ClockBasis != found.timing.Basis || row.StartTS.UnixMilli() != found.timing.Start.UnixMilli() ||
		row.TS.UnixMilli() != found.timing.End.UnixMilli() {
		return ""
	}
	return found.fields[field]
}

func planKubernetesJoinSQL(from string, plan flow.QueryPlan) string {
	if !flow.PlanUsesKubernetes(plan) {
		return from
	}
	return from + " ANY LEFT JOIN kubernetes_capture_lookup AS kube ON kube.kube_tenant=tenant_id" +
		" AND kube.kube_key=routing_capture_key AND kube.kube_capture_ns=routing_captured_unix_nanos" +
		" AND kube.kube_start_ms=toUnixTimestamp64Milli(start_ts) AND kube.kube_end_ms=toUnixTimestamp64Milli(ts)" +
		" AND kube.kube_basis=clock_basis"
}
