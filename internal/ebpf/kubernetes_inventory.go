// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

const (
	kubernetesInventoryBudget = 64 << 20
	kubernetesWatchLease      = 75 * time.Second
	defaultKubernetesInterval = 15 * time.Second
	maxKubernetesPageItems    = 500
)

var (
	errKubernetesWatchCovered = errors.New("kubernetes: inventory watch covered the requested revision")
	errKubernetesCoverageGap  = errors.New("kubernetes: incomplete inventory ownership interval")
)

// KubernetesInventoryConfig gives the collector a namespace-local service
// account and its separate evidence-only mTLS credentials.
type KubernetesInventoryConfig struct {
	Namespace          string        `yaml:"namespace"`
	APIServer          string        `yaml:"api_server"`
	TokenFile          string        `yaml:"token_file"`
	CAFile             string        `yaml:"ca_file"`
	BindingID          string        `yaml:"binding_id"`
	Interval           time.Duration `yaml:"interval"`
	EvidenceGRPCAddr   string        `yaml:"evidence_grpc_addr"`
	EvidenceCertFile   string        `yaml:"evidence_cert_file"`
	EvidenceKeyFile    string        `yaml:"evidence_key_file"`
	EvidenceCAFile     string        `yaml:"evidence_ca_file"`
	EvidenceServerName string        `yaml:"evidence_server_name"`
}

func (c *Config) validateKubernetesInventory() error {
	settings := c.KubernetesInventory
	if settings == nil {
		return nil
	}
	if c.AgentID == "" || !kubernetesNamespace.MatchString(settings.Namespace) || settings.BindingID == "" ||
		settings.EvidenceGRPCAddr == "" || settings.EvidenceCertFile == "" || settings.EvidenceKeyFile == "" || settings.EvidenceCAFile == "" {
		return errors.New("kubernetes_inventory requires a registered collector, namespace, binding ID, and evidence mTLS endpoint and identity files")
	}
	if settings.Interval != 0 && settings.Interval < time.Second {
		return errors.New("kubernetes_inventory.interval must be at least one second")
	}
	return nil
}

type KubernetesInventoryCollector struct {
	reader    *kubernetesPodReader
	bindingID string
	interval  time.Duration
	send      func(context.Context, *agentv1.KubernetesInventoryUpload) (*agentv1.KubernetesInventoryReceipt, error)
	log       *slog.Logger
}

func NewKubernetesInventoryCollector(settings KubernetesInventoryConfig,
	send func(context.Context, *agentv1.KubernetesInventoryUpload) (*agentv1.KubernetesInventoryReceipt, error), log *slog.Logger,
) (*KubernetesInventoryCollector, error) {
	id, err := uuid.Parse(settings.BindingID)
	if err != nil || id == uuid.Nil || id.String() != settings.BindingID || send == nil || log == nil {
		return nil, errors.New("kubernetes inventory requires a current source binding and an evidence client")
	}
	reader, err := newKubernetesPodReader(settings.APIServer, settings.Namespace, settings.TokenFile, settings.CAFile,
		maxKubernetesPageItems, 10*time.Second)
	if err != nil {
		return nil, err
	}
	interval := settings.Interval
	if interval == 0 {
		interval = defaultKubernetesInterval
	}
	return &KubernetesInventoryCollector{reader: reader, bindingID: id.String(), interval: interval, send: send, log: log}, nil
}

// Run collects historical ownership intervals and keeps an identical pending
// upload across transient delivery failures. Incomplete capture is logged as
// a coverage gap independently of the ordinary eBPF telemetry loop.
func (c *KubernetesInventoryCollector) Run(ctx context.Context) {
	var pending *kubernetesPreparedUpload
	var baseline *kubernetesInventorySnapshot
	for ctx.Err() == nil {
		if pending == nil {
			upload, latest, err := c.captureInventory(ctx, baseline)
			baseline = latest
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				c.log.Warn("Kubernetes inventory interval unavailable", "binding_id", c.bindingID)
				if !waitKubernetesInventory(ctx, c.interval) {
					return
				}
				continue
			}
			pending = upload
		}
		if err := pending.deliver(ctx, c.send); err != nil {
			if ctx.Err() != nil {
				return
			}
			code := status.Code(err)
			c.log.Warn("Kubernetes inventory delivery unavailable", "binding_id", c.bindingID, "status", code.String())
			if errors.Is(err, errKubernetesCoverageGap) {
				pending = nil
			}
			switch code {
			case codes.FailedPrecondition, codes.InvalidArgument, codes.AlreadyExists, codes.PermissionDenied, codes.Unauthenticated:
				// A closed or invalid receipt needs a new source interval.
				pending = nil
			}
			if !waitKubernetesInventory(ctx, c.interval) {
				return
			}
			continue
		}
		pending = nil
	}
}

func (c *KubernetesInventoryCollector) closePodWindow(ctx context.Context, before, after kubernetesPodSnapshot) (*agentv1.KubernetesInventoryWindow, []*agentv1.KubernetesInventoryRow, error) {
	replay := kubernetesPodReplay{Namespace: before.Namespace, StartVersion: before.ResourceVersion}
	var progress string
	if before.ResourceVersion != after.ResourceVersion {
		err := tryKubernetesWatch(ctx, func(lease time.Duration) error {
			// The last revision may have been partially delivered when a lease
			// closed. Replay the full interval from the original LIST.
			replay.Changes = nil
			return c.reader.watch(ctx, before.ResourceVersion, lease, kubernetesInventoryBudget, func(change kubernetesPodChange) error {
				replay.Changes = append(replay.Changes, change)
				if kubernetesWatchCoversVersion(change, after.ResourceVersion) {
					progress = change.ResourceVersion
					return errKubernetesWatchCovered
				}
				return nil
			})
		})
		if !errors.Is(err, errKubernetesWatchCovered) {
			return nil, nil, errKubernetesCoverageGap
		}
	}
	addresses, covered := stableKubernetesPodAddresses(before, after, replay)
	if !covered {
		return nil, nil, errKubernetesCoverageGap
	}
	const pod = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_POD
	window := &agentv1.KubernetesInventoryWindow{Kind: pod, FirstListVersion: before.ResourceVersion,
		LastListVersion: after.ResourceVersion, WatchProgressVersion: progress,
		FirstReadCompleteUnixNano: before.ReadCompletedAt.UnixNano(), LastReadStartUnixNano: after.ReadStartedAt.UnixNano()}
	rows := kubernetesPodInventoryRows(before, after, addresses)
	return window, rows, nil
}

func kubernetesPodInventoryRows(before, after kubernetesPodSnapshot, intervals []kubernetesPodAddressInterval) []*agentv1.KubernetesInventoryRow {
	const kind = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_POD
	retained := make(map[string]kubernetesPodMetadata, len(before.Pods))
	for _, pod := range before.Pods {
		retained[pod.UID] = pod
	}
	var rows []*agentv1.KubernetesInventoryRow
	for _, pod := range after.Pods {
		prior := retained[pod.UID]
		if prior.Name == pod.Name {
			rows = append(rows, &agentv1.KubernetesInventoryRow{Record: &agentv1.KubernetesInventoryRow_Object{
				Object: &agentv1.KubernetesInventoryObject{Kind: kind, Uid: pod.UID, Name: pod.Name},
			}})
			if pod.ResourceVersion != "" && pod.ResourceVersion == prior.ResourceVersion && pod.Owner != nil &&
				prior.Owner != nil && *pod.Owner == *prior.Owner {
				if edge := kubernetesControllerInventoryRow(kind, pod.UID, pod.Owner, 0); edge != nil {
					rows = append(rows, edge)
				}
			}
		}
	}
	for _, interval := range intervals {
		rows = append(rows, &agentv1.KubernetesInventoryRow{Record: &agentv1.KubernetesInventoryRow_Address{
			Address: &agentv1.KubernetesInventoryAddress{Kind: kind, Uid: interval.Claim.UID, Address: interval.Address.String()},
		}})
	}
	return rows
}

func waitKubernetesInventory(ctx context.Context, interval time.Duration) bool {
	wait := time.NewTimer(interval)
	defer wait.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-wait.C:
		return true
	}
}
