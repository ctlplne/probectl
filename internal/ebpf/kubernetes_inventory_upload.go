// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"bytes"
	"context"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

type kubernetesPreparedUpload struct {
	bindingID, generationID string
	begin                   *agentv1.KubernetesInventoryBegin
	parts                   []*agentv1.KubernetesInventoryPart
}

func prepareKubernetesInventoryUpload(bindingID string, windows []*agentv1.KubernetesInventoryWindow,
	rows []*agentv1.KubernetesInventoryRow) (*kubernetesPreparedUpload, error) {
	if len(windows) == 0 || len(rows) > entity.KubernetesInventoryGenerationRows {
		return nil, errKubernetesCoverageGap
	}
	random, err := crypto.Random(16)
	if err != nil {
		return nil, err
	}
	generation, err := uuid.NewRandomFromReader(bytes.NewReader(random))
	if err != nil {
		return nil, err
	}
	upload := &kubernetesPreparedUpload{bindingID: bindingID, generationID: generation.String()}
	manifest := &agentv1.KubernetesInventoryManifest{Rows: uint64(len(rows)), Windows: windows}
	for first := 0; first < len(rows); first += entity.KubernetesInventoryPartRows {
		end := min(first+entity.KubernetesInventoryPartRows, len(rows))
		part := &agentv1.KubernetesInventoryPart{Index: manifest.Parts, Rows: rows[first:end]}
		manifest.PayloadBytes += uint64(proto.Size(part))
		if manifest.PayloadBytes > entity.KubernetesInventoryGenerationBytes {
			return nil, errKubernetesCoverageGap
		}
		manifest.Parts++
		upload.parts = append(upload.parts, part)
	}
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	digest, err := entity.HashKubernetesInventory(wire, &kubernetesUploadPartsReader{parts: upload.parts})
	if err != nil {
		return nil, err
	}
	upload.begin = &agentv1.KubernetesInventoryBegin{Manifest: manifest, PayloadDigest: digest}
	return upload, nil
}

func (u *kubernetesPreparedUpload) deliver(ctx context.Context,
	send func(context.Context, *agentv1.KubernetesInventoryUpload) (*agentv1.KubernetesInventoryReceipt, error)) error {
	request := &agentv1.KubernetesInventoryUpload{BindingId: u.bindingID, GenerationId: u.generationID,
		Operation: &agentv1.KubernetesInventoryUpload_Begin{Begin: u.begin}}
	call := func() (*agentv1.KubernetesInventoryReceipt, error) {
		if proto.Size(&agentv1.SubmitEntityEvidenceRequest{KubernetesInventory: request}) > entity.KubernetesInventoryRequestBytes {
			return nil, errKubernetesCoverageGap
		}
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		return send(ctx, request)
	}
	ack, err := call()
	if err != nil {
		return err
	}
	if ack == nil || ack.NextPart > u.begin.Manifest.Parts || !bytes.Equal(ack.PayloadDigest, u.begin.PayloadDigest) {
		return errKubernetesCoverageGap
	}
	if ack.Published {
		return u.requirePublished(ack)
	}
	for index := ack.NextPart; index < u.begin.Manifest.Parts; index++ {
		request.Operation = &agentv1.KubernetesInventoryUpload_Append{Append: u.parts[index]}
		ack, err := call()
		if err != nil {
			return err
		}
		if ack == nil || ack.NextPart != index+1 || ack.Published {
			return errKubernetesCoverageGap
		}
	}
	request.Operation = &agentv1.KubernetesInventoryUpload_Publish{Publish: &agentv1.KubernetesInventoryPublish{}}
	ack, err = call()
	if err != nil {
		return err
	}
	return u.requirePublished(ack)
}

func (u *kubernetesPreparedUpload) requirePublished(ack *agentv1.KubernetesInventoryReceipt) error {
	if ack == nil || !ack.Published || ack.NextPart != u.begin.Manifest.Parts || ack.RetainedRows != u.begin.Manifest.Rows ||
		!bytes.Equal(ack.PayloadDigest, u.begin.PayloadDigest) {
		return errKubernetesCoverageGap
	}
	return nil
}

type kubernetesUploadPartsReader struct {
	parts   []*agentv1.KubernetesInventoryPart
	current io.Reader
}

func (r *kubernetesUploadPartsReader) Read(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	for {
		if r.current != nil {
			n, err := r.current.Read(payload)
			if !errors.Is(err, io.EOF) {
				return n, err
			}
			r.current = nil
			if n > 0 {
				return n, nil
			}
		}
		if len(r.parts) == 0 {
			return 0, io.EOF
		}
		wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(r.parts[0])
		if err != nil {
			return 0, err
		}
		r.parts = r.parts[1:]
		r.current = entity.FrameKubernetesInventoryRecord(wire)
	}
}
