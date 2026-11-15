// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package evidence

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/ctlplne/probectl/internal/crypto"
)

// AttachmentSource owns already-redacted JSON in a sealed operation-local
// stage. Open supplies the exact content-addressed bytes, never a URL or a
// retained authorization grant. It must remain valid through WriteSigned.
type AttachmentSource struct {
	Digest    string
	MediaType string
	Bytes     int64
	Open      func(context.Context) (io.ReadCloser, error)
}

// WriteSigned preserves the existing portable JSON wire form while copying
// complete sealed attachments without an extra whole-body byte slice. It
// verifies each copied digest and exact size through the configured crypto
// provider. The caller stages the output and discards it on any error; a
// partially written package must never be published as a successful artifact.
func WriteSigned(ctx context.Context, target io.Writer, manifest Manifest, sources []AttachmentSource, privatePEM []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if target == nil {
		return errors.New("evidence: complete output writer is required")
	}
	target = evidenceExactWriter{target}
	signed, err := Sign(manifest, nil, privatePEM)
	if err != nil {
		return err
	}
	var shell Package
	if err := json.Unmarshal(signed, &shell); err != nil {
		return err
	}
	if _, err := verifyManifest(shell.Manifest, shell.Signing); err != nil {
		return err
	}
	available := map[string]bool{}
	for _, source := range sources {
		if source.Digest == "" || available[source.Digest] || source.MediaType == "" || source.Bytes <= 0 || source.Bytes == int64(^uint64(0)>>1) || source.Open == nil {
			return errors.New("evidence: complete distinct attachment stages are required")
		}
		available[source.Digest] = true
	}
	if err := verifyReferences(manifest, available); err != nil {
		return err
	}
	for _, source := range sources {
		if err := validateAttachmentSource(ctx, source); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(target, `{"manifest":`); err != nil {
		return err
	}
	if _, err := target.Write(shell.Manifest); err != nil {
		return err
	}
	if _, err := io.WriteString(target, `,"attachments":[`); err != nil {
		return err
	}
	for index, source := range sources {
		if err := ctx.Err(); err != nil {
			return err
		}
		if index > 0 {
			if _, err := io.WriteString(target, ","); err != nil {
				return err
			}
		}
		if err := writeSignedAttachment(ctx, target, source); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(target, `],"signing":`); err != nil {
		return err
	}
	if err := json.NewEncoder(target).Encode(shell.Signing); err != nil {
		return err
	}
	_, err = io.WriteString(target, "}")
	return err
}

func writeSignedAttachment(ctx context.Context, target io.Writer, source AttachmentSource) error {
	header, err := json.Marshal(struct {
		Digest    string `json:"digest"`
		MediaType string `json:"media_type"`
	}{source.Digest, source.MediaType})
	if err != nil {
		return err
	}
	if _, err := target.Write(header[:len(header)-1]); err != nil {
		return err
	}
	if _, err := io.WriteString(target, `,"content":`); err != nil {
		return err
	}
	reader, err := source.Open(ctx)
	if err != nil {
		return err
	}
	if reader == nil {
		return errors.New("evidence: attachment stage reader is unavailable")
	}
	defer reader.Close()
	counted := &evidenceCopyReader{ctx: ctx, reader: io.LimitReader(reader, source.Bytes+1)}
	digest, err := crypto.HashReader(io.TeeReader(counted, target))
	if err != nil {
		return err
	}
	if counted.bytes != source.Bytes || DigestAlgorithm+":"+hex.EncodeToString(digest) != source.Digest {
		return errors.New("evidence: sealed attachment changed during complete copy")
	}
	if strings.ContainsRune(" \r\n\t", rune(counted.first)) || strings.ContainsRune(" \r\n\t", rune(counted.last)) {
		return errors.New("evidence: attachment JSON has bytes outside its content value")
	}
	_, err = io.WriteString(target, "}")
	return err
}

type evidenceCopyReader struct {
	ctx         context.Context
	reader      io.Reader
	bytes       int64
	first, last byte
}

func (r *evidenceCopyReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(p)
	if n > 0 {
		if r.bytes == 0 {
			r.first = p[0]
		}
		r.last = p[n-1]
	}
	r.bytes += int64(n)
	return n, err
}

func validateAttachmentSource(ctx context.Context, source AttachmentSource) error {
	reader, err := source.Open(ctx)
	if err != nil {
		return err
	}
	if reader == nil {
		return errors.New("evidence: attachment stage reader is unavailable")
	}
	defer reader.Close()
	counted := &evidenceCopyReader{ctx: ctx, reader: io.LimitReader(reader, source.Bytes+1)}
	decoder := json.NewDecoder(counted)
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return err
	}
	depth := 0
	if delimiter, ok := first.(json.Delim); ok {
		if delimiter != '{' && delimiter != '[' {
			return errors.New("evidence: malformed attachment JSON")
		}
		depth = 1
	}
	for depth > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("evidence: attachment JSON has trailing values")
	}
	if counted.bytes != source.Bytes || strings.ContainsRune(" \r\n\t", rune(counted.first)) || strings.ContainsRune(" \r\n\t", rune(counted.last)) {
		return errors.New("evidence: attachment stage size or exact JSON boundary changed")
	}
	return ctx.Err()
}

type evidenceExactWriter struct{ io.Writer }

func (w evidenceExactWriter) Write(value []byte) (int, error) {
	n, err := w.Writer.Write(value)
	if err == nil && n != len(value) {
		err = io.ErrShortWrite
	}
	return n, err
}
