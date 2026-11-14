// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"strings"
	"time"
	"unicode"

	"github.com/ctlplne/probectl/internal/crypto"
)

// MailAttachment is a complete, already-verified report body. Its stable ID
// gives relays/recipients a duplicate hint; SMTP acknowledgement loss still
// makes external delivery at least once, never an exactly-once guarantee.
type MailAttachment struct {
	Filename, MediaType, MessageID string
	Bytes                          int64
	Body                           io.Reader
}

// AttachmentMailSender extends the existing tenant-configured SMTP transport.
// The source must be fully staged and authorized before opening a session.
type AttachmentMailSender interface {
	MailSender
	SendAttachment(context.Context, []string, string, MailAttachment) error
}

func (s *SMTPSender) SendAttachment(ctx context.Context, to []string, subject string, attachment MailAttachment) error {
	if attachment.Body == nil || attachment.Bytes <= 0 || (attachment.MediaType != "application/pdf" && attachment.MediaType != "text/csv") || attachment.Filename == "" || attachment.MessageID == "" {
		return fmt.Errorf("smtp: complete report metadata required")
	}
	for _, value := range []string{attachment.Filename, attachment.MessageID} {
		if strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return fmt.Errorf("smtp: report metadata contains a control character")
		}
	}
	boundary, err := crypto.UUIDv4()
	if err != nil {
		return err
	}
	return s.send(ctx, to, func(target io.Writer) error {
		if _, err := fmt.Fprintf(target, "From: %s\r\nDate: %s\r\n", headerValue(s.from), time.Now().UTC().Format(time.RFC1123Z)); err != nil {
			return err
		}
		if err := writeReportRecipients(target, to); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(target, "Subject: %s\r\nMessage-ID: %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n", encodedSubject(subject), attachment.MessageID, boundary); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(target, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nYour probectl report is attached. Access and retention remain governed by your tenant.\r\n\r\n--%s\r\nContent-Type: %s\r\nContent-Disposition: %s\r\nContent-Transfer-Encoding: base64\r\n\r\n", boundary, boundary, attachment.MediaType, mime.FormatMediaType("attachment", map[string]string{"filename": attachment.Filename})); err != nil {
			return err
		}
		lines := &mailBase64Lines{target: target}
		encoder := base64.NewEncoder(base64.StdEncoding, lines)
		if _, err := io.CopyN(encoder, attachment.Body, attachment.Bytes); err != nil {
			return fmt.Errorf("smtp: report body incomplete: %w", err)
		}
		var extra [1]byte
		if n, err := attachment.Body.Read(extra[:]); n != 0 || err != io.EOF {
			return fmt.Errorf("smtp: report body differs from verified length")
		}
		if err := encoder.Close(); err != nil {
			return err
		}
		if lines.column != 0 {
			if _, err := io.WriteString(target, "\r\n"); err != nil {
				return err
			}
		}
		_, err := fmt.Fprintf(target, "--%s--\r\n", boundary)
		return err
	})
}

// RFC2045 line folding streams the complete body without a second full-size
// base64 allocation. There is no attachment-size ceiling below report admission.
type mailBase64Lines struct {
	target io.Writer
	column int
}

func (w *mailBase64Lines) Write(body []byte) (int, error) {
	consumed := 0
	for len(body) > 0 {
		n := min(76-w.column, len(body))
		written, err := w.target.Write(body[:n])
		consumed += written
		w.column += written
		body = body[written:]
		if err != nil {
			return consumed, err
		}
		if written != n {
			return consumed, io.ErrShortWrite
		}
		if w.column == 76 {
			if _, err := io.WriteString(w.target, "\r\n"); err != nil {
				return consumed, err
			}
			w.column = 0
		}
	}
	return consumed, nil
}

// Fold complete recipient headers instead of truncating a route's recipient
// population to the short-label budget used by alert subjects.
func writeReportRecipients(target io.Writer, recipients []string) error {
	if _, err := io.WriteString(target, "To: "); err != nil {
		return err
	}
	column := 4
	for i, recipient := range recipients {
		parsed, err := mail.ParseAddress(recipient)
		if err != nil || parsed.Address != recipient || strings.ContainsAny(recipient, "\r\n") {
			return fmt.Errorf("smtp: invalid report recipient")
		}
		if i > 0 {
			if _, err := io.WriteString(target, ", "); err != nil {
				return err
			}
			column += 2
		}
		if column+len(recipient) > 78 {
			if _, err := io.WriteString(target, "\r\n "); err != nil {
				return err
			}
			column = 1
		}
		if _, err := io.WriteString(target, recipient); err != nil {
			return err
		}
		column += len(recipient)
	}
	_, err := io.WriteString(target, "\r\n")
	return err
}
