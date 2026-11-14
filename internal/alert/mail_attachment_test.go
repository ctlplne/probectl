// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"
)

func TestSMTPReportAttachmentsKeepCompleteBinaryOverTLS(t *testing.T) {
	for _, mode := range []SMTPTLSMode{SMTPStartTLS, SMTPImplicitTLS} {
		t.Run(string(mode), func(t *testing.T) {
			serverCfg, clientCfg := serverTLS(t, []string{"127.0.0.1"})
			server := newFakeSMTP(t, serverCfg, mode == SMTPImplicitTLS)
			sender := NewSMTPSender(server.addr(), "reports@example.test", nil, mode, clientCfg)
			body := bytes.Repeat([]byte{0, 0xff, 0x0a, 'a', 'b', 'c'}, 600000)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			attachment := MailAttachment{Filename: "monthly-東京.pdf", MediaType: "application/pdf", MessageID: "<probectl-report-proof@example.test>", Bytes: int64(len(body)), Body: bytes.NewReader(body)}
			recipients := make([]string, 24)
			for i := range recipients {
				recipients[i] = fmt.Sprintf("client-accounting-%02d@example.test", i)
			}
			if err := sender.SendAttachment(ctx, recipients, "Monthly client report", attachment); err != nil {
				t.Fatal(err)
			}
			server.mu.Lock()
			raw := server.data
			plain := server.plaintextMailFrom
			server.mu.Unlock()
			if plain {
				t.Fatal("report envelope sent before TLS")
			}
			message, err := mail.ReadMessage(strings.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			addresses, err := mail.ParseAddressList(message.Header.Get("To"))
			if err != nil || len(addresses) != len(recipients) {
				t.Fatal("report recipient header truncated", err)
			}
			for i, address := range addresses {
				if address.Address != recipients[i] {
					t.Fatal("report recipient changed")
				}
			}
			if _, err := mail.ParseDate(message.Header.Get("Date")); err != nil {
				t.Fatal("report message has no valid date", err)
			}
			if message.Header.Get("Message-ID") != attachment.MessageID {
				t.Fatal("report retry identity lost")
			}
			kind, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
			if err != nil || kind != "multipart/mixed" {
				t.Fatal("report MIME envelope invalid", err)
			}
			parts := multipart.NewReader(message.Body, params["boundary"])
			first, err := parts.NextPart()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(io.Discard, first); err != nil {
				t.Fatal(err)
			}
			part, err := parts.NextPart()
			if err != nil {
				t.Fatal(err)
			}
			_, disposition, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
			if err != nil || disposition["filename"] != attachment.Filename || part.Header.Get("Content-Type") != attachment.MediaType {
				t.Fatal("report attachment metadata changed", err)
			}
			decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, part))
			if err != nil || !bytes.Equal(decoded, body) {
				t.Fatal("report attachment truncated or changed", err)
			}
			if _, err := parts.NextPart(); err != io.EOF {
				t.Fatal("report MIME has extra or incomplete parts", err)
			}
		})
	}
}
func TestSMTPReportRefusesIncompleteOrAmbiguousBodies(t *testing.T) {
	serverCfg, clientCfg := serverTLS(t, []string{"127.0.0.1"})
	server := newFakeSMTP(t, serverCfg, true)
	sender := NewSMTPSender(server.addr(), "reports@example.test", nil, SMTPImplicitTLS, clientCfg)
	for _, tc := range []struct {
		body  string
		bytes int64
	}{{"short", 6}, {"extra", 4}} {
		attachment := MailAttachment{Filename: "report.csv", MediaType: "text/csv", MessageID: "<report-proof@example.test>", Bytes: tc.bytes, Body: strings.NewReader(tc.body)}
		if err := sender.SendAttachment(t.Context(), []string{"client@example.test"}, "report", attachment); err == nil {
			t.Fatal("mismatched complete report length accepted")
		}
	}
}
