// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"fmt"
	"html"
	"io"
	"mime/quotedprintable"

	"github.com/ctlplne/probectl/internal/branding"
	"github.com/ctlplne/probectl/internal/crypto"
)

func brandedMailText(customer, body string) string {
	return customer + "\n" + branding.Attribution + " (" + branding.AttributionURL + ")\n\n" + body
}

// writeBrandedMail emits both a plaintext URL and a fixed link for HTML
// clients. Customer text cannot introduce HTML, CSS, links or MIME headers.
func writeBrandedMail(target io.Writer, customer, body string) error {
	boundary, err := crypto.UUIDv4()
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(target, "Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", boundary); err != nil {
		return err
	}
	for _, part := range []struct{ mediaType, text string }{
		{"text/plain", brandedMailText(customer, body)},
		{"text/html", "<p><strong>" + html.EscapeString(customer) + "</strong> " +
			`<a href="` + branding.AttributionURL + `" style="color:#fffefa;background-color:#231b16;padding:2px 6px;border-radius:8px;">` +
			branding.Attribution + "</a></p><div style=\"white-space:pre-wrap\">" + html.EscapeString(body) + "</div>"},
	} {
		if _, err := fmt.Fprintf(target, "--%s\r\nContent-Type: %s; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", boundary, part.mediaType); err != nil {
			return err
		}
		encoded := quotedprintable.NewWriter(target)
		if _, err := io.WriteString(encoded, part.text); err != nil {
			return err
		}
		if err := encoded.Close(); err != nil {
			return err
		}
		if _, err := io.WriteString(target, "\r\n"); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(target, "--%s--\r\n", boundary)
	return err
}
