// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"html/template"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/ctlplne/probectl/internal/apierror"
)

// This emergency page needs no app bundle, scripts, remote assets or storage.
// Browser-native semantic HTML keeps recovery usable when tenant storage is held.
var quarantineLoginPage = template.Must(template.New("quarantine-login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign-in temporarily unavailable · probectl</title></head>
<body><main><p>probectl</p><h1>Sign-in temporarily unavailable</h1>
<p>{{.Message}}</p><p>Error: <code>{{.Code}}</code></p>
{{if .RequestID}}<p>Request ID: <code>{{.RequestID}}</code></p>{{end}}
<p>Contact your deployment operator. After the tenant is restored, retry sign-in.</p>
<nav aria-label="Sign-in recovery"><a href="{{.Retry}}">Retry sign-in</a> · <a href="{{.Console}}">Return to console</a></nav>
</main></body></html>`))

// writeQuarantineLoginPage changes only a browser's login refusal presentation.
// The 503 and quarantine enforcement remain unchanged; API callers retain JSON.
func writeQuarantineLoginPage(w http.ResponseWriter, r *http.Request, domain *apierror.Error, requestID string) bool {
	if r.Method != http.MethodGet || r.URL.Path != "/auth/login" || domain.Code != string(apierror.CodeTenantQuarantined) {
		return false
	}
	acceptsHTML := false
	for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
		media, params, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil || media != "text/html" {
			continue
		}
		quality := 1.0
		if raw, ok := params["q"]; ok {
			quality, err = strconv.ParseFloat(raw, 64)
			if err != nil {
				continue
			}
		}
		if quality > 0 && quality <= 1 {
			acceptsHTML = true
		}
	}
	if !acceptsHTML {
		return false
	}
	retry, console := "/auth/login", "/ui/"
	// Keep only the validated public routing hint, never callback credentials,
	// arbitrary return destinations or the rest of the incoming query string.
	if tenant := r.URL.Query().Get("tenant"); uuidRe.MatchString(tenant) {
		retry += "?tenant=" + tenant
		console += "?login_tenant=" + tenant
	}
	var body bytes.Buffer
	if err := quarantineLoginPage.Execute(&body, struct{ Message, Code, RequestID, Retry, Console string }{domain.Message, domain.Code, requestID, retry, console}); err != nil {
		return false
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Add("Vary", "Accept")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write(body.Bytes())
	return true
}
