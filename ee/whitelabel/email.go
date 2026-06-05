// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package whitelabel

import (
	"bytes"
	"fmt"
	"html/template"

	"github.com/imfeelingtheagi/probectl/internal/branding"
)

// Branded email-notification templates (S-T4). probectl has no SMTP sender
// yet (notifications ride Slack/Teams/PagerDuty/ServiceNow/Jira — S33), so
// this is the TEMPLATE CONTRACT: when an email channel lands it renders
// through here and is branded for free. The renderer is strict
// html/template — every brand field is escaped; the logo is an inline data
// URI already validated by the core branding contract (no external fetches
// in mail clients, sovereignty-style).

// Email is one renderable notification.
type Email struct {
	Subject   string
	Preheader string
	BodyHTML  template.HTML // produced by probectl templates, never user input
}

const emailTemplate = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>{{.Subject}}</title></head>
<body style="margin:0;padding:24px;background:#f4f5f7;font-family:Arial,Helvetica,sans-serif;color:#1a1d24;">
<span style="display:none;max-height:0;overflow:hidden;">{{.Preheader}}</span>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0">
<tr><td align="center">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;padding:32px;">
<tr><td style="padding-bottom:16px;">
{{if .LogoDataURI}}<img src="{{.LogoDataURI}}" alt="{{.ProductName}}" height="32" style="display:block;">{{else}}<strong style="font-size:18px;">{{.ProductName}}</strong>{{end}}
</td></tr>
<tr><td style="font-size:16px;line-height:1.5;">{{.Body}}</td></tr>
<tr><td style="padding-top:24px;font-size:12px;color:#6b7280;">
{{if .EmailFooter}}{{.EmailFooter}}{{else}}Sent by {{.ProductName}}.{{end}}
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>`

var emailTmpl = template.Must(template.New("email").Parse(emailTemplate))

// RenderEmail wraps a notification body in the tenant's brand. From returns
// the branded From display name ("" falls back to the product name).
func RenderEmail(b branding.Branding, e Email) (html, from string, err error) {
	if b.ProductName == "" {
		b = branding.Default()
	}
	// The logo is a data: URI that the core branding contract has already
	// validated (strict data:image/(png|jpeg|svg+xml);base64 regex), so it is
	// safe to mark as a URL — html/template would otherwise rewrite data:
	// schemes to #ZgotmplZ.
	if branding.ValidateLogo(b.LogoDataURI) != nil {
		b.LogoDataURI = "" // defense in depth: never emit an unvalidated URI
	}
	var buf bytes.Buffer
	data := struct {
		Subject, Preheader, ProductName, EmailFooter string
		LogoDataURI                                  template.URL
		Body                                         template.HTML
	}{
		Subject:     e.Subject,
		Preheader:   e.Preheader,
		ProductName: b.ProductName,
		LogoDataURI: template.URL(b.LogoDataURI),
		EmailFooter: b.EmailFooter,
		Body:        e.BodyHTML,
	}
	if err := emailTmpl.Execute(&buf, data); err != nil {
		return "", "", fmt.Errorf("whitelabel: render email: %w", err)
	}
	from = b.EmailFromName
	if from == "" {
		from = b.ProductName
	}
	return buf.String(), from, nil
}
