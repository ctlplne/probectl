# MSP customer branding

Provider edition administrators can set a customer's product name, logo,
colors, and custom domain. This supersedes the white-label removal decision
of 2026-07-14 (F54). The tenant indicator and separate provider console remain.

## Change a customer's brand

Choose **Brand** beside the customer in the provider console. The editor
loads the current brand before a save can proceed. Tenant branding belongs
to that customer and changes only the allowed display fields:

- A display name of up to 120 bytes.
- An inline PNG logo of up to 32 KiB and 512 by 512 pixels.
- Allowlisted color overrides. Each value is a bare HSL triplet, such as
  `28 85% 30%`. The effective palette must pass contrast checks in light
  and dark. Core `PROBECTL_THEME_OVERRIDES` continues to provide the
  deployment defaults.
- One unique DNS hostname. Numeric IP aliases are rejected. Configure the
  customer's DNS, HTTPS certificate, and ingress before assigning the
  hostname. Pass the original `Host` to probectl. Register the same
  `https://<customer-host>/auth/callback` URL in the customer's SSO settings
  and at the IdP. probectl reserves the hostname in the deployment-level
  `PROBECTL_OIDC_REDIRECT_URL` for the shared console. An existing shared-console
  sign-in link that selects the customer opens the branded sign-in page on
  the customer host. The user selects **Sign in** there to start SSO.

For the built-in Helm ingress, keep `ingress.host` as the shared console and
list customer domains in `ingress.additionalHosts`. Each entry names a TLS
Secret in the same namespace. The ingress preserves the request hostname and
uses the same verified HTTPS backend for all hosts.

```yaml
ingress:
  additionalHosts:
    - host: portal.customer.example
      tlsSecretName: customer-portal-tls
```

An automation client can read `GET /provider/v1/tenants/{id}/brand` and
replace it with `PUT /provider/v1/tenants/{id}/brand`. Send the last strong
`ETag` in `If-Match` with the complete document. The initial revision is
`"0"`. A missing precondition returns 428. A stale revision or assigned domain
returns 409. A replacement writes its provider audit event in the same
transaction. Empty fields return the customer to the default presentation
and clear the hostname mapping.

`probectl provider brand <tenant-id>` returns the brand and its current
`revision`. Replace it with `probectl provider set-brand <tenant-id>
--revision <revision> --body-file <brand.json>`. The file contains the
complete brand document returned under `brand`.

## Sign-in and attribution

Before sign-in, `GET /branding` resolves a custom host by exact match. The
host selects the tenant when its sign-in button is used, including when a
bookmark carries an older tenant hint. The IdP and session still authenticate
the user and determine tenant access. A customer host refuses console API requests
that carry credentials from a different tenant. The domain remains reserved
while a customer is suspended. On a shared host, the authenticated tenant
selects the brand. Customer branding responses are private and non-cacheable.
The protected console applies a customer brand when the branding response and
`/v1/me` agree on the authenticated tenant. During a session change it shows
probectl branding until the current customer's presentation is available.
If a tenant is quarantined, the browser recovery page can show its published
name and fixed attribution from the same registered host.

Every customer brand is accompanied by **Powered by probectl**, linked to
[probectl.com](https://probectl.com). The customer console and sign-in display
it beside the customer's name. Alert and report emails contain a clickable
HTML badge and a plain-text URL. Each branded PDF page links to probectl
beside the customer's name and in the footer. When the bundled offline fonts
lack a character in the name, the PDF displays a question mark and preserves
the full name in its text layer. CSV reports carry the URL in their metadata
rows, and branded notifications
include the same attribution and URL. This also applies to on-call test
deliveries and notifications recovered after a restart. The badge uses fixed
probectl styling independent of the configured logo, palette and deployment
theme. The identity stays visible as the navigation links scroll on desktop
and in the mobile navigation drawer. On mobile it also sits above the
console controls.

Old branding rows start with revision zero and remain inert until a provider
administrator saves an approved brand. Core and Enterprise show the probectl
name and mark. See the [Additional Use Grant](../LICENSE) for the attribution
condition.
