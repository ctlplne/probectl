// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Shared `no-restricted-syntax` selectors, so the lint config
// (web/eslint.config.js) and the WEB-27 self-test gate
// (scripts/check_web_no_danger.mjs) enforce the EXACT same rules and cannot
// drift apart. Each selector is an esquery AST query plus the operator message.
export const restrictedSyntax = [
  {
    // UX-006: apiFetch already prepends the /v1 API base, so a literal
    // apiFetch('/v1/...') produces a /v1/v1/... double-prefix (UX-001). Ban the
    // literal at lint time; off-/v1 surfaces use publicFetch instead.
    selector:
      "CallExpression[callee.name='apiFetch'] > Literal.arguments:first-child[value=/^\\/v1(\\/|$)/]",
    message:
      'apiFetch path must be relative to API_BASE — drop the /v1 prefix (it is prepended). Use publicFetch for off-/v1 surfaces. (UX-006)',
  },
  {
    selector:
      "CallExpression[callee.name='apiFetch'] > TemplateLiteral.arguments:first-child > TemplateElement:first-child[value.raw=/^\\/v1(\\/|$)/]",
    message:
      'apiFetch path must be relative to API_BASE — drop the /v1 prefix (it is prepended). Use publicFetch for off-/v1 surfaces. (UX-006)',
  },
  // WEB-27 (docs/guardrails.md G2 no phone-home / G12 outbound): a hardcoded
  // absolute http(s):// fetch target is an exfiltration risk — same-origin API
  // traffic goes through apiFetch/publicFetch. Ban the literal and
  // template-literal forms at lint time.
  {
    selector:
      "CallExpression[callee.name='fetch'] > Literal.arguments:first-child[value=/^https?:\\/\\//]",
    message:
      'fetch() must not target an absolute http(s):// URL — use apiFetch/publicFetch for same-origin calls. (WEB-27)',
  },
  {
    selector:
      "CallExpression[callee.name='fetch'] > TemplateLiteral.arguments:first-child > TemplateElement:first-child[value.raw=/^https?:\\/\\//]",
    message:
      'fetch() must not target an absolute http(s):// URL — use apiFetch/publicFetch for same-origin calls. (WEB-27)',
  },
  // WEB-27: ban the dangerouslySetInnerHTML XSS sink in both the JSX attribute
  // form and the createElement/object-prop form.
  {
    selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
    message:
      'dangerouslySetInnerHTML is banned — render text, or sanitize through the approved helper. (WEB-27)',
  },
  {
    selector: "Property[key.name='dangerouslySetInnerHTML']",
    message:
      'dangerouslySetInnerHTML is banned — render text, or sanitize through the approved helper. (WEB-27)',
  },
]
