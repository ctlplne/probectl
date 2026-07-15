# Keyboard command reference

<!-- Generated from web/src/shell/journeyCommands.ts; do not hand-edit. -->

The command palette opens with `Ctrl+K` or `⌘K`. Commands preserve the safe X3 clock, filters, and authorized selection, but never encode `tenant_id`. Unavailable or unauthorized commands remain visible with a reason. Provider commands cross into the separately authenticated provider privilege domain.

<!-- prettier-ignore -->
| Journey | Action                                            | Stable command / shortcut                                                         | Observable result                                                                         |
| ------- | ------------------------------------------------- | --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| J1      | Open the first-real-insight workflow              | Ctrl/⌘+K → Start first real insight → Enter                                       | Guided onboarding opens without carrying a stale object selection.                        |
| J1      | Mint the one-time enrollment token                | Tab to Mint enrollment token → Enter                                              | A human explicitly creates the short-lived enrollment credential.                         |
| J1      | Copy the tenant-bound agent command               | Tab to Copy command → Enter                                                       | The shell command is copied; secrets are not counted or echoed.                           |
| J1      | Create the default real test and open its finding | Tab through native fields → Enter on Create test; Enter on the finding link       | Producer health and the named first server finding are distinct receipts.                 |
| J2      | Open the incident RCA workspace                   | Ctrl/⌘+K → Open incident RCA → Enter                                              | Incident, absolute clock, filters, and authorized evidence stay in X3 context.            |
| J2      | Select evidence and generate cited RCA            | Tab to evidence → Enter; Tab to Explain this view → Enter                         | The selected evidence and server-authored reasoning provenance remain visible.            |
| J2      | Open the exact citation                           | Tab to the citation → Enter                                                       | Focus moves to the cited, tenant-authorized evidence row.                                 |
| J2      | Copy the fixed cited snapshot                     | Ctrl/⌘+K → Share cited incident RCA → Enter                                       | The copied URL contains only a random share artifact ID.                                  |
| J3      | Open canonical Explorer                           | Ctrl/⌘+K → Open canonical Explorer → Enter                                        | The tenant-scoped grammar opens with the current safe clock and filters.                  |
| J3      | Answer each of ten taught questions               | Focus question → Enter; focus Run query → Enter (repeat 10×)                      | All ten answers use exact structured queries with zero typed query text.                  |
| J4      | Inspect the worst ECMP branch                     | Tab to Inspect worst hop → Enter; Escape closes detail safely                     | The branch stays selected in X3 context after focus returns.                              |
| J4      | Compare immutable path rounds                     | Ctrl/⌘+K → Compare path rounds → Enter; use native Compare with select            | The exact-value table mirrors the visual path comparison.                                 |
| J4      | Copy the stable path replay URL                   | Ctrl/⌘+K → Copy stable path link → Enter                                          | Rounds, clock, and branch survive; tenant identity is absent.                             |
| J4      | Simulate the selected topology node               | Select the graph or list node; Ctrl/⌘+K → Simulate selected topology node → Enter | Graph and list invoke the same observe-only blast-radius preview.                         |
| J4      | Open exact incident evidence                      | Tab to Open incident evidence → Enter                                             | The incident receives the same clock, rounds, and branch selection.                       |
| J5      | Filter the fleet to exceptions                    | Ctrl/⌘+K → Review unhealthy fleet → Enter                                         | Only tenant-scoped stale, skewed, or capability-gap agents remain.                        |
| J5      | Open the evidence-only safe action                | Tab to the recommended action → Enter; Escape closes and restores focus           | No update executes; human approval, health gates, rollback, RBAC, and audit stay visible. |
| J6      | Triage the highest-ranked fleet exception         | Alt+X; Tab to Triage exception → Enter                                            | Metadata-only evidence opens without implicit tenant telemetry access.                    |
| J6      | Open tenant lifecycle and choose silo isolation   | Alt+T; use native Isolation model select                                          | Isolation and residency are explicit before provisioning.                                 |
| J6      | Enter residency, slug, and display name           | Tab through native fields and type the values                                     | The provider request contains lifecycle metadata only.                                    |
| J6      | Provision the tenant                              | Tab to Provision → Enter                                                          | Expired licenses leave this control visibly read-only.                                    |
| J6      | Export usage showback                             | Alt+E                                                                             | The provider-scoped CSV export opens directly after separate-plane authentication.        |

Escape closes palettes and dialogs without committing an action. Dialog focus is trapped and restored. Path and topology visual selections have equivalent native table/list buttons. Tenant switching first navigates to a neutral onboarding route, clearing action parameters and object references before the new tenant session can be used.
