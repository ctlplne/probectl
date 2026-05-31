# web/

The netctl frontend.

## Status (S0)

Intentionally empty. **S0 does not pick a frontend framework** (sprint plan S0
*Watch out for*). The framework, state/data-fetching architecture, themeable
design-token system, component library, app shell + command palette, auth-aware
routing, and the WCAG 2.2 AA baseline are all established in **S8a — Frontend
foundation & design system**, which every later UI sprint builds on.

## Guardrails that already apply (do not violate when S8a lands)

- **No hardcoded design values** — color, spacing, type, radius, and motion all
  route through design tokens so per-tenant white-label (S-T4) is a token
  override, not a rewrite (CLAUDE.md §6).
- **Sovereignty**: no third-party calls or phone-home fonts; the UI must be
  usable without external network access (CLAUDE.md §7 guardrail 11).
- **Always-visible tenant indicator**; the UI resolves to exactly one tenant.
