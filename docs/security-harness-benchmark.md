# Security Harness Benchmark Notes

Reviewed during harness mining on 2026-05-06:

- `vercel-labs/deepsec`
- `arm/metis`
- `anthropics/claude-code-security-review`
- `qodo-ai/pr-agent`
- `iknowjason/llm-security-scanner`

## Blunt Take

Do not add another general AI reviewer lane yet. The harness gets more useful by improving deterministic Odoo candidate generation, evidence collection, CI behavior, and regression tests.

The right shape is:

1. Deterministic scanners and Odoo-aware matchers find risky files/functions.
2. LLM lanes triage, explain, chain, and produce Odoo-specific fixes only for those risky surfaces.
3. Final findings preserve evidence, false-positive lessons, and regression state.

## Patterns Worth Stealing

### DeepSec

Useful:

- Append-only per-file candidate records.
- Matcher catalog with `slug`, `noiseTier`, `filePatterns`, examples, and repo gates.
- Prompt assembly scoped to current candidate slugs.
- Low-coverage warnings when a language/surface has too few candidates.

Apply to this harness as an Odoo candidate ledger under `<OUT>/inventory/candidates/`.

### Arm Metis

Useful:

- Deterministic evidence pack before model triage.
- Structured model decision: `valid`, `invalid`, `inconclusive`.
- Evidence obligations: concrete citations, resolution chain, unresolved hops.
- Deterministic adjudication after model output.

Apply to this harness by extending `fp_check` in `findings.json` with `evidence`, `resolution_chain`, and `unresolved_hops`.

### Claude Code Security Review Action

Useful:

- PR-only diff review by default.
- GitHub Action cache/reservation so a PR is not reviewed repeatedly unless requested.
- Hard false-positive filtering before posting comments.
- Custom security and false-positive instruction files.

Apply to this harness by adding PR cache/reservation to the GitHub Action template and adding Odoo-specific hard exclusions before PR comments.

### PR-Agent

Useful:

- Simple GitHub Action and CLI install story.
- PR compression and dynamic context.
- Multi-provider configuration without making model choice the product.
- Separate commands for describe/review/improve/ask.

Apply sparingly. The Odoo harness should stay security-specific, but PR compression and concise delta comments are worth copying.

### llm-security-scanner

Useful:

- Small, easy-to-understand schema with severity, line numbers, impact, recommendation, and fix example.
- Vulnerable sample app for regression checks.
- PR changed-file workflow vs scheduled full workflow.

Apply by adding intentionally vulnerable mini Odoo modules and a `scripts/odoo-review-rule-test` regression runner.

## First Upgrades To Implement

1. Add `detect-secrets` to deterministic scanners.
2. Extend `findings.json` with `false_positive_reason` and evidence obligations.
3. Add Odoo matcher examples/tests.
4. Add intentionally vulnerable mini Odoo modules:
   - public route + `sudo().search([])`
   - `csrf=False` webhook with no HMAC
   - `**kw` mass assignment
   - user-controlled `order=`
   - unsafe `t-raw`
   - universal `ir.rule`
   - portal IDOR through `browse(id)`
5. Add a candidate ledger and feed candidate-heavy files into Codex hunters.
6. Add PR Action cache/reservation and Odoo-specific false-positive filtering.

## Odoo Hard-Exclusion Ideas

These should suppress comments/leads, not final evidence-backed findings:

- Demo/test fixture credentials when the file is only loaded by `demo` or test manifests.
- Admin-equivalent findings where the only reachable group is `base.group_system`.
- Static website routes with no attacker-controlled data and only `t-esc` rendering.
- `cr.execute` migrations with hardcoded SQL and no user-controlled values.
- `safe_eval` on static XML/domain strings with no request, record, or config input.
- Generic rate-limit/resource-exhaustion comments without Odoo-specific business impact.

Every exclusion needs a `false_positive_reason` so the harness teaches why the lead was rejected.
