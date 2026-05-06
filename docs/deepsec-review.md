# DeepSec Review Notes

Reviewed source: `https://github.com/vercel-labs/deepsec` at commit `5d08800106e1c88cf6b09a9947d9354115e5977f` (`5d08800`, 2026-05-06).

## Summary

DeepSec is not a drop-in replacement for this harness. It is a TypeScript/polyglot scanner with an append-only `data/<project>/files/**/*.json` state model, regex matcher plugins, AI batch processing, revalidation, enrichment, and export stages.

The useful pieces are design patterns, not wholesale code:

1. A first-class matcher catalog with `slug`, `description`, `noiseTier`, `filePatterns`, optional repo gates, and inline examples.
2. Per-file candidate records that preserve candidate matches, analysis history, run metadata, file hashes, and finding status across runs.
3. Prompt assembly that injects only context relevant to the current batch: detected tech highlights, candidate slugs, project info, and configured prompt append text.
4. Coverage diagnostics such as per-language match rates and low-coverage warnings.
5. A separate revalidation stage that annotates findings as true-positive, false-positive, fixed, or uncertain instead of replacing them.
6. Small, testable matcher helpers and matcher examples that act as CI contracts.

## Highest-Value Ports

### 1. Add An Odoo Candidate Ledger

Current harness artifacts are strong at the run level (`inventory/`, `scans/`, `codex/`, `findings.json`), but DeepSec's most useful primitive is the append-only per-file `FileRecord`.

For this harness, a smaller Python version would be enough:

```json
{
  "file": "custom_addon/controllers/main.py",
  "module": "custom_addon",
  "file_hash": "sha256...",
  "candidates": [
    {
      "slug": "odoo-public-route-with-sudo",
      "noise_tier": "normal",
      "lines": [42, 51],
      "snippet": "...",
      "matched_pattern": "public route + sudo"
    }
  ],
  "analysis_history": [
    {
      "run_id": "20260506-...",
      "phase": "hunter",
      "agent": "codex",
      "model": "gpt-5.3-codex",
      "finding_count": 1
    }
  ],
  "status": "pending|analyzed|error"
}
```

Suggested output path: `<OUT>/inventory/candidates/files/**/*.json`.

Why it helps:

- Phase 5 hunters can process candidate-heavy files first.
- Reruns can skip files already analyzed with the same hash.
- Phase 5.6 coverage can diff actual file records instead of only `Reviewed:` prose.
- Future accepted-risk/fix-list reconciliation can match both candidate and final-finding layers.

### 2. Replace The Flat Semgrep-Only Rule Layer With A Matcher Catalog

DeepSec's matcher interface is simple and worth adapting conceptually:

- `slug`
- `description`
- `noise_tier`: `precise`, `normal`, `noisy`
- `file_patterns`
- optional `requires` gate
- `examples`
- `match(content, file_path) -> candidates`

Keep Semgrep, but add a local Python matcher catalog for Odoo shapes that Semgrep YAML expresses poorly. The first useful matchers:

- `odoo-public-route-entrypoint` (`noisy`): every `@http.route(auth='public'|'none')`.
- `odoo-route-no-methods` (`normal`): route decorator without explicit `methods=`.
- `odoo-route-kw-mass-assignment` (`precise`): `def ...(**kw)` followed by `.write(kw)` or `.create(kw)`.
- `odoo-user-controlled-order` (`precise`): `order=request.params[...]` or `order=kw[...]`.
- `odoo-user-controlled-fields-read` (`normal`): `fields=request.params` / `fields=kw`.
- `odoo-public-sudo-empty-domain` (`precise`): public route plus `sudo().search([])` or `sudo().search_read([])`.
- `odoo-webhook-csrf-no-hmac` (`normal`): `csrf=False` without nearby `hmac.compare_digest`, signature header, or token validation.
- `odoo-ir-rule-universal-domain` (`precise`): XML `domain_force` equivalent to universal allow.
- `odoo-public-attachment-create` (`normal`): `ir.attachment.create` with `public=True`.
- `odoo-html-sanitize-disabled-variant` (`precise`): `sanitize=False`, `sanitize_attributes=False`, `Markup(...)`, `t-raw`.

### 3. Add Matcher Example Tests

DeepSec puts examples beside matchers and has one test that asserts every example fires. This would immediately raise quality on `skills/odoo-code-review/rules/odoo.yml`, where regex regressions are currently easy to miss.

Recommended test contract:

- Store examples under `skills/odoo-code-review/rules/examples/*.yml` or inline in a Python matcher catalog.
- Add `scripts/odoo-review-rule-test`.
- Run Semgrep against snippets and run Python matchers against snippets.
- Fail if an example does not produce the expected slug.

### 4. Make Prompt Context Batch-Specific

DeepSec's prompt assembler includes only the slug notes and framework highlights relevant to a batch. Your harness already has strong Odoo reference files, but Codex hunter prompts are broad.

Useful adaptation:

- Generate `<OUT>/inventory/candidate-slugs-by-module.json`.
- In `codex_prompt()`, include only the reference sections for slugs present in that hunter/module slice.
- Add one-line slug notes beside `cwe-map.json`, for example:
  - `odoo-public-route-with-sudo`: "Only report if response or side effect crosses public/portal/user/root boundary; reject static template routes."
  - `odoo-user-controlled-order`: "Odoo validates field names imperfectly across versions; prove the parameter reaches `order` or `read_group`."

### 5. Add Revalidation As Machine State

The harness has a strong human Phase 7 validation process. DeepSec's useful addition is making revalidation explicit machine data:

```json
"revalidation": {
  "verdict": "true-positive|false-positive|fixed|uncertain",
  "reasoning": "...",
  "validated_at": "...",
  "run_id": "...",
  "model": "..."
}
```

This can live inside each final `findings.json` entry and would make `odoo-review-diff`, baselines, and weekly runs easier to trust.

### 6. Add Low-Coverage Warnings

DeepSec computes per-language match rates. For Odoo, compute per-surface coverage instead:

- Python files with candidates / Python files scanned.
- XML view/report files with candidates / XML files scanned.
- Controllers with candidates / controllers discovered.
- Modules with at least one candidate / modules scoped.
- Public routes with at least one associated candidate / public routes discovered.

Emit `<OUT>/inventory/coverage/matcher-coverage.json` and a short warning in `tooling.md` when coverage is suspiciously low.

## Lower-Value Or Overkill

- Vercel Sandbox distributed execution: useful for very large monorepos, but unnecessary for a local Odoo harness unless reviews routinely exceed one workstation.
- Full TypeScript plugin architecture: good for DeepSec's ecosystem, but too heavy for this repo. A Python registry plus TOML config is enough.
- Generic polyglot matcher catalog: keep this harness Odoo-specific. Generic Python issues should stay scanner leads, not final-report drivers.
- DeepSec's direct AI processing loop: your Claude/Qwen/Codex lane model is more specialized for Odoo and should remain the center.

## Suggested Implementation Order

1. Build a minimal Python matcher catalog and emit `<OUT>/inventory/candidates/files/**/*.json`.
2. Add examples/tests for existing Semgrep rules and new Python matchers.
3. Feed candidate slugs and candidate-heavy files into breadth dispatch and Codex hunter prompts.
4. Add matcher/surface coverage metrics to `tooling.md`.
5. Extend `findings.json` with optional `revalidation`.

This keeps the current harness architecture intact while porting the DeepSec parts that increase repeatability, rerun quality, and candidate prioritization.
