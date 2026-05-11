# Odoo Application Security Harness

Claude Code harness for repeatable Odoo source-code security reviews.

Provides one comprehensive command, `/odoo-code-review`. Claude Code remains the lead reviewer and final arbiter. Local Ollama/Qwen provides private hint-only triage. Codex/OpenAI handles token-heavy hunter passes, discourse drafts, chaining drafts, evidence packs, and report drafts.

## North Star

**Use this tool to become the best Odoo developer possible.** This is an AI-assisted code-review companion, not a one-shot scanner. Every run should leave you sharper than the last:

- Each ACCEPT finding explains the Odoo-idiomatic fix (not "validate input" but "use `ir.model.access` + `ir.rule` with `company_id` filter, drop the `sudo()`, propagate `with_user(self.env.user)` through related fields"). Cite Odoo source / docs / OCA precedent when relevant.
- Each REJECT explains _why_ it isn't a bug in Odoo's model so you internalize the framework's invariants (e.g., "ORM ALREADY parameterizes via `psycopg2.sql` for table identifiers — the f-string here is over a hardcoded constant, not user data").
- Findings target the Odoo bug shapes that don't show up in generic Python scanners: multi-company isolation, prefetch leakage, `sudo()` propagation, `ir.model.access` vs `ir.rule` precedence, `_sql_constraints` gaps, computed-field-with-sudo recompute amplification, QWeb sinks (`t-raw` / `Markup` / `fields.Html(sanitize=False)`), portal `/my/*` exposure, `safe_eval` sandbox edges, `with_user(env.ref('base.user_admin'))` patterns.
- The iteration loop builds your knowledge base: every `accepted_risks` reason in `scope.yml` becomes a paragraph of senior-level Odoo reasoning you can show to teammates.

If a finding could be lifted verbatim from `bandit -r .`, it doesn't belong in the report. The point is the Odoo expertise you absorb every iteration.

## TL;DR

Run `/odoo-code-review -ks` from your Odoo repo root for the max-quality kitchen-sink check. Use `--quick` for fast local iteration and `--pr <n>` for pull requests. The kitchen-sink path handles inventory → scanners → Qwen advisory → risk-prioritized breadth (`--breadth-budget deep`) → Codex hunters → stock-Claude control lane → discourse → chaining → runtime evidence path → 6-gate validation → final report → SARIF/bounty/diff export. After the report, it drafts accepted-risk and fix-list learning artifacts for review. Add `--yes` only when you want non-interactive auto-apply behavior.

Use Claude Code for the full `-ks` workflow. The direct shell runner is useful for setup, scans, Codex prompt execution, and CI-ish stages, but it cannot spawn Claude subagents or make the final Phase 7 security judgment by itself.

## Architecture

```text
Odoo Application Security Harness
├── Detection Engine          — Semgrep, Bandit, Ruff, pylint-odoo, CodeQL, Joern, pip-audit, osv-scanner, detect-secrets
├── Agent Framework           — Claude Code lead + local Ollama/Qwen triage + Codex hunter passes
├── Validation Pipeline       — 6-gate fp-check, evidence packs, variant analysis, chaining
└── Attack Graph Analysis     — Phase 7.6 graph construction and Graphviz render
```

## Lanes

Three parallel lanes feed Claude's final validation. Claude Code stays lead and final arbiter.

```text
                       ┌──────────────────────────┐
                       │   Odoo source repo +     │
                       │   /odoo-code-review      │
                       └────────────┬─────────────┘
                                    │
            ┌───────────────────────┼───────────────────────┐
            ▼                       ▼                       ▼
  ┌──────────────────────┐ ┌──────────────────────────┐ ┌──────────────────────┐
  │  Lane 1              │ │  Lane 2                  │ │  Lane 3              │
  │  Claude Code         │ │  Runner + Ollama/Qwen    │ │  Codex / OpenAI      │
  │  (lead)              │ │  (local triage)          │ │  (execution engine)  │
  ├──────────────────────┤ ├──────────────────────────┤ ├──────────────────────┤
  │ • orchestration      │ │ Runner (Python):         │ │ • hunter passes      │
  │ • attack surface     │ │  • inventory             │ │ • discourse drafts   │
  │   (final pass)       │ │  • manifest parsing (AST)│ │ • chaining drafts    │
  │ • /goals tracking    │ │  • route/sudo/QWeb index │ │ • evidence packs     │
  │ • 6-gate fp-check    │ │  • scanner exec          │ │ • test/fuzz scripts  │
  │ • directive author   │ │ Qwen (LLM):              │ │ • report drafts      │
  │ • final report       │ │  • module narrative      │ │                      │
  │                      │ │  • scanner triage        │ │                      │
  │                      │ │  • hint-only signal      │ │                      │
  │                      │ │  • offline, no egress    │ │                      │
  └──────────┬───────────┘ └────────────┬─────────────┘ └──────────┬───────────┘
             │                          │                          │
             │      ┌───────────────────┴────────────────────┐     │
             ├─────▶│  .audit/ artifacts (leads, not final)  │◀────┤
             │      └───────────────────┬────────────────────┘     │
             │                          ▼                          │
             │             ┌──────────────────────────┐            │
             │             │  Claude 6-gate validation│            │
             │             │  → final report          │            │
             │             └────────────┬─────────────┘            │
             │                          │                          │
             │                          ▼                          │
             │       ┌────────────────────────────────────┐        │
             └──────▶│  directives/D-NNNN-<slug>.md       │◀───────┘
                     │  → odoo-review-rerun → lane redo   │
                     │  (iterative loop, targeted reruns) │
                     └────────────────────────────────────┘
```

Lane outputs are leads only. Nothing ships until Claude's 6-gate validation confirms. When deeper coverage needed, Claude writes a directive file (`<OUT>/directives/D-NNNN-<slug>.md`) and `odoo-review-rerun` dispatches it to Qwen or Codex — result lands in `directives/results/`.

## What It Does

- Inventories Odoo modules and manifests.
- Maps Odoo attack surface: routes, ACLs, record rules, sharp-edge APIs.
- Reviews deployment posture across Odoo config, XML/CSV parameters, Docker, Compose, Kubernetes, Helm, Ansible-style YAML, and Terraform env declarations.
- Scores per-module risk (`module-risk.md` + `inventory/module-risk.json`) so hunters hit highest-risk modules first.
- Emits a risk-prioritized Phase 1.7 breadth plan for Claude Agent subagents, capped by `--breadth-budget` / `--breadth-max-chunks`.
- Seeds hunters with `inventory/cwe-map.json` (583 Odoo bug-shape → CWE/CAPEC/OWASP mappings).
- Runs repeatable scanner setup for Semgrep, Bandit, Ruff, pylint-odoo, CodeQL, dependency tools, and optional Joern.
- Runs local Qwen advisory notes through Ollama.
- Launches or prepares Codex hunter tasks.
- Runs a stock-Claude control lane in weekly mode so plain `/code-review`-style findings become current-run validation leads instead of surprises.
- Writes a `goals.md` guide for lead-session `/goals` tracking in Codex-capable review sessions.
- Produces `.audit/` artifacts for Claude's final 6-gate validation.
- Exports findings.json → SARIF 2.1.0, fingerprints, and HackerOne/Intigriti bounty drafts via `odoo-review-export`.
- Diffs two findings.json snapshots (new / fixed / changed) via `odoo-review-diff` for ongoing audits.
- Re-tasks Qwen or Codex mid-review via `odoo-review-rerun` and the `directives/` feedback loop.

The scanner and model outputs are leads, not final findings. The final report still requires Claude's 6-gate validation.

## Runner Flags

The direct runner is `odoo-review-run [target] [flags]`. The slash command forwards the same review flags.

| Flag | Purpose |
| ---- | ------- |
| `--out <dir>` | Override output directory. Default is `<target>/.audit-YYYYMMDD-HHMM/`. |
| `--prune-old-runs <N>` | After a successful run, keep only the most recent `N` stamped audit dirs. |
| `--modules <list>` | Restrict scope to comma-separated Odoo module names. |
| `--odoo-version <N>` | Override Odoo version detection. |
| `--config <file>` | Load project TOML config. Defaults to `.odoo-review/config.toml` or `.odoo-review.toml` when present. CLI flags override config. |
| `--model-pack <name>` | Apply model/lane preset: `default`, `cheap-recall`, `balanced`, `frontier-validation`, or `local-private`. |
| `--quick` | Fast local pass. Skips automated scanners and discourse prep. |
| `--no-discourse` | Skip Phase 5.5 hunter discourse. |
| `--no-local-qwen` | Skip local Ollama/Qwen advisory pass. |
| `--local-model <name>` | Override local Ollama model. Default: `qwen3:0.6b`. |
| `--allow-missing-lanes` | Continue if Codex or Qwen is unavailable. Records weaker coverage in `tooling.md`. |
| `--joern` | Enable optional Joern CPG graph review. |
| `--runtime` | Enable Phase 7.5 runtime path and generate `runtime/probes/` route-probe templates. |
| `--zap-target <url>` | Run ZAP baseline against a QA target. Requires `--runtime`. |
| `--odoomap-target <url\|self>` | Add optional OdooMap runtime recon against an authorized QA/staging target. Requires `--runtime`; brute-force modes are not enabled. |
| `--no-codex` | Skip Codex hunter execution. |
| `--codex-model <name>` | Override Codex model. |
| `--codex-budget low\|normal\|deep` | Set Codex pass budget label. |
| `--codex-mode run\|prepare` | Run Codex tasks or only write prompt files. |
| `--ensemble off\|cheap\|balanced` | Run focused recall passes before Phase 7 validation. |
| `--ensemble-passes <N>` | Limit ensemble pass count. `0` means preset default. |
| `--requirements <file>` | Enable Phase 7.8 requirements/spec verification. |
| `--no-html` | Skip `findings.html` generation. |
| `--no-json` | Skip `findings.json` sidecar. JSON is emitted by default. |
| `--json` | Compatibility no-op; JSON is already on by default. |
| `--no-export` | Skip Phase 8.6 export/finalize wrapper. |
| `--baseline <path>` | Baseline `findings.json` or `.audit/` for diffing. |
| `--preflight-only` | Write run plan/tooling/inventory artifacts, then stop. |
| `--no-scans` | Skip scanners even when not `--quick`. |
| `--scope <file>` | Apply `scope.yml` excluded modules/paths and coarse accepted risks. |
| `--pr <n>` | Scope review to files changed in GitHub PR `n` using `gh`. |
| `--pr-repo <owner/repo>` | Override PR repository for `--pr`. |
| `--accepted-risks <path>` | Override per-finding accepted-risk suppression file. |
| `--check-only-accepted-risks` | Validate accepted-risks file and exit non-zero on errors/expired entries. |
| `--fix-list <path>` | Override fix-it tracking file. |
| `--check-only-fix-list` | Validate fix-list file and exit non-zero on validation errors/overdue entries. |
| `--no-server-actions` | Skip loose-Python sweep of `docs/server_actions/*.py`. |
| `--no-scripts` | Skip loose-Python sweep of `scripts/*.py`. |
| `--no-breadth` | Skip Phase 1.7 breadth-sweep dispatch plan. Equivalent to `--breadth-budget off`. |
| `--breadth-budget off\|low\|normal\|deep` | Control Claude Agent spend for Phase 1.7. `low` emits top 8 risky chunks, `normal` top 24, `deep` all. Default: `normal`; `-ks` defaults to `deep`. |
| `--breadth-max-chunks <N>` | Hard-cap Phase 1.7 chunks after risk prioritization. `0` uses the selected budget preset. |
| `--breadth-chunk-size <N>` | Files per breadth-sweep chunk. Default: `40`. |
| `--phase1-min-lines-per-module <N>` | Phase 1 fail-loud threshold. Default: `4`. |
| `--no-phase1-assert` | Disable Phase 1 fail-loud assertion. Escape hatch only. |
| `--allow-empty-scope` | Continue even when no Odoo modules/pseudo-modules are discovered. Default is fail-before-model-lanes to avoid quota waste on the wrong target. |
| `--yes`, `-y` | Non-interactive mode. Suppresses y/N prompts and auto-applies learn suggestions only when `--learn` is also set. |
| `--learn` | Generate durable baseline/fix-list/accepted-risk learning artifacts after final findings exist. |
| `--learn-cap <N>` | Max Phase 8.7 learning iterations. Default: `3`. |
| `--baseline-stock-cc` | Spawn stock Claude Code control lane; stock-only misses become validation leads. |
| `-ks`, `--ks`, `--kitchensink`, `--weekly` | Kitchen sink mode: Joern, runtime, `--breadth-budget deep`, JSON, learn, stock-CC gate, and durable state auto-detect. Add `--yes` separately for zero prompts. |

Runtime helper:

| Flag | Purpose |
| ---- | ------- |
| `odoo-review-runtime <OUT>` | Boot Odoo for Phase 7.5 and capture evidence. |
| `--odoo-bin <path>` | Odoo binary. Defaults to `$ODOO_BIN` or `odoo-bin`. |
| `--config <path>` | Odoo config file. Defaults to `$ODOO_CONFIG`. |
| `--database`, `--db <name>` | Database name. Defaults to `$ODOO_DB`. |
| `--addons-path <paths>` | Comma-separated addons path. Defaults to `$ODOO_ADDONS_PATH` or repo. |
| `--host <host>` / `--port <port>` | Bind/check host and port. Defaults to `127.0.0.1:8069`. |
| `--health-path <path>` | Readiness path. Default: `/web/login`. |
| `--timeout <seconds>` | Readiness timeout. Default: `120`. |
| `--poc <script>` | Replay an explicit PoC script after Odoo is ready. Repeatable. |
| `--run-generated-probes` | Replay auto-safe probes listed in `runtime/probes/safe-pocs.txt`. |
| `--odoomap-target <url\|self>` | Run optional OdooMap recon/module/CVE leads against an authorized target. Use `self` for the booted local runtime URL. |
| `--odoomap-enumerate` | Run OdooMap authenticated enumeration only when `--odoomap-database`, `--odoomap-username`, and `--odoomap-password` are all supplied. |
| `--keep-running` | Leave Odoo running and write `runtime/odoo.pid`. |
| `--plan-only` | Write runtime command/plan artifacts without booting Odoo. |

## Install

```bash
git clone <your-fork-url> odoo-app-security-harness
cd odoo-app-security-harness
./install.sh
```

The installer copies:

- `commands/odoo-code-review.md` -> `~/.claude/commands/odoo-code-review.md`
- `skills/odoo-code-review/` -> `~/.claude/skills/odoo-code-review/`
- convenience symlinks in `~/.local/bin/`:
  - `odoo-review-run` — main pipeline runner
  - `odoo-review-rerun` — directive dispatcher (Qwen/Codex re-task)
  - `odoo-review-finalize` — Phase 8.6 wrapper: export + diff + severity/stock gates (default for CI / non-Claude paths and manual re-export)
  - `odoo-review-runtime` — Phase 7.5 helper: boot Odoo, wait for readiness, run PoC scripts, capture evidence
  - `odoo-review-export` — direct SARIF + fingerprints + bounty drafts (called by finalize)
  - `odoo-review-diff` — direct baseline vs current comparison (called by finalize)
  - `odoo-review-learn` — Phase 8.7 baseline/fix-list/accepted-risk learning helper
  - `odoo-review-stock-diff` — stock-Claude control-lane diff and lessons helper
  - `odoo-review-coverage` — Phase 5.6 hunter coverage diff and CI gap gate
  - `odoo-review-validate-config` — schema validator for `.odoo-review/config.toml`, `scope.yml`, accepted-risk files, and fix-list files; use `--type accepted-risks` or `--type fix-list` for renamed governance files
  - `odoo-deep-scan` — standalone static scanner that emits JSON, Markdown, SARIF, PoCs, coverage inventories, and a CI gate

## Prerequisites

Required for the full three-lane workflow:

```bash
brew install ollama
ollama pull qwen3:0.6b
```

Codex CLI must be installed and authenticated separately.

Optional scanner tools:

```bash
pipx install semgrep bandit ruff pylint pylint-odoo pip-audit detect-secrets
brew install codeql osv-scanner graphviz
```

Some teams install these through `pip`, `uv`, `brew`, or a devcontainer instead. Missing scanners are recorded in `tooling.md`.

## Usage

From Claude Code:

```text
/odoo-code-review /path/to/odoo-addons --allow-missing-lanes
```

Direct runner:

```bash
odoo-review-run /path/to/odoo-addons --allow-missing-lanes
```

Standalone deep scanner:

```bash
odoo-deep-scan /path/to/odoo-addons \
  --out .audit-deep \
  --pocs \
  --fail-on high \
  --baseline .audit-baseline/deep-scan-findings.json \
  --fail-on-new high \
  --accepted-risks .audit-accepted-risks.yml \
  --fix-list .audit-fix-list.yml \
  --fail-on-fix-regression \
  --fail-on-unmapped-taxonomy
```

Use `odoo-deep-scan` when you want the static harness without the full Claude/Qwen/Codex orchestration. It exits `0` by default, or `2` when `--fail-on critical|high|medium|low` finds a blocking severity. Add `--baseline <findings.json|audit-dir>` and `--fail-on-new critical|high|medium|low` to gate only findings that are new relative to a fingerprint baseline. Add `--accepted-risks <yml|json>` to suppress active, already-triaged findings while still reporting expired matches. Add `--fix-list <yml|json>` to tag tracked bugs, regressions, wontfix findings, and likely-fixed entries without suppressing findings. Use `--check-only-accepted-risks` or `--check-only-fix-list` to validate governance files and emit their inventory/report without running scanners. Governance gates are opt-in: `--fail-on-policy-errors`, `--fail-on-expired-accepted-risk`, `--fail-on-overdue-fix`, and `--fail-on-fix-regression`. Add `--fail-on-unmapped-taxonomy` to fail CI when a scanner emits a rule ID that lacks CWE/CAPEC/OWASP metadata. Use `--fail-on none` to disable severity gating.

Standalone deep-scan outputs:

- `deep-scan-findings.json` — normalized findings with stable IDs, fingerprints, and triage state.
- `deep-scan-report.md` — Markdown findings report.
- `findings.html` — self-contained offline triage report with accepted-risk and fix-list export queues.
- `deep-scan.sarif` — SARIF 2.1.0 for GitHub Code Scanning and similar review tools.
- `review-gate.json` — CI verdict, threshold, severity counts, and blocking finding summaries.
- `taxonomy-gate.json` — CI verdict for unmapped emitted rule IDs when taxonomy drift gating is enabled.
- `governance-gate.json` — CI verdict for accepted-risk/fix-list policy health gates.
- `deep-scan-delta.json` + `deep-scan-delta.md` — fingerprint baseline delta when `--baseline` is supplied.
- `00-accepted-risks.md` + `inventory/accepted-risks.json` — accepted-risk suppression inventory, suppressed findings, and expired matches.
- `00-fix-list.md` + `inventory/fix-list.json` — fix-list tracking buckets for tracked, regression, wontfix, likely-fixed, confirmed-fixed, and drifted entries.
- `deep-scan-validation.json` — finding schema validation result.
- `tooling.md` — scanner coverage, rule catalog, finding summary, module risk, PoC coverage, and artifact manifest pointer.
- `module-risk.md` + `inventory/module-risk.json` — per-module risk scoring for review prioritization.
- `inventory/coverage/matcher-coverage.json` — surface, route, scanner-source, registry, rule-catalog, gate, and risk coverage.
- `inventory/coverage/rule-catalog.json` — declared rule IDs and emitted/undocumented rule coverage.
- `inventory/coverage/taxonomy-coverage.json` — emitted rule coverage for CWE/CAPEC/OWASP metadata.
- `inventory/coverage/scanner-manifest.json` — scanner callable to source-label mapping.
- `inventory/artifacts.json` — required/optional output bill of materials with existence, byte size, and counts.
- `inventory/coverage/poc-coverage.json` and `pocs/` — generated PoC coverage and scripts when `--pocs` is enabled.

Safer dry setup:

```bash
odoo-review-run /path/to/odoo-addons \
  --preflight-only \
  --allow-missing-lanes \
  --codex-mode prepare
```

Prepare Codex prompts without spending Codex tokens:

```bash
odoo-review-run /path/to/odoo-addons \
  --codex-mode prepare \
  --allow-missing-lanes
```

Cap Claude breadth subagents when quota matters:

```bash
odoo-review-run /path/to/odoo-addons \
  --breadth-budget low \
  --breadth-max-chunks 8 \
  --codex-mode prepare
```

Kitchen-sink full check:

```text
/odoo-code-review /path/to/odoo-addons -ks
```

`-ks` uses `--breadth-budget deep` unless you explicitly override it, for example:

```text
/odoo-code-review /path/to/odoo-addons -ks --breadth-budget normal
```

Cost-efficient recall ensemble:

```bash
odoo-review-run /path/to/odoo-addons \
  --model-pack cheap-recall \
  --ensemble cheap \
  --ensemble-passes 6 \
  --codex-mode prepare \
  --allow-missing-lanes
```

This writes focused recall prompts under `ensemble/` for Odoo bug classes such as public route + `sudo()`, portal IDOR, CSRF/method weirdness, multi-company leakage, QWeb/HTML sinks, raw SQL/domain injection, attachment/report exposure, and proxy/external integration context. Ensemble output is lead material only; Phase 7 still performs strict validation.

Shared project config:

```bash
mkdir -p .odoo-review
cp <harness>/skills/odoo-code-review/references/config.example.toml .odoo-review/config.toml
odoo-review-run . --config .odoo-review/config.toml
```

CLI flags override `.odoo-review/config.toml`. Built-in model packs are `default`, `cheap-recall`, `balanced`, `frontier-validation`, and `local-private`.
Runtime config targets must be explicit `http://` or `https://` URLs; `runtime.odoomap_target` may also be `self` for the booted local runtime.

Runtime evidence for an accepted candidate:

```bash
odoo-review-runtime .audit-YYYYMMDD-HHMM \
  --odoo-bin /path/to/odoo-bin \
  --config /path/to/odoo.conf \
  --database review_db \
  --addons-path /path/to/odoo/addons,/path/to/custom/addons \
  --poc .audit-YYYYMMDD-HHMM/runtime/reproductions/poc-F-1.sh
```

The helper writes `runtime/status.json`, `runtime/odoo.log`, `runtime/odoo-stdout.log`, and PoC output logs under `runtime/reproductions/`.

Optional OdooMap runtime leads can be captured alongside PoCs:

```bash
odoo-review-runtime .audit-YYYYMMDD-HHMM \
  --odoo-bin /path/to/odoo-bin \
  --config /path/to/odoo.conf \
  --database review_db \
  --addons-path /path/to/odoo/addons,/path/to/custom/addons \
  --odoomap-target self \
  --odoomap-modules \
  --odoomap-cve
```

The OdooMap integration is lead material only and intentionally exposes reconnaissance/module/CVE/authenticated-enumeration options without database, credential, user, master-password, or model-name brute-force switches. Authenticated enumeration is skipped unless database, username, and password are all supplied; partial credentials are ignored instead of being passed to OdooMap. Output is written under `runtime/odoomap/`; generated command artifacts redact the OdooMap password.

When the runner is invoked with `--runtime` or `-ks`, it also generates a route-derived probe plan under `runtime/probes/`. Literal public `GET`-only routes are listed in `runtime/probes/safe-pocs.txt` and can be replayed automatically:

```bash
odoo-review-runtime .audit-YYYYMMDD-HHMM \
  --run-generated-probes \
  --odoo-bin /path/to/odoo-bin \
  --config /path/to/odoo.conf \
  --database review_db \
  --addons-path /path/to/odoo/addons,/path/to/custom/addons
```

Authenticated, parameterized, JSON, mixed-method, or method-unbounded routes are emitted as manual PoC templates and do not send traffic unless explicitly enabled with `ODOO_REVIEW_ALLOW_UNSAFE_PROBES=1`.

Scope to a PR's changed files (uses `gh pr view --json files`):

```bash
odoo-review-run /path/to/odoo-addons --pr 42 [--pr-repo owner/repo]
```

Honor a `scope.yml` (excluded modules/paths + accepted risks with audit trail):

```bash
odoo-review-run /path/to/odoo-addons --scope ./scope.yml
# See skills/odoo-code-review/references/scope.example.yml for schema.
```

## Post-Processing

`/odoo-code-review` runs Phase 8.6 finalize automatically. For non-Claude paths (CI, codex-only sessions, manual re-export), call the wrapper directly:

```bash
odoo-review-finalize .audit                          # auto-detect baseline + run gates (default --fail-on high)
odoo-review-finalize .audit --baseline .baseline     # explicit baseline path
odoo-review-finalize .audit --fail-on critical       # only fail on critical ACCEPT
odoo-review-finalize .audit --fail-on none           # disable severity gate
odoo-review-finalize .audit --no-stock-gate          # disable unresolved stock-CC lead gate
odoo-review-finalize .audit --no-bounty --no-diff    # SARIF + fingerprints only
```

Emits:

- `.audit/findings.sarif` — SARIF 2.1.0 (GitHub Code Scanning, GitLab, etc.)
- `.audit/findings-fingerprints.json` — stable cross-run dedup hashes
- `.audit/bounty/F-N.md` — HackerOne/Intigriti-shaped drafts (one per ACCEPT, suppressed entries skipped)
- `.audit/delta.md` + `.audit/delta.json` — diff vs baseline (when baseline detected)
- `.audit/finalize.log` — audit trail of what ran, exit codes, ACCEPT counts

Exit code: `0` pass, `2` ACCEPT exceeds severity gate, `4` unresolved stock-CC leads, non-zero forwarded from export/diff failures.

Baseline auto-detection order: `--baseline <path>` → `$ODOO_REVIEW_BASELINE` → `.audit-baseline/findings.json` → `.audit-baseline.json`.

If you only want one stage, the underlying scripts are still exposed:

```bash
odoo-review-export .audit                            # SARIF + fingerprints + bounty (no diff, no gate)
odoo-review-diff .baseline/findings.json .audit/findings.json   # delta only
```

## CI Integration

Drop-in GitHub Action template at `skills/odoo-code-review/templates/github-action.yml`:

- Runs PR-scoped review on every PR (`--pr <n>`) and full sweep on push to main. Manual recurring sweeps should use `/odoo-code-review -ks` from Claude Code.
- Calls `odoo-review-finalize .audit --fail-on high` — single step replaces export + diff + gate. Exit code fails the PR check on ACCEPT critical/high.
- Uploads `findings.sarif` to GitHub Code Scanning (inline PR annotations + Security tab).
- Posts a sticky PR comment with delta vs main baseline (`.audit/delta.md`).
- Persists `findings.json` + `delta.md` + `bounty/` + `finalize.log` as 90-day artifacts.

Copy to `.github/workflows/odoo-security.yml` in your addons repo and set `OPENAI_API_KEY` secret if Codex lane is desired.

For a lighter static-only CI lane, use `skills/odoo-code-review/templates/deep-scan-github-action.yml`:

- Validates `.odoo-review/config.toml`, `.odoo-review.toml`, `scope.yml`, `.audit-accepted-risks.*`, and `.audit-fix-list.*` before scanning.
- Runs `odoo-deep-scan . --out .audit-deep --pocs --fail-on "$ODOO_DEEP_SCAN_FAIL_ON"`.
- Defaults the severity gate to `high`; set repository variable `ODOO_DEEP_SCAN_FAIL_ON` to `critical`, `medium`, `low`, or `none`.
- Set `ODOO_DEEP_SCAN_BASELINE` plus `ODOO_DEEP_SCAN_FAIL_ON_NEW` to fail only on new findings over a baseline.
- Set `ODOO_DEEP_SCAN_ACCEPTED_RISKS` to a YAML/JSON accepted-risk file to suppress active known findings.
- Set `ODOO_DEEP_SCAN_FIX_LIST` to a YAML/JSON fix-list file to tag tracked bugs and regressions without suppressing them.
- Set `ODOO_DEEP_SCAN_CHECK_ONLY_ACCEPTED_RISKS` or `ODOO_DEEP_SCAN_CHECK_ONLY_FIX_LIST` to `true` to validate governance files without running scanners.
- Set `ODOO_DEEP_SCAN_FAIL_ON_POLICY_ERRORS`, `ODOO_DEEP_SCAN_FAIL_ON_EXPIRED_ACCEPTED_RISK`, `ODOO_DEEP_SCAN_FAIL_ON_OVERDUE_FIX`, or `ODOO_DEEP_SCAN_FAIL_ON_FIX_REGRESSION` to `true` to enforce governance health.
- Set repository variable `ODOO_DEEP_SCAN_FAIL_ON_UNMAPPED_TAXONOMY` to `true` to fail CI on rule IDs without CWE/CAPEC/OWASP metadata.
- Uploads `.audit-deep/deep-scan.sarif` to Code Scanning.
- Persists `deep-scan-findings.json`, `review-gate.json`, `tooling.md`, module risk, inventories, and PoCs as 90-day artifacts.

## Output

Default output goes to a stamped run directory:

```text
<repo>/.audit-YYYYMMDD-HHMM/
```

Important artifacts:

- `00-run-mode.md`, `run-mode.json` — orchestration flags Claude must honor (`--yes`, `--learn`, stock-CC, breadth budget, etc.)
- `00-modules.md`
- `01-attack-surface.md`
- `00-accepted-risks.md`, `inventory/accepted-risks.json` — per-finding suppression inventory with active/expired/stale buckets
- `00-fix-list.md`, `inventory/fix-list.json` — fix-it tracker inventory and reconciliation buckets
- `module-risk.md` — per-module risk score + band (critical/high/medium/low)
- `goals.md`
- `directives/` — feedback-loop scratch space (`README.md`, `_template.md`, `D-NNNN-*.md`, `results/`)
- `inventory/breadth/dispatch.json`, `inventory/breadth/dispatch.md`, `inventory/breadth/leads.md` — risk-prioritized Phase 1.7 breadth plan and collected Claude Agent leads
- `inventory/manifests.json`
- `inventory/routes.json`
- `inventory/acl-index.json`
- `inventory/sharp-edge-index.json`
- `inventory/module-risk.json` — machine-readable risk score
- `inventory/cwe-map.json` — 583 Odoo bug-shape → CWE/CAPEC/OWASP mappings (seeds hunters)
- `inventory/scope.json` — applied scope.yml + computed inclusions/exclusions
- `local-qwen/module-notes.md`
- `scans/*`
- `codex/hunters/*`
- `tooling.md`
- `tooling.json`
- `qwen-handoff/` — local Qwen fallback packet for token pressure
- `baseline-stock/` — stock-Claude control-lane prompt/output/diff artifacts when `--baseline-stock-cc` or `-ks` is used

Post-processing artifacts (after `odoo-review-export` / `odoo-review-diff`):

- `findings.sarif` — SARIF 2.1.0 (suppressions for accepted_risks)
- `findings-fingerprints.json` — stable hashes for cross-run dedup
- `bounty/F-N.md` — bounty submission drafts (one per ACCEPT, suppressed entries skipped)
- `delta.md`, `delta.json` — baseline-vs-current diff
- `finalize.log` — Phase 8.6 audit trail (commands, exit codes, ACCEPT counts, gate verdict)

## Sharing Notes

This repo does not include private Odoo source code, API keys, Claude session data, or local `.audit/` outputs. Review generated reports before sharing them outside a client or team boundary.
