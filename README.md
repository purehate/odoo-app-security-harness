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

Run `/odoo-code-review` from your Odoo repo root. The harness handles inventory → scanners → Qwen advisory → Codex hunters → discourse → chaining → 6-gate validation → final report → SARIF/bounty/diff export end-to-end. After the report, the AI auto-drafts `accepted_risks` for false positives, cross-checks via the other lane, and re-runs with the new scope. Each iteration sharpens signal. The HTML report has manual Accept-Risk buttons as a fallback. No follow-up commands.

## Architecture

```text
Odoo Application Security Harness
├── Detection Engine          — Semgrep, Bandit, Ruff, pylint-odoo, CodeQL, Joern, pip-audit, osv-scanner
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
- Scores per-module risk (`module-risk.md` + `inventory/module-risk.json`) so hunters hit highest-risk modules first.
- Seeds hunters with `inventory/cwe-map.json` (19 Odoo bug-shape → CWE/CAPEC/OWASP mappings).
- Runs repeatable scanner setup for Semgrep, Bandit, Ruff, pylint-odoo, CodeQL, dependency tools, and optional Joern.
- Runs local Qwen advisory notes through Ollama.
- Launches or prepares Codex hunter tasks.
- Writes a `goals.md` guide for lead-session `/goals` tracking in Codex-capable review sessions.
- Produces `.audit/` artifacts for Claude's final 6-gate validation.
- Exports findings.json → SARIF 2.1.0, fingerprints, and HackerOne/Intigriti bounty drafts via `odoo-review-export`.
- Diffs two findings.json snapshots (new / fixed / changed) via `odoo-review-diff` for ongoing audits.
- Re-tasks Qwen or Codex mid-review via `odoo-review-rerun` and the `directives/` feedback loop.

The scanner and model outputs are leads, not final findings. The final report still requires Claude's 6-gate validation.

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
  - `odoo-review-export` — SARIF + fingerprints + bounty drafts
  - `odoo-review-diff` — baseline vs current findings comparison

## Prerequisites

Required for the full three-lane workflow:

```bash
brew install ollama
ollama pull qwen3:0.6b
```

Codex CLI must be installed and authenticated separately.

Optional scanner tools:

```bash
pipx install semgrep bandit ruff pylint pylint-odoo pip-audit
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

After a run produces `.audit/findings.json`, export to industry formats:

```bash
odoo-review-export .audit
# Emits:
#   .audit/findings.sarif              — SARIF 2.1.0 (GitHub Code Scanning, GitLab, etc.)
#   .audit/findings-fingerprints.json  — stable cross-run dedup hashes
#   .audit/bounty/F-N.md               — HackerOne/Intigriti-shaped drafts (one per ACCEPT)
```

Compare against a baseline (e.g., main-branch `.audit/`) for delta tracking:

```bash
odoo-review-diff .baseline/findings.json .audit/findings.json
# Emits:
#   .audit/delta.md   — markdown summary (new / fixed / changed / unchanged)
#   .audit/delta.json — machine-readable delta
```

## CI Integration

Drop-in GitHub Action template at `skills/odoo-code-review/templates/github-action.yml`:

- Runs PR-scoped review on every PR (`--pr <n>`), full sweep on push to main + weekly schedule.
- Uploads `findings.sarif` to GitHub Code Scanning (inline PR annotations + Security tab).
- Posts a sticky PR comment with delta vs main baseline.
- Persists `findings.json` + `delta.md` + `bounty/` as 90-day artifacts.

Copy to `.github/workflows/odoo-security.yml` in your addons repo and set `OPENAI_API_KEY` secret if Codex lane is desired.

## Output

Default output goes to:

```text
<repo>/.audit/
```

Important artifacts:

- `00-modules.md`
- `01-attack-surface.md`
- `module-risk.md` — per-module risk score + band (critical/high/medium/low)
- `goals.md`
- `directives/` — feedback-loop scratch space (`README.md`, `_template.md`, `D-NNNN-*.md`, `results/`)
- `inventory/manifests.json`
- `inventory/routes.json`
- `inventory/acl-index.json`
- `inventory/sharp-edge-index.json`
- `inventory/module-risk.json` — machine-readable risk score
- `inventory/cwe-map.json` — 19 Odoo bug-shape → CWE/CAPEC/OWASP mappings (seeds hunters)
- `inventory/scope.json` — applied scope.yml + computed inclusions/exclusions
- `local-qwen/module-notes.md`
- `scans/*`
- `codex/hunters/*`
- `tooling.md`
- `tooling.json`

Post-processing artifacts (after `odoo-review-export` / `odoo-review-diff`):

- `findings.sarif` — SARIF 2.1.0 (suppressions for accepted_risks)
- `findings-fingerprints.json` — stable hashes for cross-run dedup
- `bounty/F-N.md` — bounty submission drafts (one per ACCEPT, suppressed entries skipped)
- `delta.md`, `delta.json` — baseline-vs-current diff

## Sharing Notes

This repo does not include private Odoo source code, API keys, Claude session data, or local `.audit/` outputs. Review generated reports before sharing them outside a client or team boundary.
