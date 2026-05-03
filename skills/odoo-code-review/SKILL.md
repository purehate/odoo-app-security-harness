---
name: odoo-code-review
description: Source-code security review for Odoo using one Claude Code command with three lanes: Claude Code as lead reviewer/orchestrator, local Ollama/Qwen for private advisory triage, and Codex/OpenAI as the heavy worker for Odoo specialist hunters, discourse, chaining drafts, variant analysis, PoC/artifact work, and report drafting. Structured 0–8 phase audit of any Odoo addon repo. Phase 0 inventories modules + manifests. Phase 1 maps Odoo attack surface (routes/ACL/cron/mail). Phase 1.5 runs local Ollama/Qwen advisory triage for private first-pass module summaries and scanner-hint review. Phases 2–4.5 run Semgrep+custom Odoo rules, Bandit, ruff, pylint-odoo, OCA pre-commit, CodeQL Python, Joern (optional), Pysa, pip-audit, osv-scanner. Phase 5 delegates Odoo specialist hunter passes to Codex by default. Phase 5.5 delegates discourse draft to Codex, with Claude resolving disputes. Phase 6 uses Codex for chaining draft, Claude finalizes. Phase 7 uses Codex evidence packs/variant drafts, Claude performs final 6-gate verdicts. Phase 7.5 runtime testing and Phase 7.6 attack graphs are Codex/script heavy. Phase 8 uses Codex report draft, Claude final edits. Use when the user asks for a security review, code review, "audit this Odoo repo", appsec review, vuln hunt, or pentest of Odoo source. Outputs evidence-backed findings only — no scanner noise, no theoretical concerns, no style nits.
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
  - Edit
  - Write
  - Agent
  - TaskCreate
  - TaskUpdate
  - TaskList
  - TaskGet
---

# Code Review — Odoo

Structured, technique-organized AI security review of an Odoo source-code repository. Tuned for the two trust boundaries that matter in Odoo: **public-vs-authenticated** (`auth='public'`) and **user-vs-root** (`sudo()`).

## North Star

**Using this tool as an AI-assisted code-review companion makes the developer the best Odoo developer possible.** The harness is a teaching loop, not a one-shot scanner.

Every ACCEPT must teach. Per finding:

- **Why it's wrong in Odoo's model.** Cite the Odoo invariant being violated (e.g., "`@http.route(auth='public')` + `sudo()` crosses the public-vs-authenticated and user-vs-root boundaries simultaneously", or "computed field using `self.sudo()` causes recompute under privileged context for every user that triggers the dependency").
- **The Odoo-idiomatic fix.** Not "validate input" — `_check_company` + `company_id` filter; not "sanitize HTML" — `fields.Html(sanitize=True)` or `tools.html_sanitize()`; not "don't use sudo" — drop sudo and rely on `ir.model.access` + `ir.rule`, or scope sudo to one specific record with explicit reasoning. Cite Odoo source, docs, or OCA precedent where relevant.
- **The bug shape, not the bug.** After a finding lands, the developer should recognize the same shape next time without the tool.

Every REJECT must also teach: explain why Odoo's framework already handles the case (e.g., "the ORM parameterizes table identifiers via `psycopg2.sql.Identifier`; the f-string here interpolates a hardcoded constant, not user data"). Rejecting without explanation wastes the iteration.

Phase 7 hunters, fp-check gates, severity decisions, and `accepted_risks` reasons should all read as written by someone who has shipped Odoo to production and debugged it at 3am — not someone running a generic Python scanner. If a finding could be lifted verbatim from `bandit -r .`, it does not belong in a final report.

The iteration loop is the teaching mechanism: each `accepted_risks` reason in `scope.yml` becomes a paragraph of senior-level Odoo reasoning the developer wrote (or co-wrote with the AI) and can reuse.

Operating principle: **deep framework expertise > scanner breadth**. Semgrep + custom Odoo rules + agent validation beats 400 generic warnings every time.

## Run-Mode Contract (READ FIRST)

The runner writes `<OUT>/run-mode.json` and `<OUT>/00-run-mode.md` at the top of every run. Lead Claude MUST read `00-run-mode.md` before Phase 0/1 work and honor these flags:

- `non_interactive=true` (set only by `--yes`) → **never** emit `[y/N]` prompts. Pick the documented default action and proceed. This kills the Phase 8.7 step-4 prompt and any mid-stream "should I continue?" pauses.
- `learn=true` (set by `--learn` or `-ks`) → after Phase 8.6, run `scripts/odoo-review-learn <OUT>` to promote `findings.json` → `<repo>/.audit-baseline/findings.json` and write accepted-risk/fix-list suggestions. Use `--apply` only when `non_interactive=true` or the user explicitly approved the suggestions. Iteration cap: `learn_cap` (default 3).
- `baseline_stock_cc=true` (set by `--baseline-stock-cc` or `-ks`) → during Phase 1, dispatch one `subagent_type: general-purpose` Agent with the prompt at `<OUT>/baseline-stock/dispatch.md`. Before the run is considered complete, run `scripts/odoo-review-stock-diff <OUT>` and validate every stock-only entry in `<OUT>/baseline-stock/validation-leads.md` as a current-run lead. `odoo-review-finalize` fails while these remain unresolved. After disposition, optionally run `scripts/odoo-review-stock-diff <OUT> --apply-lessons` to append stock-only finding patterns to `references/agent-prompts.md`.
- `weekly=true` (set by `-ks` / `--ks` / `--kitchensink`) → kitchen-sink mode: max-quality full review. Equivalent to `--joern --runtime --breadth --json --learn --baseline-stock-cc` plus auto-detect of `<repo>/.audit-baseline/findings.json`, `<repo>/scope.yml`, `<repo>/.audit-accepted-risks.yml`, `<repo>/.audit-fix-list.yml`. Add `--yes` separately for zero prompts. Do not use `--allow-missing-lanes` for a serious `-ks` review unless you accept weaker coverage.

When `non_interactive=true` and `learn=true` are both set, the lead session runs end-to-end with NO user input from Phase 0 through Phase 8.7 baseline promotion. Otherwise, kitchen-sink mode is manual: full coverage, but the lead still presents suppression suggestions before applying them.

## Mode Simplicity

Use three primary modes:

- `--quick` — fast local pass. Useful while developing or checking an obvious risky area.
- `--pr <n>` — PR-scoped review through `gh`. Combine with `--quick` for quick PR triage.
- `-ks` / `--ks` — kitchen sink. The best available review regardless of token/runtime cost: scanners, Codex hunters, local Qwen, breadth sweep, stock-CC control lane, runtime evidence path, learn loop, and unresolved-stock-lead close gate.

Everything else is an escape hatch or advanced override.

Run `-ks` from Claude Code for the full workflow. The direct CLI runner can produce artifacts and execute scanners/Codex/Qwen, but it cannot spawn the stock-CC control Agent or replace Claude's final 6-gate judgment.

## Token Pressure / Qwen Handoff

Claude token exhaustion is not directly observable by the runner. The harness handles this with a standing handoff packet instead of pretending to detect it:

1. Every run writes `<OUT>/qwen-handoff/README.md` plus Qwen directives `D-9001..D-9003`.
2. When lead Claude context gets tight, run the listed `odoo-review-rerun <OUT>/directives/D-900*.md` commands.
3. Qwen returns hint-only risk clusters, likely-noise triage, and evidence-gap checklists under `<OUT>/directives/results/`.
4. After compaction or a fresh lead session, Claude reads those results and continues Phase 6/7. Qwen never makes final ACCEPT/REJECT/severity decisions.

## When to Use

- User asks for a security review, code review, source-code audit, appsec review, vuln hunt, pentest of source, or "audit this Odoo repo".
- Engagement is source-only (no live target) or starts with source.
- Repo contains custom Odoo addons (community/enterprise/OCA/third-party) — single addon to multi-million LOC.
- Findings need to be defensible to a client (evidence + reproduction + impact, not "scanner says so").

## When NOT to Use

- Single-file or single-PR review — use `superpowers:requesting-code-review`, `everything-claude-code:code-review`, or `differential-review` instead.
- Style / lint / dependency-CVE-only checks — use the relevant linter or `supply-chain-risk-auditor`.
- Live black-box pentest — use `wooyun-legacy` or `ffuf-web-fuzzing` skills.
- Threat modeling without code review — use `openai-security-threat-model`.
- Non-Odoo Python projects — the surface model and 10 hunters are Odoo-specific. For generic Python, use `everything-claude-code:python-review`.

## Hard Rules (Do Not Negotiate)

1. **Real exploitability only.** No theoretical, no "could be bad if X", no missing-input-validation without a dangerous sink shown.
2. **Cite evidence.** Every finding lands on a `file:line` and includes a concrete payload or reproducer (curl, XML-RPC, JSON-RPC, browser action, odoo-bin shell).
3. **Verify hunter claims by reading the actual code.** Hunters are smart but hallucinate. Phase 7 reads the bytes.
4. **No re-reporting fixed CVEs** unless you prove a regression in this codebase.
5. **Skip scanner noise.** Style, naming, "best practice without exploitability" — drop on the floor.
6. **Match severity to actual blast radius.** Internal-user → broader read != portal → internal user. DoS != RCE. Default-config != opt-in misuse.
7. **Match scope to what was asked.** Don't scope-creep into refactoring, fixes, or PRs unless the user asks.

## Rationalizations to Reject

| Rationalization                                     | Reality                                                                                       |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| "It's documented as the developer's responsibility" | If the API is the footgun (e.g., `sudo()`), it's still worth flagging — DOWNGRADE not REJECT. |
| "Browsers don't allow that"                         | Verify against RFCs. Server-to-server (XML-RPC, webhooks) often still applies.                |
| "It's behind authentication"                        | Portal != admin. `auth='user'` != `auth='public'`. Many bugs cross those boundaries.          |
| "It's an internal app"                              | Internal Odoo gets owned via SSRF, lateral movement, credential reuse, mass-assignment.       |
| "The ORM handles SQL injection"                     | `cr.execute()` bypasses the ORM. Identifiers can't be parameterised. ORDER BY isn't escaped.  |
| "QWeb auto-escapes"                                 | `t-raw` and `Markup()` and `fields.Html(sanitize=False)` all bypass.                          |
| "The user has admin already"                        | Admin can already do RCE — but cross-company / cross-tenant escalation still matters.         |
| "It's just DoS"                                     | Production DoS is a paging incident. HIGH if pre-auth + cheap.                                |
| "The hunter said it's a bug, ship it"               | Hunters hallucinate. Phase 7 reads the source.                                                |
| "I'll explain verbally"                             | No artifact = finding lost. Write the report.                                                 |

## The Phases

Run them in order. Don't skip Phase 0/1 — without the module inventory and attack surface map, hunters waste time on dead code. Don't skip Phase 7 — without verification, false positives reach the client.

## Local Runner

Start every `/odoo-code-review` run by invoking the bundled runner:

```bash
~/.claude/skills/odoo-code-review/scripts/odoo-review-run <target> <flags>
```

The runner handles preflight, output directory creation, manifest inventory, attack-surface indexing, scanner execution, Ollama/Qwen advisory output, and Codex hunter launch/prompt prep. Claude Code then continues with discourse, chaining, Phase 7 validation, severity decisions, and final report editing.

Use `--codex-mode prepare` when Codex prompts should be reviewed or launched manually. Use the default `--codex-mode run` for the full one-command three-lane workflow.

## Codex Goals Integration

If the lead review session supports `/goals`, create one lead-session goal after the runner writes `<OUT>/goals.md`. Use the suggested objective in that file and keep the goal open until Phase 8 is complete.

Use goals for the long-running lead/orchestrator thread only. Do not require every `codex exec` hunter subprocess to create its own goal; hunter prompts are bounded by output files and are already tracked by TaskCreate.

Goal checkpoints should mirror the review gates:

- Phase 0/1 inventory and attack-surface map exist.
- Scanner/advisory leads are captured or skipped in `tooling.md`.
- Phase 5 hunter drafts exist.
- Phase 5.5/6 discourse and chaining are resolved.
- Phase 7 candidate findings have final triage and 6-gate reasoning.
- Phase 8 final report and reproducibility appendix are written.

## Directive Feedback Loop

When the lead session reads existing `.audit/` artifacts and concludes a lane needs rework — for example, "rescan portal routes for `@http.route` + `sudo()` combos" or "Codex builds a PoC sketch for finding F-7" — Claude writes a directive instead of doing the work itself.

Workflow:

1. The runner seeds `<OUT>/directives/` with `README.md` and `_template.md` on every run.
2. Claude copies `_template.md` to `D-NNNN-<slug>.md`, fills the YAML frontmatter (`target_lane`, `task_type`, `scope`, `model`) and body (Why / Ask / Expected Output).
3. Run the dispatcher:
   ```bash
   odoo-review-rerun <OUT>/directives/D-0001-portal-sudo.md
   ```
4. The dispatcher writes `<OUT>/directives/results/D-0001-portal-sudo.result.md` and flips the directive's `status:` from `pending` → `done` (or `failed`).
5. Claude reads the result, decides whether to issue more directives, fold the result into the relevant phase artifact, or move on.

`target_lane: qwen` produces hint-only output (no ACCEPT/REJECT). `target_lane: codex` runs read-only by default and `workspace-write` only when `task_type: build-poc`. Use directives sparingly — they exist for targeted follow-ups, not full hunter passes (those still live in Phase 5).

## One-Command Three-Lane Orchestration

When run from Claude Code via `/odoo-code-review`, use all three lanes in one run:

| Lane           | Invocation                 | Responsibility                                                                                                                                                                 |
| -------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Lead reviewer  | Claude Code session        | Scope, orchestration, risk judgment, dispute resolution, final 6-gate verdicts, final report edit                                                                              |
| Local advisory | `ollama run <local-model>` | Phase 1.5 private module notes, scanner triage, obvious reject candidates                                                                                                      |
| Heavy worker   | `codex exec` / Codex CLI   | Phase 5 hunters, Phase 5.5 discourse draft, Phase 6 chaining draft, Phase 7 variant/evidence packs, PoC writeability, runtime/ZAP harness support, attack graphs, report draft |

Qwen output is always `HINT` only and cannot create ACCEPT findings, reject findings, or set final severity. Codex does the expensive reading and drafting, but Claude remains the final arbiter for ACCEPT/DOWNGRADE/REJECT, severity, and client-ready wording.

Codex invocation pattern:

```bash
codex exec -C <repo> -m gpt-5.3-codex -s read-only --ask-for-approval never -o <OUT>/codex/<task>.md -- "<task prompt>"
```

Use `-s workspace-write` only for artifact-generation tasks under `<OUT>` such as runtime harnesses, DOT/SVG attack graphs, and report drafts. Never let Codex modify source unless the user explicitly asks for fixes.

### Phase 0 — Odoo Module Inventory + Manifest Map

Enumerate every addon. Parse every `__manifest__.py` (name, version, depends, data, external_dependencies, license). Build the depends-graph. Tag origin (core/enterprise/OCA/custom/third-party). Index every `data:` entry so Phase 1 and Phase 5 can grep into them. Writes `<OUT>/00-modules.md` and `<OUT>/inventory/`.

Phase 0 also loads the optional accepted-risks suppression file (`<repo>/.audit-accepted-risks.yml`, override with `--accepted-risks <path>`). The loader validates schema (per `references/accepted-risks.md`), aborts the run on validation errors, and writes `<OUT>/00-accepted-risks.md` (human-readable summary, EXPIRED + STALE buckets) plus `<OUT>/inventory/accepted-risks.json` (machine-readable). Hunters and Phase 7 Gate 0 read the JSON to suppress already-triaged findings via stable 16-hex `fingerprint` (primary key, sha256 over `f"{file}:{primary_line}:{sink_kind}:{title.strip().lower()}"[:16]`) or legacy `file`/`lines`/`match` heuristic. Each emitted finding in `findings.html` carries a "Mark as accepted risk" button that copies a pre-filled YAML stanza in our exact schema, so adding a new suppression is one click. This is the per-finding fingerprint layer; `--scope <file>` (see Flags) is the broader engagement-scope layer with its own coarser `accepted_risks` block.

Phase 0 also loads the optional fix-it tracking file (`<repo>/.audit-fix-list.yml`, override with `--fix-list <path>`). This is the symmetric companion to accepted-risks: same canonical fingerprint, but a different verdict — _"this IS a real bug, we are tracking the fix"_. The loader validates schema (per `references/fix-list.md`), aborts on errors, and writes `<OUT>/inventory/fix-list.json` plus a Phase-0 snapshot at `<OUT>/00-fix-list.md` listing active and overdue entries. Phase 8 reconciliation then matches every emitted finding against fix-list entries by fingerprint and produces the final `00-fix-list.md` buckets: **TRACKED** (status `open`/`in-progress` + finding present), **LIKELY-FIXED** (status `open`/`in-progress` + finding gone), **REGRESSION** (status `fixed` + finding present, **red banner**), **CONFIRMED-FIXED** (status `fixed` + finding gone), **WONTFIX** (status `wontfix` + finding present, passive tag), **DRIFTED** (status `wontfix` + finding gone). `findings.html` carries a second per-card button — "Add to fix-it list" — that copies a pre-filled YAML stanza with the fingerprint already populated, so the human reader's only triage action per finding is exactly one click: accept-risk OR fix-it. Fix-list entries do **not** suppress findings — they are emitted with a tracking pill (`tracked: FIX-NNN`, `REGRESSION`, or `wontfix`).

### Phase 1 — Odoo Attack Surface Map

Identify Odoo version + edition + Python + Postgres + Werkzeug. Map HTTP routes (`@http.route` decorators with auth/csrf/type/methods), RPC entry points (`xmlrpc/2/object`, `jsonrpc`), portal routes (`/my/*`), models touched by public/portal routes, ACL CSV rows, `ir.rule` records, server actions, cron, mail templates. Risk-rank modules 1–5. Plan hunter assignments. Writes `<OUT>/01-attack-surface.md` with a per-module surface section so downstream hunters know exactly what each module exposes.

**Default scope expansion (2026-05):** the runner now also sweeps `docs/server_actions/*.py` and `scripts/*.py` as pseudo-modules (origin tags `server_action` / `script`). Disable with `--no-server-actions` / `--no-scripts` if reviewing a tree that uses those folders for non-Odoo content.

**Phase 1 fail-loud (2026-05):** the runner asserts each in-scope module has at least `--phase1-min-lines-per-module` (default 4) content lines in `01-attack-surface.md`. A near-empty surface map silently misroutes hunters; the runner now exits with code 6 when the threshold is missed. Override with `--no-phase1-assert` (escape hatch — not recommended).

See `references/workflow.md` Phase 1 for the full checklist.

### Phase 1.7 — Breadth Sweep Dispatch (eve-cc style)

Runner emits `<OUT>/inventory/breadth/dispatch.json` listing file chunks (default 40 files / chunk; override via `--breadth-chunk-size`). Lead Claude dispatches one Agent (`subagent_type: general-purpose`) per chunk in parallel batches, eve-cc style. Each subagent enumerates every public route, `sudo()`, `cr.execute`, `eval/exec`, `ir.rule` gap, and authentication boundary in its slice and appends a section to `<OUT>/inventory/breadth/leads.md`.

The hunters in Phase 5 ingest `leads.md` as additional input. This pairs eve-cc breadth with harness depth: every file gets a fast scan, then specialist hunters pivot into deep analysis on the leads. Disable with `--no-breadth`.

### Phase 1.5 — Local Qwen / Ollama Advisory Check

Runs by default in the one-command Claude Code workflow unless `--no-local-qwen` is set. This is a local-only, no-cloud advisory pass through Ollama after Phase 1 and again after scanner output exists. Default model: `qwen3:0.6b`, override with `--local-model <ollama-model>`.

Use it for privacy-preserving first-pass summaries, module risk notes, scanner output triage, and obvious reject candidates. Treat Qwen output as hints only. It cannot create ACCEPT findings, change severity, or replace Phase 7 verification.

Outputs → `<OUT>/local-qwen/module-notes.md`, `<OUT>/local-qwen/scanner-triage.md`, and `<OUT>/local-qwen/reject-candidates.md`.

### Phase 2 — Semgrep Python/Odoo Rules

Community rulesets: `p/python`, `p/owasp-top-ten`, `p/trailofbits`, `p/0xdea`. Custom rules in `.semgrep/odoo.yml` covering `auth='public'+sudo()`, `csrf=False` without HMAC, `cr.execute(f"...")`, `t-raw=` on user data, `request.params` → `write/create`, `ir.config_parameter.set_param` from controllers, `with_user(env.ref('base.user_admin'))`, etc.

### Phase 2.5 — Bandit Sweep

Generic Python AppSec issues Semgrep misses (assert in prod, tempfile.mktemp, weak hashes, hardcoded passwords).

### Phase 2.6 — Ruff + pylint-odoo + OCA pre-commit

Ruff with `select=["S","B","PIE","BLE","ARG","RET"]`. `pylint --load-plugins=pylint_odoo --enable=odoolint`. OCA pre-commit. `pylint-odoo` is the bridge — knows `@api.model`, `_name`, `_inherit`, Translation, `<record>` rules.

### Phase 3 — CodeQL Python Dataflow

`codeql database create --build-mode=none --language=python` then analyze with `python-security-and-quality.qls` and `python-security-experimental.qls`.

### Phase 3.5 — Joern Graph Review (Optional)

Triggered by `--joern`. CPG-based graph traversal catches multi-hop / `getattr`-dispatched / metaclass-resolved flows CodeQL standard suites miss. Build CPG via `joern-parse <repo> --language pythonsrc`, run query batch (eval/exec/safe_eval reachability, cr.execute non-literal, sudo propagation, controller→model paths, deserialization, SSRF, path traversal). Treat hits as leads for Phase 5, not findings. Skip when SMALL (<20k LOC) or `--quick`.

### Phase 4 — Pysa Optional Taint Analysis

`pyre analyze --no-verify`. Skip if Pyre setup fails (Odoo's metaclass-heavy ORM often confuses it). Catches multi-hop taint Semgrep misses.

### Phase 4.5 — Dependency Scan

`pip-audit` + `osv-scanner`. Cross-reference manifest external_dependencies with Phase 1 reachability.

Full commands: `references/automated-scans.md`. Output is **hints not truth** — feed to hunters, verify in Phase 7.

### Phase 5 — Odoo Specialist Hunters via Codex

Delegate the 9 technique hunter passes to Codex by default to preserve Claude limits. Each owns one technique class across the whole repo. Hunters get the Phase 0 module map + Phase 1 surface map + Phase 1.5 Qwen hints + Phase 2–4.5 scan paths. Write outputs to `<OUT>/agents/hunter-*.md`.

Claude's job in Phase 5 is to prepare compact packets, launch/track Codex tasks, and spot-check returned claims before Phase 5.5. Claude should not spend context doing full hunter sweeps unless Codex is unavailable.

Hunter packets MUST include the paths to `<OUT>/inventory/accepted-risks.json`, `<OUT>/inventory/fix-list.json`, `<OUT>/inventory/py-files-by-module.json`, and `<OUT>/inventory/breadth/leads.md` (if present).

**Coverage-proof contract (2026-05):** every hunter MUST emit a `Reviewed:` block at the very top of its output listing the modules and concrete file:line ranges it inspected. Empty `Reviewed:` blocks are a contract violation. Phase 5.6 diffs the `Reviewed:` blocks against `py-files-by-module.json` and emits per-hunter gaps for re-dispatch. Each hunter computes the candidate fingerprint before emitting and silently drops any accepted-risks match (Gate 0 short-circuit) so the lead session never sees re-litigated findings. Hunters also stamp every emitted finding with a `Fingerprint:` line and `Sink kind:` line per the contract in `references/agent-prompts.md`, so `findings.html` can wire the per-card buttons without recomputation. Hunters do **not** suppress on a fix-list match; instead they tag emitted findings: `Tracked by FIX-NNN (target YYYY-MM-DD)` for `open`/`in-progress`, `REGRESSION — fix-list FIX-NNN marked status=fixed` for `fixed` (a flagged regression), `wontfix per FIX-NNN` for `wontfix`. The full reconciliation buckets are produced in Phase 8 from `inventory/fix-list.json` cross-referenced against the final ACCEPT findings.

The 10 Odoo hunters:

1. **Access Control** — ACL CSV, `ir.rule`, groups, `sudo()`/`with_user()`/`with_context()` misuse
2. **Controller / Route** — `@http.route`, `request.params/jsonrequest`, CSRF, IDOR, mass-assignment
3. **ORM / SQL / Domain** — `cr.execute`, raw SQL, domain injection, `search([])`, `unlink()`, mass-assignment
4. **QWeb / XSS** — `t-raw`, `Markup()`, `fields.Html(sanitize=False)`, mail body, OWL `innerHTML`
5. **Business Logic** — state machines, races, workflow bypass, `ir.actions.server` `state='code'`, cron
6. **Secrets / Config** — hardcoded secrets, `ir.config_parameter`, `odoo.conf`, debug PIN, `list_db`/`admin_passwd`
7. **External Integration** — `requests`/`urllib`/SSRF, webhook signature verify, mail header injection, LDAP, OAuth
8. **Data Exposure** — `/my/*` portal, `ir.attachment` `public=True`, chatter, reports, xmlrpc enumeration
9. **Dependency** — `requirements.txt`, OCA pins, base image, JS deps in `static/src`
10. **Chaining** — runs after #1–9 in Phase 6, combines lower-severity findings into higher-impact paths

Full prompt templates: `references/agent-prompts.md`.

### Phase 5.5 — Discourse / Cross-Hunter FP Reduction

Delegate the first discourse draft to Codex. Hunters review each other's findings using AGREE / CHALLENGE / CONNECT / SURFACE tags. Claude resolves disputed CHALLENGE items and decides what enters Phase 6. Skip only if `--quick` or repo SMALL.

Pattern: `references/discourse.md`.

### Phase 5.6 — Hunter Coverage Diff (eve-cc gap closure)

Run `scripts/odoo-review-coverage <OUT>` after Phase 5 hunters return. The script:

1. Reads `<OUT>/inventory/py-files-by-module.json` for the expected module set.
2. Parses the `Reviewed:` block from every `<OUT>/codex/hunters/*.md` and `<OUT>/agents/*.md`.
3. Emits `<OUT>/coverage/coverage.{json,md}` (matrix) and `<OUT>/coverage/gaps.md` (per-hunter missing modules).

Pass `--fail-on-gap` in CI to block merges when any hunter skipped a module without justification. When gaps are detected, lead Claude re-dispatches the affected hunters with a tighter scope. This phase is the eve-cc countermeasure: it forces every module to be opened by every relevant hunter, eliminating the silent-skip class that produced the 15-vs-53 finding-count gap.

### Phase 6 — Cross-Agent Correlation (Chaining)

Ask Codex for a chaining draft, then have Claude finalize. Combine findings into higher-impact paths. The Odoo trust model amplifies certain combos:

- `auth='public'` + `sudo()` + sensitive model = **unauthenticated data dump**
- Mass-assignment on `res.users.group_ids` + `auth='user'` = **user → admin**
- QWeb `t-raw` + `message_post` from portal = **stored XSS in admin chatter**
- SQL injection in `cr.execute` + `database.secret` leak = **session forgery + DB write**
- `safe_eval` sandbox bypass + `ir.cron` `user_root` = **persistent RCE**

The chaining hunter (#10) gets discourse-CONNECT entries as high-prior chain candidates.

### Phase 7 — Validation (7-Gate fp-check + Variant Analysis + Negative Space)

Three sub-passes:

1. **Codex evidence pack per finding** — source context, reachability trace, attacker-control notes, PoC sketch, assumptions.
2. **Claude 7-gate fp-check per finding** — Gate 0 (accepted-risks suppression: fingerprint primary, legacy fallback, expiry check) → source-matches → reachable → attacker-controls → realistic-preconditions → pseudocode-PoC → impact-matches-severity. ACCEPT only if Gate 0 is NOT-MATCH AND every substantive gate PASSes. Gate 0 MATCH → SKIP (recorded in `<OUT>/00-accepted-risks.md`, never enters `findings.md`). (`references/fp-check.md`)
3. **Codex variant analysis draft on each ACCEPT** — extract bug shape, fan out grep/Semgrep across the whole repo, group siblings under the parent finding. Claude reviews the grouped variants. (`references/variant-analysis.md`)
4. **Negative-space audit** — Codex drafts checklist coverage; Claude confirms any reportable gaps. (`references/insecure-defaults.md`, distinct from `references/sharp-edges.md`.)

Triage:

- **ACCEPT** — Gate 0 NOT-MATCH and all 6 substantive gates PASS. Real, exploitable, meaningful impact.
- **DOWNGRADE** — gates 1–5 PASS, gate 6 fails — keep finding, lower severity.
- **REJECT** — any of gates 1–3 FAIL.
- **SKIP** — Gate 0 MATCH (already triaged in accepted-risks file). Tracked in `<OUT>/00-accepted-risks.md`, not in `findings.md`.
- **NEEDS MANUAL TESTING** — plausible from source but a gate requires runtime confirmation.

Triage rubric + output format: `references/triage.md`.

### Phase 7.5 — Runtime Odoo Testing (Optional)

Triggered by `--runtime`. Two sub-passes:

- **Sub-pass A — odoo-bin runtime helper.** Run `scripts/odoo-review-runtime <OUT>` with explicit launch details (`--odoo-bin`, `--config`/`--database`, `--addons-path`) to boot Odoo, wait for `/web/login`, replay ACCEPT-finding PoC scripts with `ODOO_BASE_URL`, and capture logs/status/stdout under `<OUT>/runtime/`.
- **Sub-pass B — ZAP baseline (only if `--zap-target <url>`).** Run `zap-baseline.py` against the booted Odoo. macOS Docker quirk: mount needs `--user 0` and `chmod 777` on the wrk dir. Output → `<OUT>/runtime/zap/zap-baseline.{html,json}`.

Required when Gate 5 (PoC) demands runtime evidence.

### Phase 7.6 — Attack Graph DOT/SVG (Chained Findings)

Auto-runs when Phase 6 produced 2+ chained findings. Emits Graphviz DOT + rendered SVG per chain to `<OUT>/attack-graphs/chain-N.{dot,svg}`. Nodes = entry point / model / action. Edges = trust-boundary crossings (anonymous→authenticated, user→sudo, portal→internal, tenant A→B, internal→root). Embedded inline in `findings.html` so report stays self-contained.

### Phase 7.7 — Codex Adversarial Check

Runs by default on CRITICAL/HIGH ACCEPT findings unless `--no-codex` is set. Because Codex already performed heavy evidence work, this pass must use a fresh Codex prompt/session that sees only the final finding card and source snippets, not the prior Codex draft. Each finding is handed to Codex/OpenAI for independent verdict + PoC-write attempt. Reconciliation table:

| Codex                   | odoo-code-review | Result                                        |
| ----------------------- | ---------------- | --------------------------------------------- |
| ACCEPT                  | ACCEPT           | keep ACCEPT, +1 confidence                    |
| REJECT                  | ACCEPT           | force NEEDS-MANUAL, log disagreement          |
| DOWNGRADE               | ACCEPT           | re-evaluate severity if limiting factor sound |
| writes PoC              | no PoC           | attach Codex PoC, raise confidence            |
| no PoC and no other PoC | n/a              | downgrade to NEEDS-MANUAL                     |
| ACCEPT                  | DOWNGRADE        | keep DOWNGRADE, note Codex stronger view      |

Outputs → `<OUT>/codex/second-opinion/verdicts/F-N.md` + `<OUT>/codex/second-opinion/reconciliation.md`.

### Phase 7.8 — Requirements-Aware Verification (Optional)

Triggered by `--requirements <file>`. Extract claims → compile predicates → dispatch judges → repair-loop (≤2 rounds) → R-N findings. Catches missed-requirement bugs.

Procedure: `references/requirements-mode.md`.

### Phase 8 — Output Assembly

Have Codex draft `findings.md`, `findings.html`, `findings.json` when requested, and `tooling.md` from the verified Phase 7 records. Claude performs the final edit, removes unsupported claims, checks severity language, and ensures every ACCEPT has evidence and a 6-gate table.

Phase 8 also performs **fix-list reconciliation** against `inventory/fix-list.json`. Every ACCEPT finding fingerprint is matched against the fix-list; matches receive a tracking pill in `findings.html` (green `tracked: FIX-NNN`, red `REGRESSION`, or grey `wontfix`). The runner then emits `<OUT>/00-fix-list.md` with buckets in fixed read-order: REGRESSION → OVERDUE → TRACKED → CONFIRMED-FIXED → LIKELY-FIXED → WONTFIX → DRIFTED. Each finding card in `findings.html` carries two buttons — "Mark as accepted risk" (suppression) and "Add to fix-it list" (tracking) — so the human reader's per-finding triage is one of two clicks. See `references/fix-list.md` for the schema and `references/html-report.md` for the button spec.

## Workflow Checklist (Track in TaskCreate)

- [ ] Phase 0: create `<OUT>` dir, find every `__manifest__.py`, parse to JSON, build depends graph, tag origins.
- [ ] Phase 1: identify Odoo version + stack, map HTTP/RPC/portal surface, ACL CSV, `ir.rule`, cron, mail templates, draft hunter assignments. Runner asserts ≥ N content lines per module in `01-attack-surface.md` (fail-loud, exit code 6).
- [ ] If available, create/update the lead-session `/goals` objective from `<OUT>/goals.md`; keep TaskCreate for per-phase and per-hunter progress.
- [ ] Phase 1.5 (unless `--no-local-qwen`): run local Ollama/Qwen advisory module notes and scanner-hint triage → `<OUT>/local-qwen/`.
- [ ] Phase 1.7 (unless `--no-breadth`): read `inventory/breadth/dispatch.json`, dispatch Agent calls in parallel batches (eve-cc breadth pass), collect leads into `inventory/breadth/leads.md`.
- [ ] Phase 2: Semgrep community + custom Odoo rules → `<OUT>/scans/semgrep/`.
- [ ] Phase 2.5: Bandit → `<OUT>/scans/bandit/`.
- [ ] Phase 2.6: ruff + pylint-odoo + OCA pre-commit → `<OUT>/scans/ruff/`, `pylint-odoo/`, `oca-precommit/`.
- [ ] Phase 3: CodeQL Python DB extract + analyze → `<OUT>/scans/codeql/`.
- [ ] Phase 3.5 (only if `--joern`): build CPG, run query batch → `<OUT>/scans/joern/`.
- [ ] Phase 4: Pysa (optional, skip on Pyre failure) → `<OUT>/scans/pysa/`.
- [ ] Phase 4.5: pip-audit + osv-scanner → `<OUT>/scans/deps/`.
- [ ] Phase 5: launch Codex hunter tasks #1–#9 with Phase 0/1 packets, Qwen hints, scan paths, and `inventory/breadth/leads.md`. Each hunter MUST emit a `Reviewed:` block.
- [ ] Phase 5: Claude spot-checks hunter outputs for unsupported claims before discourse.
- [ ] Phase 5.5: Codex discourse draft; Claude resolves CHALLENGE items (skip if `--quick` or SMALL repo).
- [ ] Phase 5.6: run `scripts/odoo-review-coverage <OUT>`. Re-dispatch any hunter with gaps in `coverage/gaps.md`.
- [ ] Phase 6: Codex chaining draft; Claude finalizes chained paths.
- [ ] Phase 7: Codex evidence packs; Claude 6-gate fp-check per finding.
- [ ] Phase 7: Codex variant-analysis fan-out per ACCEPT; Claude verifies grouped variants.
- [ ] Phase 7: Codex negative-space draft; Claude confirms reportable gaps.
- [ ] Phase 7.5 sub-pass A (only if `--runtime`): run `odoo-review-runtime <OUT>` with Odoo launch details, replay PoC scripts, capture evidence.
- [ ] Phase 7.5 sub-pass B (only if `--runtime --zap-target <url>`): Codex/scripts run ZAP baseline → `<OUT>/runtime/zap/`.
- [ ] Phase 7.6 (auto when 2+ chained findings): Codex/scripts emit DOT + SVG → `<OUT>/attack-graphs/`.
- [ ] Phase 7.7 (unless `--no-codex` and only when CRITICAL/HIGH ACCEPT exists): fresh Codex adversarial check → `<OUT>/codex/second-opinion/`.
- [ ] Phase 7.8 (only if `--requirements <file>`): extract claims, compile predicates, judges, repair-loop, R-N findings.
- [ ] Phase 8: Codex draft + Claude final edit for `findings.md` + `findings.html` (unless `--no-html`) + `tooling.md`.
- [ ] Phase 8: fix-list reconciliation against `inventory/fix-list.json` → `<OUT>/00-fix-list.md` REGRESSION/OVERDUE/TRACKED/CONFIRMED-FIXED/LIKELY-FIXED/WONTFIX/DRIFTED buckets.
- [ ] Engagement stats: modules, LOC, wall-clock, tokens, findings by severity.
- [ ] Reproducibility appendix: `<OUT>/tooling.md` with tool versions + commands run.

Each Phase 5 hunter MUST be tracked as its own TaskCreate so the user sees progress and so completion notifications map cleanly.

## Flags

- `--out <dir>` — override default `<repo>/.audit-YYYYMMDD-HHMM/` output dir.
- `--with-discourse` / `--no-discourse` — force Phase 5.5 on/off (default: on except `--quick`).
- `--quick` — skip Phases 2–4.5 + Phase 5.5; hunters only on Phase 0/1 maps.
- `--no-local-qwen` — skip local Ollama/Qwen advisory triage.
- `--local-model <name>` — override local Ollama model (default: `qwen3:0.6b`).
- `--allow-missing-lanes` — continue if the local Qwen or Codex lane is unavailable; record the skip in `tooling.md`.
- `--joern` — enable Phase 3.5 Joern CPG graph review (skip on SMALL or `--quick`).
- `--runtime` — enable Phase 7.5 sub-pass A. Use `odoo-review-runtime <OUT>` with Odoo launch details to boot Odoo and replay PoCs.
- `--zap-target <url>` — also run Phase 7.5 sub-pass B (ZAP baseline). Requires `--runtime`.
- `--no-codex` — skip Codex heavy-worker lane and Phase 7.7 adversarial check; Claude performs all review work locally.
- `--requirements <file>` — enable Phase 7.8 requirements-aware verification.
- `--no-html` — skip `findings.html` generation in Phase 8 (default: on).
- `--json` — emit `findings.json` sidecar in Phase 8.
- `--modules <list>` — restrict scope to comma-separated module names.
- `--odoo-version <N>` — override Odoo version detection (e.g., `17.0`).
- `--scope <file>` — apply a `scope.yml` (`excluded_modules`, `excluded_paths`, `accepted_risks` with id/module/file/rule/cwe/line_range/reason/expires). Exclusions filter Phase 0 manifests; accepted-risks become SARIF `suppressions` at export time. Coarse-grained engagement scope. See `references/scope.example.yml`.
- `--pr <n>` — restrict scope to files changed in PR `<n>` (uses `gh pr view --json files`). Combine with `--pr-repo owner/repo` if not in the same checkout.
- `--pr-repo <owner/repo>` — override PR-target repo for `--pr`.
- `--accepted-risks <path>` — override default `<repo>/.audit-accepted-risks.{yml,yaml,json}` location. Per-finding fingerprint suppression layer (distinct from `--scope`'s coarser layer). See `references/accepted-risks.md`.
- `--check-only-accepted-risks` — validate accepted-risks file, write `<OUT>/inventory/accepted-risks.json` + `<OUT>/00-accepted-risks.md`, then exit. Non-zero on validation errors or expired entries. Use in CI to catch rot.
- `--fix-list <path>` — override default `<repo>/.audit-fix-list.{yml,yaml,json}` location. Per-finding fingerprint **tracking** layer (real bugs the team has committed to fixing). Findings are tagged, not suppressed. See `references/fix-list.md`.
- `--check-only-fix-list` — validate fix-list file, write `<OUT>/inventory/fix-list.json` + `<OUT>/00-fix-list.md`, then exit. Non-zero on validation errors or any `open`/`in-progress` entry past its `target_date`. Use in CI to gate the backlog.
- `--no-server-actions` — skip `docs/server_actions/*.py` loose-Python sweep (default: include).
- `--no-scripts` — skip `scripts/*.py` loose-Python sweep (default: include).
- `--no-breadth` — skip Phase 1.7 breadth-sweep dispatch plan emission (default: emit).
- `--breadth-chunk-size <N>` — files per breadth-sweep subagent chunk (default: 40).
- `--phase1-min-lines-per-module <N>` — Phase 1 fail-loud threshold: minimum content lines per module in `01-attack-surface.md` (default: 4).
- `--no-phase1-assert` — disable Phase 1 fail-loud assertion (escape hatch — not recommended).

## Post-Processing Scripts

The runner emits `findings.json` (after Phase 8). Four companion scripts process it:

- **`odoo-review-finalize <OUT>`** — canonical Phase 8.6 wrapper. Runs export + diff, auto-detects baseline (`<OUT>/../.audit-baseline/findings.json` or `$ODOO_REVIEW_BASELINE`), runs the stock-CC unresolved-lead gate when `baseline_stock_cc=true`, stamps `finalize.log`, exits non-zero when ACCEPT severity ≥ `--fail-on` (default `high`) or stock-only leads remain unresolved. Use this from CI / non-Claude paths or manual re-export. `--fail-on none` disables only the severity gate; `--no-stock-gate` disables the stock gate.
- **`odoo-review-runtime <OUT>`** — Phase 7.5 runtime helper. Boots Odoo from explicit `--odoo-bin`/`--config`/`--database`/`--addons-path` inputs, waits for a health URL, captures logs/status, and runs PoC scripts with `ODOO_BASE_URL`.
- `odoo-review-export <.audit-dir>` — direct SARIF 2.1.0 + fingerprints + bounty/F-N.md emit. Called by `finalize`; expose for one-off re-export. Honors `scope.json` accepted_risks as SARIF `suppressions` unless `--no-suppress`.
- `odoo-review-diff <baseline> <current>` — classifies findings new / fixed / unchanged / changed (severity OR triage delta) by `fingerprint`. Emits `delta.md` + `delta.json`. Called by `finalize` when baseline detected.
- `odoo-review-rerun <directive>` — directive feedback-loop dispatcher (Qwen or Codex). See "Directive Feedback Loop" above.
- `odoo-review-coverage <OUT>` — Phase 5.6 coverage diff. Parses `Reviewed:` blocks from hunter outputs, diffs against `inventory/py-files-by-module.json`, emits `coverage/coverage.{json,md}` + `coverage/gaps.md`. Pass `--fail-on-gap` to gate CI when any hunter skipped a module without justification.

## CI Template

`templates/github-action.yml` is a drop-in `.github/workflows/odoo-security.yml`:

- PR-scoped review on `pull_request` (auto `--pr <n>`).
- Full sweep on `push` to main, or run `/odoo-code-review -ks` manually on your chosen cadence.
- Uploads `findings.sarif` to GitHub Code Scanning (`security-events: write`).
- Sticky PR comment with `delta.md` (vs main baseline artifact).
- 90-day artifact retention for `findings.json`, `delta.md`, `bounty/`.

## Reference Files

Load only what applies to the engagement:

- `references/lang-odoo.md` — Odoo framework patterns (manifest, models, controllers, ACL, sudo, safe_eval)
- `references/lang-qweb.md` — QWeb / OWL templating sinks (`t-raw`, `Markup`, mail body, `innerHTML`)
- `references/lang-python.md` — generic Python AppSec (Django/Flask/FastAPI fallbacks, SQLAlchemy, pickle/yaml)
- `references/lang-web.md` — TypeScript/Node (only relevant for `static/src` JS)
- `references/sharp-edges.md` — footgun APIs incl. Odoo section
- `references/insecure-defaults.md` — config-level defaults incl. Odoo section
- `references/weekly-workflow.md` — recurring manual-review loop: stamped run dirs, master accepted-risks + fix-list, triage flow, `--prune-old-runs`
- `<OUT>/qwen-handoff/README.md` — generated token-pressure fallback packet for local Qwen.

## Output

Phase 8 emits two reports — `findings.md` (canonical, line-citable) and `findings.html` (single-file, self-contained, severity color-coded, embedded SVG attack graphs). `--no-html` skips HTML; `--json` adds `findings.json` sidecar.

Every engagement ends with:

1. **Findings table** — Title / Severity / Confidence / Affected Files / Triage.
2. **Per-finding detail** — full Odoo finding format from `references/agent-prompts.md` Common Header. Each ACCEPT carries:
   - 6-row fp-check gate table (`references/fp-check.md`)
   - Variants sub-table (`references/variant-analysis.md`)
   - `Odoo surface:` field (route / model / view / cron / wizard / server-action)
   - Codex 2nd-opinion verdict + reconciliation note for CRITICAL/HIGH ACCEPT findings
3. **Chained attack paths** — one block per chain, with embedded Phase 7.6 SVG.
4. **Negative-space summary** — insecure-defaults missed by hunters (`references/insecure-defaults.md` Odoo section).
5. **Discourse summary** — consensus / challenged / connected / surfaced (Phase 5.5 record).
6. **Engagement stats** — modules, LOC scanned, wall-clock, tokens used, hunter-by-hunter table.
7. **Reproducibility appendix** — `<OUT>/tooling.md`: Odoo version, model/provider lane table, Semgrep ruleset hashes (incl. custom `.semgrep/odoo.yml@<sha>`), CodeQL pack versions, Ollama/Qwen version, Joern/ZAP/Codex/Graphviz versions, exact commands run.
8. **Recommended actions** — file upstream issue (with OCA / Odoo S.A. / vendor), hardening PR, or no action with reason.

Stats demonstrate AI speed-up to client/AppSec leadership. Never skip them.

## Adapt Depth to Repo Size

| Size                                | Approach                                                                                                                                                                                                                       |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| SMALL (1–5 modules, <20k LOC)       | Single hunter pass per technique, deep read. Skip Phase 5.5.                                                                                                                                                                   |
| MEDIUM (5–30 modules, 20k–200k LOC) | All 10 hunters, single pass. ~5–10 min wall-clock.                                                                                                                                                                             |
| LARGE (30–100 modules, 200k–2M LOC) | Hunters with module-scoping (split risk-5 from risk-1). ~10–20 min wall-clock.                                                                                                                                                 |
| HUGE (>100 modules, >2M LOC)        | Multi-pass: hunters first run on highest-risk modules only, then expand. Under `non_interactive=true` (`--yes`) auto-cap to top-30 risk-ranked modules and proceed; under default mode, discuss scope cap with user. |

## Philosophy

For Odoo, Semgrep + custom Odoo rules + CodeQL/Pysa + agent validation beats adding a pile of generic scanners. The money is in finding **"public route calls sudo and returns sensitive model data"** — not 400 generic Python warnings.

Hunters know Odoo semantics. The two trust boundaries (`auth='public'` and `sudo()`) anchor every triage decision. Severity reflects whose data crosses which boundary.

## See Also

- `references/workflow.md` — exhaustive phase detail (Phases 0–8)
- `references/automated-scans.md` — Phases 2–4.5 commands (Semgrep + custom Odoo + Bandit + ruff + pylint-odoo + CodeQL + Pysa + pip-audit + osv-scanner)
- `references/agent-prompts.md` — 10 Odoo hunter prompt templates
- `references/discourse.md` — Phase 5.5 hunter-vs-hunter FP reduction (incl. judge tie-break)
- `references/requirements-mode.md` — Phase 7.7 requirements-aware verification
- `references/fp-check.md` — Phase 7 6-gate verification rubric
- `references/variant-analysis.md` — pattern fan-out per ACCEPT
- `references/insecure-defaults.md` — negative-space audit checklist (Odoo section + generic)
- `references/sharp-edges.md` — footgun-API audit checklist (Odoo section + generic)
- `references/lang-odoo.md` — Odoo framework patterns
- `references/lang-qweb.md` — QWeb / OWL templating sinks
- `references/lang-python.md` — generic Python AppSec
- `references/lang-web.md` — TypeScript/Node patterns (for `static/src` JS only)
- `references/triage.md` — rubric, output format, stats template
- `references/findings-schema.md` — `findings.json` schema (v1.0) consumed by export/diff
- `references/cwe-map.json` — 19 Odoo bug-shape → CWE/CAPEC/OWASP mappings (auto-copied to `inventory/cwe-map.json`)
- `references/scope.example.yml` — scope.yml schema (excluded_modules / excluded_paths / accepted_risks — coarse engagement-scope layer)
- `references/accepted-risks.md` — per-finding fingerprint suppression schema (fine-grained exclusion-bucket layer; fingerprint canonicalisation, legacy match rules, expiry semantics)
- `references/accepted-risks.example.yml` — copy-paste template for `<repo>/.audit-accepted-risks.yml`
- `references/fix-list.md` — per-finding fingerprint **tracking** schema (symmetric companion to accepted-risks; status open/in-progress/fixed/wontfix; reconciliation matrix incl. REGRESSION detection)
- `references/fix-list.example.yml` — copy-paste template for `<repo>/.audit-fix-list.yml`
- `references/html-report.md` — single-file `findings.html` spec (no CDN, embedded SVG, sortable table, severity colors, print-friendly)
- `templates/github-action.yml` — drop-in GitHub Action for PR-scoped review + SARIF upload + sticky delta comments
- `/odoo-code-review` — slash command to kick off the whole pipeline
