---
description: Odoo source-code security review — kicks off the odoo-code-review pipeline against an Odoo addon repo.
---

# /odoo-code-review

Run a technique-organized Odoo security review of source code (Phases 0 → 1 → 2 → 2.5 → 2.6 → 3 → 3.5 → 4 → 4.5 → 5 → 5.5 → 6 → 7 → 7.5 → 7.6 → 7.7 → 7.8 → 8).

## Usage

```
/odoo-code-review                                  # audit current working directory → <repo>/.audit-YYYYMMDD-HHMM/
/odoo-code-review <path>                           # audit a specific path
/odoo-code-review <path> --out <dir>               # override output dir
/odoo-code-review <path> --modules <list>          # restrict scope to listed module names
/odoo-code-review <path> --odoo-version <N>        # override Odoo version detection (e.g., 17.0)
/odoo-code-review <path> --no-discourse            # skip Phase 5.5 hunter discourse
/odoo-code-review <path> --quick                   # skip Phases 2–4.5 + Phase 5.5; hunters only on Phase 0/1 maps
/odoo-code-review <path> --no-local-qwen           # skip local Ollama/Qwen advisory triage
/odoo-code-review <path> --local-model qwen3:0.6b  # override local model
/odoo-code-review <path> --allow-missing-lanes     # continue if Qwen or Codex preflight is unavailable
/odoo-code-review <path> --joern                   # enable Phase 3.5 Joern CPG graph review
/odoo-code-review <path> --runtime                 # enable Phase 7.5 runtime evidence helper path
/odoo-code-review <path> --runtime --zap-target <url>  # also Phase 7.5 sub-pass B (ZAP baseline)
/odoo-code-review <path> --no-codex                # skip Codex heavy-worker lane and Phase 7.7
/odoo-code-review <path> --requirements <file>     # Phase 7.8 — judge-verified claims from spec/threat-model/SOC2 doc
/odoo-code-review <path> --no-html                 # skip findings.html generation in Phase 8
/odoo-code-review <path> --json                    # emit findings.json sidecar in Phase 8
/odoo-code-review <path> --scope ./scope.yml       # apply excluded_modules/paths + accepted_risks
/odoo-code-review <path> --pr 42                   # scope to files changed in PR 42 (gh CLI)
/odoo-code-review <path> --pr 42 --pr-repo o/r     # PR scope when checkout is not the PR's repo
/odoo-code-review <path> --no-export               # skip Phase 8.6 auto-export (SARIF/bounty/diff)
/odoo-code-review <path> --yes                     # non-interactive: strip every y/N prompt (only when explicitly requested)
/odoo-code-review <path> --learn                   # auto-promote baseline + accumulate accepted-risks/fix-list
/odoo-code-review <path> --baseline-stock-cc       # spawn stock-CC subagent, validate stock-only misses, append lessons
/odoo-code-review <path> -ks                       # kitchen sink: max-quality review path
/odoo-code-review --help                           # print compact flag table and exit (no review)
```

**TL;DR:** use three modes: `--quick` for a fast pass, `--pr <n>` for pull requests, and `-ks` for the best possible full review regardless of token/runtime cost. `-ks` handles inventory → scanners → Qwen → Codex hunters → stock-CC control lane → discourse → chaining → runtime evidence path → 6-gate validation → final report → SARIF/bounty/diff export → baseline promotion → accepted-risks/fix-list suggestions. Add `--yes` only when you want non-interactive behavior.

Run `-ks` from Claude Code for the full workflow. Direct CLI can run scanners/Codex/Qwen and write artifacts, but it cannot spawn the stock-CC control Agent or perform Claude's final Phase 7 judgment by itself.

## Mode Flags Cheat Sheet

| Mode                             | Use                                                                                                                                   |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `-ks` / `--ks` / `--kitchensink` | Kitchen sink. Max-quality review path: all lanes, runtime path, stock gate, learning, fail-loud lane requirements. Add `--yes` only when you want zero prompts. |
| `--quick`                        | Fast pass for local iteration. Skips scanner/discourse depth.                                                                         |
| `--pr <n>`                       | Pull-request scope. Review files changed in PR `<n>`; combine with `--quick` for fast PR triage.                                     |
| `--yes` / `-y`                   | Strip every interactive y/N prompt without enabling the rest of kitchen-sink mode.                                                     |
| `--learn`                        | Promote findings.json → `.audit-baseline/`, write accepted-risk suggestions, and accumulate `.audit-fix-list.yml`.                    |
| `--baseline-stock-cc`            | Spawn a control lane: stock Claude Code reviewing the same repo. Stock-only misses become current-run validation leads and lessons.   |
| `--allow-missing-lanes`           | Escape hatch. Continue if Codex/Qwen is unavailable; do not use for a serious `-ks` review unless you accept weaker coverage.          |
| `--runtime`                      | Enable Phase 7.5 runtime evidence. Use `odoo-review-runtime <OUT>` with Odoo launch details to boot Odoo and replay PoCs.             |
| `--joern`                        | Add Joern CPG graph review (Phase 3.5).                                                                                               |
| `--requirements <file>`          | Phase 7.8 requirements-aware verification.                                                                                            |
| `--no-codex` / `--no-local-qwen` | Drop a lane (e.g. air-gapped).                                                                                                        |
| `--help`                         | Print the full flag list with one-line descriptions.                                                                                  |

## What It Does

Invokes the `odoo-code-review` skill which runs the full Odoo pipeline:

Before manual review work, run the local harness runner to create the repeatable artifact base:

```bash
~/.claude/skills/odoo-code-review/scripts/odoo-review-run <target> <flags>
```

Use `--codex-mode prepare` when you want Claude to inspect/launch Codex prompts manually. Use the default `--codex-mode run` for the full one-command three-lane workflow.

If the lead session supports `/goals`, use `<OUT>/goals.md` after the runner completes to set the review objective. Keep that goal open until Phase 8 output exists; continue using TaskCreate for phase and hunter-level tracking.

1. **Phase 0 — Module Inventory + Manifest Map.** Find every `__manifest__.py`, parse to JSON, build depends graph, tag origins (core/enterprise/OCA/custom/third-party). Writes `00-modules.md`, `inventory/`.
2. **Phase 1 — Odoo Attack Surface Map.** Identify Odoo version + stack. Map HTTP routes (`@http.route` with auth/csrf/type/methods), RPC entry points, portal `/my/*`, models touched by public routes, ACL CSV, `ir.rule`, server actions, cron, mail templates. Risk-rank modules. Writes `01-attack-surface.md`.
3. **Phase 1.5 — Local Qwen / Ollama Advisory Check.** Runs local-only module notes and scanner-hint triage via Ollama/Qwen unless `--no-local-qwen`. Hints only; no ACCEPT findings.
   3a. **Phase 1.7 — Breadth Sweep Dispatch (eve-cc style, default on).** Runner emits `<OUT>/inventory/breadth/dispatch.json` listing file chunks (default 40 files / chunk; override `--breadth-chunk-size`). Lead Claude dispatches one Agent per chunk **in parallel batches** (`subagent_type: general-purpose`, multiple Agent tool calls in a single message). Each subagent enumerates every public route, `sudo()`, `cr.execute`, `eval/exec`, `ir.rule` gap, and authentication boundary in its slice and appends a `## BR-NNN — <module>` section to `<OUT>/inventory/breadth/leads.md`. Hunters in Phase 5 ingest `leads.md`. Disable with `--no-breadth`.
4. **Phase 2 — Semgrep Python/Odoo.** Community rulesets (`p/python`, `p/owasp-top-ten`, `p/trailofbits`, `p/0xdea`) + custom `.semgrep/odoo.yml` rules (`auth='public'+sudo()`, `csrf=False` without HMAC, `cr.execute(f"...")`, `t-raw=`, `request.params → write/create`, etc.).
5. **Phase 2.5 — Bandit.** Generic Python AppSec sweep.
6. **Phase 2.6 — Ruff + pylint-odoo + OCA pre-commit.** Odoo-aware lint with `pylint_odoo`/`odoolint`.
7. **Phase 3 — CodeQL Python.** `python-security-and-quality.qls` + `python-security-experimental.qls` with `--build-mode=none`.
8. **Phase 3.5 — Joern Graph Review (only with `--joern`).** CPG via `joern-parse --language pythonsrc`, query batch covers eval/exec/safe_eval reachability, non-literal cr.execute, sudo propagation, controller→model paths, deserialization, SSRF, path traversal. Hits = leads for Phase 5, not findings.
9. **Phase 4 — Pysa (optional).** Taint analysis if Pyre check passes; otherwise skipped.
10. **Phase 4.5 — Dependency Scan.** `pip-audit` + `osv-scanner` cross-referenced with manifest external_dependencies.
11. **Phase 5 — Codex Odoo Specialist Hunting.** Claude prepares compact packets; Codex runs the 9 expensive hunter passes: Access Control, Controller/Route, ORM/SQL/Domain, QWeb/XSS, Business Logic, Secrets/Config, External Integration, Data Exposure, Dependency. Hunter packets MUST include `<OUT>/inventory/py-files-by-module.json` and (if present) `<OUT>/inventory/breadth/leads.md`. Each hunter MUST emit a `Reviewed:` block at the top of its output listing the modules and concrete file:line ranges it inspected.
12. **Phase 5.5 — Discourse.** Codex drafts AGREE / CHALLENGE / CONNECT / SURFACE discourse. Claude resolves disputed CHALLENGE items.
    12a. **Phase 5.6 — Coverage Diff (eve-cc gap closure).** Run `~/.claude/skills/odoo-code-review/scripts/odoo-review-coverage <OUT>`. Diffs hunter `Reviewed:` blocks against `inventory/py-files-by-module.json`. Re-dispatch any hunter listed in `<OUT>/coverage/gaps.md` with a tight per-module scope before proceeding.
13. **Phase 6 — Cross-Agent Correlation.** Codex drafts chained paths; Claude finalizes impact and severity.
14. **Phase 7 — Validation.** Codex prepares evidence packs and variant-analysis drafts. Claude performs final 6-gate fp-check and triage: ACCEPT / DOWNGRADE / REJECT / NEEDS-MANUAL.
15. **Phase 7.5 — Runtime Testing (only with `--runtime`).** Use `odoo-review-runtime <OUT>` with explicit Odoo launch details (`--odoo-bin`, `--config`/`--database`, `--addons-path`) to boot Odoo, wait for `/web/login`, replay PoC scripts with `ODOO_BASE_URL`, and capture logs/status under `<OUT>/runtime/`. Run ZAP when requested. Claude reviews evidence.
16. **Phase 7.6 — Attack Graph DOT/SVG.** Codex/scripts render DOT/SVG for chained findings. Claude checks graph accuracy.
17. **Phase 7.7 — Fresh Codex Adversarial Check.** Different session = blind-spot diversity. Runs on CRITICAL/HIGH ACCEPT unless `--no-codex`. Reconciliation table covers ACCEPT/REJECT/DOWNGRADE combos + PoC writeability.
18. **Phase 7.8 — Requirements Verification (only with `--requirements`).** Extract claims, compile predicates, dispatch judges, repair-loop (≤2 rounds). Files R-N findings.
19. **Phase 8 — Output Assembly.** Codex drafts `findings.md` + `findings.html` + `findings.json` + reproducibility appendix. Claude performs final edit and removes unsupported claims. `findings.json` and `findings.html` are emitted by default; opt out with `--no-json` / `--no-html`.
20. **Phase 8.5 — Directive Loop (optional, any phase).** When Claude needs a focused rerun mid-review (deeper portal-route + sudo scan, PoC sketch for one finding, narrative on an ACL gap), copy `<OUT>/directives/_template.md` to `D-NNNN-<slug>.md`, fill the YAML + body, then run `odoo-review-rerun <directive>`. Result lands in `directives/results/`. Use sparingly; not a replacement for Phase 5 hunters.
21. **Phase 8.6 — Finalize (default on).** Once `findings.json` exists, Claude runs:

    ```bash
    odoo-review-finalize <OUT> [--baseline <path>] [--fail-on high]
    ```

    `odoo-review-finalize` is the canonical wrapper. It (a) calls `odoo-review-export` to emit `findings.sarif` (SARIF 2.1.0 for GitHub Code Scanning), `findings-fingerprints.json` (cross-run dedup hashes), and `bounty/F-N.md` (HackerOne/Intigriti drafts per ACCEPT, suppressed entries skipped); (b) auto-detects a baseline at `<OUT>/../.audit-baseline/findings.json` or `$ODOO_REVIEW_BASELINE` (or honors `--baseline`) and calls `odoo-review-diff` to emit `delta.md` + `delta.json`; (c) stamps `<OUT>/finalize.log`; (d) exits non-zero when ACCEPT findings meet/exceed `--fail-on` (default `high`) — usable as a CI gate. Skip with `--no-export`.

22. **Phase 8.7 — AI-Driven Iteration Loop (the product).** This harness runs three AI lanes — Claude, Codex, local Ollama/Qwen. Use them. After Phase 8.6 the lead session (Claude):
    1. Re-reads `findings.json` + `delta.md` + every REJECT/DOWNGRADE 6-gate verdict.
    2. For each finding where 6-gate clearly fails (gate 1/2/3 FAIL with cited line evidence), drafts an `accepted_risks` entry into `<OUT>/scope-suggestions.yml` with: `id`, `finding_id`, `rule`, `cwe`, `file`, `line_range`, `reason` (citing the failing gate + code evidence), `expires` (default 90d).
    3. Cross-checks each suggestion with at least one other lane:
       - **Codex** (default for CRITICAL/HIGH-adjacent suggestions): fresh adversarial prompt, sees only the finding card + source.
       - **Local Qwen** (default for LOW/MEDIUM bulk suggestions, free + private): hint-only verdict via `odoo-review-rerun` against a directive of `target_lane: qwen`.
       - At least one cross-check lane must agree before a suggestion lands. Disagreement → keep the finding open and log to `directives/results/`.
    4. Presents the suggestions diff to the user: "Apply these N suppressions and re-run? [y/N]". On `y`, Claude appends to project `scope.yml` (creates if missing), re-invokes `/odoo-code-review --scope ./scope.yml --baseline <prev OUT>`, and the next run shows `delta.md` with the new suppressions and any newly surfaced findings. **When `<OUT>/run-mode.json` has `non_interactive=true` (set only by `--yes`), skip the prompt entirely and auto-apply.** Lead Claude calls `scripts/odoo-review-learn <OUT> --apply` only when non-interactive or user-approved. Without `--yes`, run `scripts/odoo-review-learn <OUT>` to promote the baseline and write suggestions for review. That script (a) promotes `findings.json` → `<repo>/.audit-baseline/findings.json`, (b) additively appends Codex-agreed REJECT/DOWNGRADE entries to `<repo>/.audit-accepted-risks.yml` when applied, (c) stubs new ACCEPT findings into `<repo>/.audit-fix-list.yml` (status=open, target +30d) when applied. Iteration cap: `learn_cap` (default 3).
    5. Repeats until either the user stops, the suggestion list is empty, or 3 iterations have run (cap to prevent runaway).

    Lane choice for the cross-check is governed by lane availability + cost: if `--no-codex`, Qwen handles all cross-checks; if `--no-local-qwen`, Codex handles all; if both available, the harness routes by severity (cheap lane for low-stakes bulk, expensive lane for the few high-stakes suggestions).

    `findings.html` also ships a manual **Accept Risk** button per finding (toggle + reason + expiry → downloadable `accepted-risks.yml` snippet) for cases where the human disagrees with the AI's draft. See `references/html-report.md`. The AI loop is default; the buttons are the override.

## Output

Written to `<repo>/.audit-YYYYMMDD-HHMM/` (or `--out <dir>`):

- `00-modules.md`, `01-attack-surface.md` — Phase 0/1 maps
- `goals.md` — suggested `/goals` objective, budget guidance, and phase checkpoints for the lead review session
- `directives/` — feedback-loop dispatch directory: `README.md`, `_template.md`, `D-NNNN-*.md`, `results/`. Claude writes directives; `odoo-review-rerun` dispatches to Qwen or Codex
- `qwen-handoff/` — token-pressure fallback packet. If lead Claude context gets tight, dispatch `D-9001..D-9003` Qwen directives and fold hint-only results back after compaction.
- `local-qwen/` — Phase 1.5 advisory notes: `module-notes.md`, `scanner-triage.md`, `reject-candidates.md`
- `inventory/` — manifest JSON, depends graph, ACL CSV index, route map
- `scans/semgrep/`, `scans/bandit/`, `scans/ruff/`, `scans/pylint-odoo/`, `scans/oca-precommit/`, `scans/codeql/`, `scans/joern/`, `scans/pysa/`, `scans/deps/` — raw scan outputs
- `codeql-dbs/` — extracted CodeQL Python DB
- `agents/hunter-*.md`, `agents/discourse-*.md`, `agents/chaining.md` — agent outputs
- `codex/hunters/` — Phase 5 Codex specialist hunter drafts
- `codex/evidence/` — Phase 7 evidence packs, variant drafts, and PoC writeability notes
- `codex/drafts/` — Phase 8 draft report material
- `variants/finding-N.md` — per-ACCEPT pattern fan-out
- `runtime/` — Phase 7.5 (only with `--runtime`): `reproductions/`, `odoo-shell-output/`, `zap/zap-baseline.{html,json}` (with `--zap-target`)
- `attack-graphs/chain-N.{dot,svg}` — Phase 7.6 (auto when 2+ chained findings)
- `codex/second-opinion/verdicts/F-N.md`, `codex/second-opinion/reconciliation.md` — Phase 7.7 when CRITICAL/HIGH ACCEPT exists
- `requirements/` — Phase 7.8 (only with `--requirements`): `claims.json`, `predicates.json`, `scenarios.json`, `verdicts-r{1,2}/`, `final-verdicts.md`
- `findings.md` — canonical final report:
  - Findings table (Title / Severity / Confidence / File / Triage / Odoo surface)
  - Per-finding detail: Description, Attack Path, PoC, Reproduction, Impact, Fix, **6-gate fp-check table**, **variants sub-table**, **Odoo surface field**, **Codex 2nd-opinion verdict** for CRITICAL/HIGH ACCEPT
  - Chained attack paths (with embedded Phase 7.6 SVG references)
  - Discourse summary, negative-space (insecure-defaults Odoo section) summary
  - Engagement stats: modules, LOC, wall-clock, tokens, hunter-by-hunter table
  - Recommended actions (file upstream issue with OCA/Odoo S.A./vendor / hardening PR / no action)
- `findings.html` — single-file self-contained HTML report (unless `--no-html`): inline CSS, embedded SVG attack graphs, severity color-coding, no CDN deps
- `findings.json` — machine-readable sidecar (only with `--json`)
- `tooling.md` — tool versions (Semgrep, CodeQL, Ollama/Qwen when used, Joern, ZAP, Codex, Graphviz) + exact commands run (reproducibility)

## Lane Ownership

- **Claude Code:** lead reviewer, task orchestration, final 6-gate verdicts, severity, client-ready wording.
- **Qwen/Ollama:** local HINT-only triage for module notes, scanner summaries, and obvious noise.
- **Codex/OpenAI:** token-heavy hunter passes, discourse draft, chaining draft, evidence packs, variant analysis, PoC writeability, runtime/artifact/report drafts.

## Hard Rules

- Real exploitable Odoo bugs only. No theoretical, no "missing input validation" without a sink.
- Every finding cites file:line and includes a concrete payload (curl, XML-RPC, JSON-RPC, browser action, odoo-bin shell).
- Hunters can hallucinate — Phase 7 reads the bytes.
- No re-reporting fixed CVEs unless regression proven.
- Severity matches actual blast radius. DoS != RCE. Internal-user privilege creep != portal → internal escalation.
- Two trust boundaries anchor every triage decision: **public-vs-authenticated** (`auth='public'`) and **user-vs-root** (`sudo()`).

## Skill Behavior

The odoo-code-review skill handles dispatch, tracking via TaskCreate, and final report assembly. See `~/.claude/skills/odoo-code-review/SKILL.md` for the full contract and `references/` for hunter prompts (`agent-prompts.md`), triage rubric (`triage.md`), workflow detail (`workflow.md`), and Odoo language patterns (`lang-odoo.md`, `lang-qweb.md`).

## Philosophy

For Odoo, Semgrep + custom Odoo rules + CodeQL/Pysa + agent validation beats adding a pile of generic scanners. The money is in finding **"public route calls sudo and returns sensitive model data"** — not 400 generic Python warnings.

---

## Help Short-Circuit

If `$ARGUMENTS` contains `--help` or `-h` (anywhere in the string), do NOT invoke the skill or start a review. Instead run:

```bash
~/.claude/skills/odoo-code-review/scripts/odoo-review-run --help
```

Print the runner's full argparse output verbatim to the user and stop. Do not proceed to Phase 0. The user wants a flag reference, not a review.

## Invocation

Otherwise, invoke the skill now and proceed with Phase 0 against `$ARGUMENTS` (or current working directory if no argument). When `$ARGUMENTS` contains `-ks` / `--ks` / `--kitchensink` / `--yes`, read `<OUT>/00-run-mode.md` after the runner completes and follow the run-mode contract in SKILL.md. Only suppress y/N prompts when `non_interactive=true`; always dispatch/diff the stock-CC lane when `baseline_stock_cc=true`.
