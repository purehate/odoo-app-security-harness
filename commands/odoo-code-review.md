---
description: Odoo source-code security review — kicks off the odoo-code-review pipeline against an Odoo addon repo.
---

# /odoo-code-review

Run a technique-organized Odoo security review of source code (Phases 0 → 1 → 2 → 2.5 → 2.6 → 3 → 3.5 → 4 → 4.5 → 5 → 5.5 → 6 → 7 → 7.5 → 7.6 → 7.7 → 7.8 → 8).

## Usage

```
/odoo-code-review                                  # audit current working directory → <repo>/.audit/
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
/odoo-code-review <path> --runtime                 # enable Phase 7.5 sub-pass A (odoo-bin disposable + PoC replay)
/odoo-code-review <path> --runtime --zap-target <url>  # also Phase 7.5 sub-pass B (ZAP baseline)
/odoo-code-review <path> --no-codex                # skip Codex heavy-worker lane and Phase 7.7
/odoo-code-review <path> --requirements <file>     # Phase 7.8 — judge-verified claims from spec/threat-model/SOC2 doc
/odoo-code-review <path> --no-html                 # skip findings.html generation in Phase 8
/odoo-code-review <path> --json                    # emit findings.json sidecar in Phase 8
```

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
4. **Phase 2 — Semgrep Python/Odoo.** Community rulesets (`p/python`, `p/owasp-top-ten`, `p/trailofbits`, `p/0xdea`) + custom `.semgrep/odoo.yml` rules (`auth='public'+sudo()`, `csrf=False` without HMAC, `cr.execute(f"...")`, `t-raw=`, `request.params → write/create`, etc.).
5. **Phase 2.5 — Bandit.** Generic Python AppSec sweep.
6. **Phase 2.6 — Ruff + pylint-odoo + OCA pre-commit.** Odoo-aware lint with `pylint_odoo`/`odoolint`.
7. **Phase 3 — CodeQL Python.** `python-security-and-quality.qls` + `python-security-experimental.qls` with `--build-mode=none`.
8. **Phase 3.5 — Joern Graph Review (only with `--joern`).** CPG via `joern-parse --language pythonsrc`, query batch covers eval/exec/safe_eval reachability, non-literal cr.execute, sudo propagation, controller→model paths, deserialization, SSRF, path traversal. Hits = leads for Phase 5, not findings.
9. **Phase 4 — Pysa (optional).** Taint analysis if Pyre check passes; otherwise skipped.
10. **Phase 4.5 — Dependency Scan.** `pip-audit` + `osv-scanner` cross-referenced with manifest external_dependencies.
11. **Phase 5 — Codex Odoo Specialist Hunting.** Claude prepares compact packets; Codex runs the 9 expensive hunter passes: Access Control, Controller/Route, ORM/SQL/Domain, QWeb/XSS, Business Logic, Secrets/Config, External Integration, Data Exposure, Dependency.
12. **Phase 5.5 — Discourse.** Codex drafts AGREE / CHALLENGE / CONNECT / SURFACE discourse. Claude resolves disputed CHALLENGE items.
13. **Phase 6 — Cross-Agent Correlation.** Codex drafts chained paths; Claude finalizes impact and severity.
14. **Phase 7 — Validation.** Codex prepares evidence packs and variant-analysis drafts. Claude performs final 6-gate fp-check and triage: ACCEPT / DOWNGRADE / REJECT / NEEDS-MANUAL.
15. **Phase 7.5 — Runtime Testing (only with `--runtime`).** Codex/scripts help boot disposable odoo-bin, replay PoCs, and run ZAP when requested. Claude reviews evidence.
16. **Phase 7.6 — Attack Graph DOT/SVG.** Codex/scripts render DOT/SVG for chained findings. Claude checks graph accuracy.
17. **Phase 7.7 — Fresh Codex Adversarial Check.** Different session = blind-spot diversity. Runs on CRITICAL/HIGH ACCEPT unless `--no-codex`. Reconciliation table covers ACCEPT/REJECT/DOWNGRADE combos + PoC writeability.
18. **Phase 7.8 — Requirements Verification (only with `--requirements`).** Extract claims, compile predicates, dispatch judges, repair-loop (≤2 rounds). Files R-N findings.
19. **Phase 8 — Output Assembly.** Codex drafts `findings.md` + `findings.html` + reproducibility appendix. Claude performs final edit and removes unsupported claims. `--json` adds `findings.json` sidecar.

## Output

Written to `<repo>/.audit/` (or `--out <dir>`):

- `00-modules.md`, `01-attack-surface.md` — Phase 0/1 maps
- `goals.md` — suggested `/goals` objective, budget guidance, and phase checkpoints for the lead review session
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

Invoke the skill now and proceed with Phase 0 against `$ARGUMENTS` (or current working directory if no argument).
