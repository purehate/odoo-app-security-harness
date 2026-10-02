# Odoo Application Security Harness — HarnessCard

> The machinery is disclosed here because “trust me, bro” is not a security boundary.

> Structured disclosure of the harness layer for the `odoo-app-security-harness` project.
> Based on the Control–Agency–Runtime (CAR) decomposition from
> *Harness Engineering for Language Agents* (He et al., 2026).

---

## Base Model(s)

| Lane | Model | Role | Configuration |
|------|-------|------|---------------|
| Lead | Claude Code (Claude 4 family) | Orchestration, attack surface final pass, 6-gate validation, report authoring | Repo-local `AGENTS.md`, user profiles |
| Triage | Local Ollama / Qwen3 0.6B | Offline hint-only signal, scanner triage, module narrative | No egress, runs on `localhost:11434` |
| Hunters | OpenAI Codex (GPT-5.3-codex) | Token-heavy passes: hunter sweeps, discourse drafts, chaining drafts, evidence packs, report drafts | Budget modes: `low` / `normal` / `deep` |

Claude Code remains the **final arbiter**. Nothing ships without passing Claude's 6-gate validation.

---

## Control Artifacts

Durable instructions and constraints the agent reads on every session:

| Artifact | Location | Purpose |
|----------|----------|---------|
| `AGENTS.md` | Repo root | Map of the harness; points to deeper docs |
| `README.md` | Repo root | Architecture, lanes, TL;DR usage |
| `HARNESS.md` | Repo root | This document — harness disclosure |
| `cwe-map.json` | `odoo_security_harness/` | CWE / CAPEC / OWASP mappings for every rule ID |
| `_TAXONOMY_SHAPE_HINTS` | `odoo_security_harness/scripts/odoo_deep_scan.py` | Taxonomy gate — every emitted rule must map to a known shape |
| Scanner modules | `odoo_security_harness/*_scanner.py` (75 modules) | Deterministic detection of Odoo-specific security patterns |
| `finding_schema.py` | `odoo_security_harness/finding_schema.py` | Schema validation, normalization, fingerprinting |
| `fix_catalog.py` | `odoo_security_harness/fix_catalog.py` | 135 rule ID → Odoo-idiomatic fix mappings |
| `pyproject.toml` | Repo root | Build system, deps, scripts, Python version matrix (3.9–3.13) |
| `.pre-commit-config.yaml` | Repo root | Lint/format gates (black, ruff, mypy) |
| CI workflow | `.github/workflows/` | Test matrix, lint, docker, security (bandit, safety) |

---

## Runtime Policy

How state is carried forward across sessions and context windows:

| Policy | Implementation |
|--------|---------------|
| System of record | `.audit/` directory for per-review artifacts |
| Session isolation | Each review writes to a fresh `<OUT>` directory |
| Progress tracking | `directives/D-NNNN-<slug>.md` for targeted reruns |
| Compaction | Claude Code native compaction near context limits |
| Retries | Bounded retries (3×) for flaky scanner imports; lanes report failure rather than hang |
| Recovery | `odoo-review-rerun` re-runs a directive file from a previous session |
| Git anchoring | Target repo `git_head` recorded in findings for reproducibility |

**Known limitation:** Large reviews (1M+ LOC) do not yet have structured session-progress artifacts for resuming across multiple context windows. This is on the roadmap (see `docs/harness-engineering-review.md`).

---

## Action Substrate

What the model can actually do in the environment:

| Action | Tool / API | Notes |
|--------|-----------|-------|
| File read | `read_file` (Claude Code native) | Source code, manifests, XML data |
| File edit | `edit_file` / `write_file` (Claude Code native) | Directives, reports, fix patches |
| Shell command | `bash` (Claude Code native) | Scanner execution, test runs, git ops |
| AST traversal | `ast` module (Python) | Deep pattern analysis in `analyzer.py` |
| Scanner invocation | `odoo_deep_scan.py` CLI | 75 deterministic scanners |
| LLM call (triage) | `ollama run <model>` subprocess | Local Qwen hint-only passes (module notes, scanner triage, reject candidates); no HTTP API |
| LLM call (hunters) | `codex exec` subprocess | Read-only hunter and ensemble passes; `workspace-write` only for daily remediation |
| Diff generation | `git diff` | PR review mode (`--pr <n>`) |
| Report export | JSON, Markdown, SARIF | `--format` flag |
| PoC generation | `generate_pocs()` | Evidence packs for critical findings |

---

## Execution Topology

```
┌─────────────────────────────────────────────────────────────────┐
│  User runs `/odoo-code-review -ks <repo>`                       │
└──────────────────────────┬──────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 1: Inventory                                             │
│  ├── Parse manifests (__manifest__.py)                          │
│  ├── Index routes (@http.route decorators)                      │
│  ├── Build ACL table (ir.model.access.csv)                      │
│  └── Dependency graph                                           │
└──────────────────────────┬──────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 2: Deterministic Scanners (75 modules)                   │
│  ├── Python AST scanners (models, controllers, orm, sql, ...)   │
│  ├── XML scanners (views, data, QWeb)                           │
│  └── Metadata scanners (manifests, migrations, config)          │
└──────────────────────────┬──────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 3: Qwen Triage (Lane 2)                                  │
│  ├── Module narrative generation                                │
│  ├── Scanner finding triage (hint-only)                         │
│  └── Offline, no egress                                         │
└──────────────────────────┬──────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 4: Codex Hunters (Lane 3)                                │
│  ├── Risk-prioritized breadth passes                            │
│  ├── Discourse drafts                                           │
│  ├── Chaining drafts                                            │
│  └── Evidence packs                                             │
└──────────────────────────┬──────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 5: Claude Validation (Lane 1 — Lead)                     │
│  ├── 6-gate fp-check                                            │
│  │   ├── Gate 1: Scanner confidence                             │
│  │   ├── Gate 2: Evidence existence                             │
│  │   ├── Gate 3: Odoo-framework invariant check                 │
│  │   ├── Gate 4: False-positive history                         │
│  │   ├── Gate 5: Cross-reference with accepted risks            │
│  │   └── Gate 6: Severity alignment                             │
│  └── Variant analysis                                           │
└──────────────────────────┬──────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 6: Final Report + Exports                                │
│  ├── Markdown report with evidence                              │
│  ├── SARIF export                                               │
│  ├── Bounty/diff export                                         │
│  └── Learning artifacts (accepted-risks, fix-list drafts)       │
└─────────────────────────────────────────────────────────────────┘
```

**Branching:** If deeper coverage is needed, Claude writes a directive (`D-NNNN-<slug>.md`) and `odoo-review-rerun` dispatches it to Qwen or Codex.

---

## Feedback Stack

Signals that shape agent behavior:

| Layer | Signal | Frequency |
|-------|--------|-----------|
| Static analysis | ruff, black, mypy, bandit | Every commit (pre-commit + CI) |
| Unit tests | pytest (3,900+ tests, ~89% coverage) | Every PR |
| Taxonomy gate | `test_taxonomy_coverage_maps_all_package_finding_rule_constants` | Every PR — blocks unmapped rule IDs |
| Integration tests | OCA corpus smoke tests (`tests/corpus/`) | Manual / `--corpus` flag |
| CI matrix | Python 3.10–3.13, lint, docker, security | Every push to `main` / `develop` |
| Code coverage | pytest-cov + Codecov | Every PR |
| Self-review | Claude Code reviews its own changes | Per-session |
| Human review | PR review on GitHub | Final gate before merge |

---

## Governance Layer

| Control | Implementation |
|---------|---------------|
| Sandboxing | Scanner execution is read-only (no file mutation of target repo) |
| Approval policy | Claude Code approval prompts for privileged shell commands |
| Least privilege | Scanners run with no network egress (except Codex lane, which calls OpenAI API) |
| Audit trail | `.audit/` directory contains full review artifacts |
| Directive isolation | Each directive rerun is scoped and idempotent |

---

## Observability

| Signal | Current | Target |
|--------|---------|--------|
| Test results | pytest XML + terminal | ✅ |
| Coverage | HTML + XML reports | ✅ |
| CI logs | GitHub Actions | ✅ |
| Scanner telemetry | Not structured | JSONL trace per session (roadmap) |
| Cost tracking | Not instrumented | Token burn per lane (roadmap) |
| Latency | Not instrumented | Per-scanner + per-lane timing (roadmap) |
| Trace replay | Not available | `odoo-review-trace` CLI (roadmap) |
| Failure categorization | Manual | Automated taxonomy (roadmap) |

---

## Success Criteria

A review session is considered successful when:

1. All deterministic scanners execute without crash (`returncode == 0`)
2. All emitted findings pass schema validation (`validate_findings()`)
3. All emitted rule IDs pass taxonomy coverage (`_TAXONOMY_SHAPE_HINTS` + `cwe-map.json`)
4. All unit tests pass (`pytest -m "not slow and not integration and not corpus"`)
5. Lint/format checks pass (`black`, `ruff`, `mypy`)
6. Final report is generated in at least one export format (Markdown, JSON, SARIF)
7. For interactive mode: Claude's 6-gate validation confirms each finding

---

## Known Risks

| Risk | Mitigation | Status |
|------|-----------|--------|
| Stale `.audit/` artifacts | Doc-gardening scanner (planned) | 🔴 Open |
| Session state loss on large reviews | Session-progress JSON (`session_progress.py`) | 🟢 Mitigated |
| No end-to-end eval harness | `tests/eval_harness/` | 🟢 Mitigated |
| Token burn on low-signal files | Candidate ledger (`candidate_ledger.py`) | 🟢 Mitigated |
| Harness not self-scanned for AI risks | Lurkr-inspired self-scan (planned) | 🔴 Open |
| No trajectory grading for agent runs | Trace logging + grading (planned) | 🔴 Open |
| Auto-approving writing agent in daily remediation | `codex exec --sandbox workspace-write --approve-for-me` runs only in an isolated worktree; protected branches (`main`/`master`) are rejected and delivery requires a human-only promotion PR | 🟡 Bounded |
| Prompt injection from scanned source into a writing lane | Hunters/ensemble run `-s read-only`; only the daily remediation lane writes, and its worktree diff is verified and gated | 🟡 Bounded |
| Scanner drift | Taxonomy gate + unit tests | 🟢 Mitigated |
| False-positive flood | 6-gate fp-check + accepted-risks | 🟢 Mitigated |
| Python version compatibility | CI matrix 3.9–3.13 | 🟢 Mitigated |

---

## Version

- **Harness version:** 1.0.0 (from `pyproject.toml`)
- **Last updated:** 2026-05-22
- **Schema version:** HarnessCard v0.1
