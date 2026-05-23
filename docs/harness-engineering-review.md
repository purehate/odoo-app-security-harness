# Harness Engineering Review: Applying awesome-harness-engineering to Odoo App Security Harness

**Review date:** 2026-05-22
**Source:** [walkinglabs/awesome-harness-engineering](https://github.com/walkinglabs/awesome-harness-engineering)
**Scope:** Map curated harness-engineering resources to concrete improvements for the Odoo Application Security Harness.

---

## Executive Summary

The Odoo App Security Harness is already a sophisticated system: 75+ deterministic scanners, a 3-lane agent architecture (Claude lead / Qwen triage / Codex hunters), 6-gate validation, 3,900+ unit tests, taxonomy enforcement, auto-fix catalog, and OCA corpus validation. It is stronger than most security scanners in its domain.

However, relative to the state of harness engineering in 2026, there are **8 high-impact gaps** that limit reliability, reproducibility, and iterative improvement:

| # | Gap | Source | Impact |
|---|-----|--------|--------|
| 1 | No **HarnessCard** documenting control/runtime/agency layers | CAR paper, OpenAI field report | Low transparency; onboarding friction |
| 2 | No **eval harness** separating harness quality from model quality | Anthropic evals article | Cannot measure if improvements come from prompt vs scanner vs model |
| 3 | No **intentionally vulnerable Odoo modules** for regression testing | llm-security-scanner, SEC-bench | No ground-truth baseline for end-to-end accuracy |
| 4 | No **candidate ledger** feeding risky surfaces to LLM lanes | DeepSec pattern | Codex hunters waste tokens on low-signal files |
| 5 | No **progress artifacts** across long-running review sessions | Anthropic long-running agents | Large reviews lose state between sessions |
| 6 | No **layer-aware baselines** (vary control/runtime independently) | CAR paper | Cannot attribute gains to specific harness changes |
| 7 | No **trajectory grading** or transcript analysis for agent runs | Anthropic evals, agenttrace | No visibility into why a review session failed |
| 8 | No **pass@k / pass^k** metrics for non-deterministic lanes | Anthropic evals | Cannot quantify lane reliability |

This document maps each resource from the awesome list to specific, implementable improvements.

---

## 1. Foundations: Harness Design & Architecture

### 1.1 HarnessCard — Structured Harness Reporting (CAR Decomposition)

**Resource:** [Harness Engineering for Language Agents: The Harness Layer as Control, Agency, and Runtime](https://www.preprints.org/manuscript/202603.1756)

**Key insight:** The harness layer should be treated as a first-class research object. The **Control–Agency–Runtime (CAR)** decomposition provides a lens for auditing any agent system:

- **Control:** Which instructions remain authoritative? (`AGENTS.md`, architecture rules, repo maps, taxonomy enforcement)
- **Agency:** What actions are available? (scanner execution, Codex hunter prompts, evidence pack generation)
- **Runtime:** How is state carried forward? (`.audit/` artifacts, directive files, context compaction)

**Current state:** The Odoo harness has strong control (taxonomy gate, `AGENTS.md` culture, lint enforcement) and strong agency (75 scanners, multi-lane architecture). Runtime is weaker: `.audit/` artifacts exist but are minimal, and there is no structured handoff between long-running sessions.

**Recommendation:** Create `HARNESS.md` at the repo root using the HarnessCard template. At minimum, disclose:

| Field | Current Disclosure | Target |
|-------|-------------------|--------|
| Base model(s) | Claude Code + local Qwen + Codex | Documented in `HARNESS.md` |
| Control artifacts | `AGENTS.md`, `cwe-map.json`, taxonomy gate | Add architecture rules, done-when criteria |
| Runtime policy | Implicit (`.audit/` artifacts) | Explicit: progress files, compaction rules, retry bounds |
| Action substrate | File edits, shell commands, scanner exec, LLM calls | Documented with schema |
| Execution topology | Plan → scan → triage → hunter → validate → report | Documented with branching logic |
| Feedback stack | Failing tests, taxonomy gate, custom linters | Add self-review grader checks |
| Governance layer | Approval policy for privileged actions (implicit) | Explicit sandbox/approval matrix |
| Observability | Coverage reports, CI logs | Add trace replay, cost logs, failure categorization |
| Success criteria | "Pass tests, emit valid findings" | "Merged change passes required checks, leaves updated artifacts" |

**Implementation effort:** Low. Mostly documentation with some schema additions.

---

### 1.2 OpenAI Field Report — Repo as System of Record

**Resource:** [Harness engineering: leveraging Codex in an agent-first world](https://openai.com/index/harness-engineering/)

**Key insights:**
1. **AGENTS.md as a map, not an encyclopedia.** The Odoo harness already does this well — the README is a map pointing to deeper docs.
2. **Structured `docs/` directory as system of record.** The current harness has `.audit/` but it's minimal (mostly empty JSON files). The OpenAI team uses `docs/design-docs/`, `docs/exec-plans/`, `docs/product-specs/` with validation CI.
3. **Agent-readable observability.** Codex uses LogQL/PromQL against local stacks. The Odoo harness could expose scanner metrics (coverage, false-positive rate, token usage per lane) in a queryable format.
4. **Doc-gardening agent.** A scheduled CI job that scans for stale `.audit/` artifacts and files PRs to update them.

**Recommendations:**
- [ ] **Expand `.audit/` from artifact dump to structured knowledge base.** Add `docs/harness/` with `design-docs/`, `eval-results/`, `regression-tracker/`.
- [ ] **Add a `doc-gardening` scanner** that checks whether `.audit/` files are older than the code they describe.
- [ ] **Expose scanner telemetry** (findings per scanner, token burn per lane, FP rate trend) as a JSON/CSV artifact that agents can query.

---

### 1.3 Anthropic — Effective Harnesses for Long-Running Agents

**Resource:** [Effective harnesses for long-running agents](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents)

**Key insight:** Long-running agents fail in two ways: (1) trying to do too much at once, and (2) declaring victory too early. The solution is an **initializer agent** + **incremental progress tracking**.

**Current state:** The Odoo harness runs scans in a single session. For large repos (1M+ LOC), this means:
- Context window exhaustion during the "kitchen sink" (`-ks`) pass
- No structured way to resume a review across multiple sessions
- No feature-level tracking of which security surfaces have been covered

**Recommendations:**

#### A. Review Session Progress Tracking

Create `.audit/session-progress.json` with the following structure:

```json
{
  "session_id": "uuid",
  "repo_path": "/path/to/odoo-addon",
  "feature_list": [
    {
      "category": "scanner",
      "name": "scan_raw_sql",
      "status": "completed",
      "findings_count": 3,
      "passed_validation": true
    },
    {
      "category": "lane",
      "name": "codex_hunter_sudo_patterns",
      "status": "pending",
      "candidate_files": ["models/res_users.py", "controllers/main.py"]
    }
  ],
  "last_updated": "2026-05-22T19:00:00Z",
  "git_head": "abc123"
}
```

#### B. Initializer Agent for Large Reviews

For reviews exceeding a context-window budget, use an initializer pass that:
1. Runs inventory (manifests, routes, ACLs)
2. Builds the feature list (all scanners + hunter passes)
3. Creates `.audit/session-progress.json`
4. Commits initial findings to `.audit/scans/`

Each subsequent session reads `session-progress.json`, picks the next pending feature, and updates the file on completion.

#### C. `init.sh` for Review Environment

Create `scripts/odoo-review-init.sh` that:
- Sets up the review environment (virtualenv, scanner dependencies)
- Runs a smoke test against the target repo
- Validates that all scanners can import and execute
- This prevents the "agent spends 30 minutes debugging import errors" failure mode

---

## 2. Context, Memory & Working State

### 2.1 Context Engineering — Progressive Disclosure

**Resources:**
- [Effective context engineering for AI agents](https://www.anthropic.com/engineering/effective-context-engineering)
- [Context Engineering for Coding Agents](https://www.thoughtworks.com/insights/articles/context-engineering-coding-agents)

**Key insight:** Context is a scarce budget. The current harness dumps all 75 scanner modules into context when explaining the architecture. Instead, use **progressive disclosure**.

**Recommendations:**
- [ ] **Tiered `AGENTS.md`:**
  - Level 1 (always in context): `README.md` + `HARNESS.md` + current task
  - Level 2 (on demand): Scanner architecture overview
  - Level 3 (on demand): Individual scanner implementation details
- [ ] **Scanner index file:** `docs/scanner-index.md` — a compact table mapping rule IDs to scanners, severity tiers, and file patterns. Agents can read this once and reference it without loading all scanner source.

### 2.2 Backpressure — Preventing Token Burn on Low-Value Work

**Resource:** [Context-Efficient Backpressure for Coding Agents](https://humanlayer.dev/blog/context-efficient-backpressure)

**Current state:** The Codex hunter lanes can burn tokens analyzing files that deterministic scanners already cleared. There's no backpressure mechanism.

**Recommendations:**
- [ ] **Candidate ledger** (from DeepSec pattern): Before sending files to Codex, maintain an append-only per-file candidate record. If a file has zero scanner findings and no sharp-edge index entries, skip it for hunter passes.
- [ ] **Noise tier system:** Tag each scanner with `noise_tier` (silent / low / medium / high). Files with only silent/low findings get abbreviated hunter passes.

---

## 3. Constraints, Guardrails & Safe Autonomy

### 3.1 Lurkr — Static Scanner for AI-Agent Capability Risks

**Resource:** [Lurkr](https://github.com/laigasus/lurkr)

**Key insight:** Lurkr scans for AI-agent-specific risks: shadow capabilities, credentials into LLM context, `eval/subprocess` in `@tool`, direct prompt interpolation, unverified MCP endpoints.

**Recommendations:**
- [ ] **Add `lurkr`-inspired scanner** for the harness itself:
  - Detect if scanner findings ever include raw secrets that could leak into LLM context
  - Detect if `odoo_deep_scan.py` or hunter prompts use `eval()` / `exec()` / `safe_eval()` on untrusted input
  - Detect if MCP/tool schemas allow arbitrary code execution
  - Detect if prompt templates interpolate user-controlled data without sanitization
- [ ] **Add a "harness self-scan" CI job** that runs the scanner against its own source code, looking for these AI-specific risks.

### 3.2 Prompt Injection Mitigation

**Resource:** [Mitigating Prompt Injection Attacks in Software Agents](https://github.com/All-Hands-AI/openhands/blob/main/docs/modules/usage/prompting-security.md)

**Recommendations:**
- [ ] **Confirmation mode for high-severity findings:** When a scanner emits `critical` or `high` severity, require explicit human confirmation before the hunter lane generates a PoC or fix.
- [ ] **Analyzer layer:** Before feeding scanner output to LLM lanes, run a sanitization pass that strips potential prompt-injection payloads from finding messages.
- [ ] **Hard policy for `@tool` calls:** Codex hunter prompts should never call `eval()`, `exec()`, `safe_eval()`, or `subprocess.run()` with user-controlled data.

---

## 4. Evals & Observability

### 4.1 Anthropic — Demystifying Evals for AI Agents

**Resource:** [Demystifying evals for AI agents](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents)

**Key insights:**
1. **Agent harness ≠ model.** When you evaluate "the agent," you're evaluating the harness *and* the model together.
2. **Three grader types:** Code-based (fast, objective), model-based (flexible, nuanced), human (gold standard).
3. **Capability vs. regression evals:** Capability evals start at low pass rates and hill-climb. Regression evals start at ~100% and catch backsliding.
4. **pass@k vs. pass^k:** pass@k = "at least 1 success in k tries" (useful for creative tasks). pass^k = "all k trials succeed" (useful for reliability).

**Current state:** The Odoo harness has 3,900+ unit tests but **no end-to-end eval harness**. There is no way to answer:
- "If I change the `scan_raw_sql` heuristic, does overall accuracy improve?"
- "Does the Codex hunter lane find more true positives than the Qwen triage lane?"
- "What is the false-positive rate for a full `-ks` run on a known-good module?"

**Recommendations:**

#### A. Build an Eval Harness

Create `tests/eval_harness/` with the following structure:

```
tests/eval_harness/
├── tasks/                    # Individual eval tasks
│   ├── task_001_sudo_bypass.py
│   ├── task_002_sql_injection.py
│   └── ...
├── graders/
│   ├── deterministic.py      # Code-based graders
│   ├── llm_rubric.py         # Model-based graders
│   └── human_review.py       # Human grader interface
├── fixtures/
│   └── vulnerable_modules/   # Intentionally vulnerable Odoo modules
└── results/                  # Eval run artifacts
```

#### B. Three Eval Suites

**Suite 1: Capability Evals ("Can we find this at all?")**
- Tasks: 20 intentionally vulnerable Odoo modules, each with 1-3 known security bugs
- Grader: Did the scanner emit the correct rule_id at the correct line?
- Starting target: 60% pass rate, hill-climb to 90%

**Suite 2: Regression Evals ("Do we still find what we used to?")**
- Tasks: 50 modules from the OCA corpus that have known-good security posture
- Grader: Zero false positives on known-good code
- Target: 99% pass rate (1% tolerance for newly discovered issues)

**Suite 3: Lane Comparison Evals ("Which lane adds the most value?")**
- Tasks: 10 complex multi-file vulnerabilities
- Grader: Did the lane produce a valid finding with evidence?
- Metrics: pass@1 per lane, token cost per true positive, latency

#### C. Graders

**Code-based graders (fast, run in CI):**
```python
def grader_rule_id_match(expected: str, actual: list[dict]) -> bool:
    return any(f["rule_id"] == expected for f in actual)

def grader_line_accuracy(expected_line: int, actual: list[dict], tolerance: int = 3) -> bool:
    return any(abs(f["line"] - expected_line) <= tolerance for f in actual)

def grader_no_false_positives_on_clean_module(findings: list[dict]) -> bool:
    return len(findings) == 0
```

**Model-based graders (for qualitative assessment):**
```python
def grader_evidence_quality(finding: dict) -> dict:
    """Use LLM to grade whether the finding's evidence is convincing."""
    prompt = f"""
    Evaluate the quality of this security finding's evidence:
    Rule: {finding['rule_id']}
    Message: {finding['message']}
    
    Score 1-5 on:
    - Concrete citation (does it cite specific code?)
    - Resolution chain (does it explain the vulnerability path?)
    - Actionability (does it suggest a specific fix?)
    """
    # Call local Qwen or lightweight model
```

#### D. Metrics

Track these per eval run:
- `pass@1` (first-try success rate)
- `pass^3` (consistency across 3 runs)
- `tokens_per_true_positive` (efficiency)
- `latency_seconds` (speed)
- `false_positive_rate` (precision)
- `recall@k` (did we find the top-k most severe issues?)

---

### 4.2 Inspect AI — Evaluation Framework

**Resource:** [Inspect AI](https://github.com/UKGovernmentBEIS/inspect_ai)

**Key insight:** UK AISI's open-source framework with solver, scorer, sandboxing, tool-use, MCP, and log-viewer primitives.

**Recommendations:**
- [ ] **Adopt Inspect AI's log format** for eval runs. Their JSONL log viewer is excellent for debugging why a particular task failed.
- [ ] **Use Inspect AI's sandboxing primitives** for running Codex hunter-generated PoCs in isolation.

---

### 4.3 agenttrace — Trace Auditing

**Resource:** [agenttrace](https://github.com/coder/agenttrace)

**Key insight:** Local-first TUI/CLI for auditing coding-agent session traces, health gates, cost spikes, tool failures, latency gaps, and attempt-to-attempt diffs.

**Recommendations:**
- [ ] **Add trace logging to the harness.** For each review session, write a JSONL trace containing:
  - Scanner invocations (start time, end time, findings count, token usage)
  - LLM lane calls (prompt hash, response hash, token count, latency)
  - Tool calls (file reads, edits, test runs)
  - Validation gate results (pass/fail per gate)
- [ ] **Add a `odoo-review-trace` CLI** that reads trace files and reports:
  - Health gates (did any scanner crash? did any lane timeout?)
  - Cost spikes (which scanner/lane consumed the most tokens?)
  - Latency gaps (which step took unexpectedly long?)
  - Attempt-to-attempt diffs (what changed between review reruns?)

---

## 5. Benchmarks

### 5.1 SEC-bench — Security-Specific Benchmark

**Resource:** [SEC-bench](https://github.com/SecurityLab/SEC-bench)

**Key insight:** Evaluates LLM agents on real-world software security tasks: vulnerability reproduction, patching, exploit generation. Stresses harness design around code execution, containerized environments, and security-aware tooling.

**Recommendations:**
- [ ] **Create an Odoo-specific SEC-bench variant.** Use intentionally vulnerable Odoo modules that test:
  - SQL injection via `cr.execute()` with f-strings
  - XSS via `t-raw` / `Markup()`
  - Access control bypass via `sudo().search([])`
  - CSRF via `@http.route(..., csrf=False)`
  - IDOR via `browse(request.params.get('id'))`
  - Mass assignment via `**kwargs` in controllers
  - Unsafe `safe_eval` in server actions
  - Insecure OAuth callback handling
- [ ] **Containerize the benchmark.** Each vulnerable module runs in an isolated Odoo container. The harness must find the bug and suggest a fix that passes the container's test suite.

### 5.2 SWE-bench Verified — Pattern for Regression Testing

**Resource:** [SWE-bench Verified](https://github.com/swe-bench/swe-bench-verified)

**Key insight:** Gives agents GitHub issues and grades by running the test suite. Solution passes only if it fixes failing tests without breaking existing ones.

**Recommendations:**
- [ ] **Create `odoo-swe-bench` fixtures:** A set of Odoo modules with known security bugs, each with:
  - A failing test that demonstrates the vulnerability
  - A passing test that verifies the fix
  - The harness must produce a fix that makes both tests pass

### 5.3 EvoClaw — Continuous Software Evolution

**Resource:** [EvoClaw: Evaluating AI Agents on Continuous Software Evolution](https://github.com/evo-claw/evo-claw)

**Key insight:** Evaluates agents across dependent milestone sequences from real repository history, surfacing regression accumulation and long-horizon precision loss.

**Recommendations:**
- [ ] **Versioned eval suite:** As the harness evolves, maintain a history of eval results. Track whether changes to scanner heuristics improve capability evals but hurt regression evals.

---

## 6. Runtimes, Harnesses & Reference Implementations

### 6.1 SWE-agent — Reference Coding Agent

**Resource:** [SWE-agent](https://github.com/swe-bench/swe-agent)

**Key insight:** Makes the harness, prompt, tools, and environment design directly inspectable. Every decision is logged and reproducible.

**Recommendations:**
- [ ] **Add `odoo-review-inspect` mode** that dumps the full harness state for a given review:
  - Exact prompts sent to each lane
  - Exact scanner configurations used
  - Full findings with evidence chains
  - Git state of the target repo
  - This makes reviews reproducible and debuggable.

### 6.2 Citadel — Multi-Agent Harness with Worktrees

**Resource:** [Citadel](https://github.com/alexanderatallah/citadel)

**Key insight:** Isolated worktrees, multi-agent coordination, and persisted memory/campaign state.

**Recommendations:**
- [ ] **Git worktree isolation for hunter lanes.** Each Codex hunter pass should run in a separate git worktree to prevent accidental mutation of the main review state.
- [ ] **Campaign state persistence.** For long-running reviews across multiple modules, persist campaign state (findings, directives, progress) in a structured format that survives session restarts.

### 6.3 Harness Evolver — Autonomous Harness Improvement

**Resource:** [Harness Evolver](https://github.com/codex-harness/harness-evolver)

**Key insight:** Autonomously evolves LLM agent harnesses using multi-agent proposers, LangSmith-backed evaluation, and git worktree isolation.

**Recommendations:**
- [ ] **Automated harness A/B testing.** When proposing a scanner heuristic change, use the eval harness to run A/B tests:
  - Variant A: Current scanner
  - Variant B: Proposed scanner
  - Measure: pass@1, false-positive rate, token cost
  - Only merge if Variant B wins on all three metrics.

---

## 7. Specific Improvements for the Odoo Harness

### 7.1 Immediate (This Week)

1. **Write `HARNESS.md`** using the HarnessCard template. Document control artifacts, runtime policy, and success criteria.
2. **Fix `.audit/` artifacts.** The current `.audit/` directory has mostly empty JSON files. Populate `inventory/` with actual scan results, or remove empty artifacts.
3. **Add `docs/scanner-index.md`.** A compact index of all 75 scanners with rule IDs, severity tiers, and file patterns. Reduces context load when explaining the harness.

### 7.2 Short-Term (This Month)

4. **Build the Eval Harness (`tests/eval_harness/`):**
   - 5 intentionally vulnerable Odoo modules
   - 3 code-based graders (rule_id match, line accuracy, no-FP on clean)
   - 1 capability eval suite targeting 60% pass rate
   - Run in CI on every PR
5. **Add candidate ledger to `odoo_deep_scan.py`.** Before sending files to Codex hunters, filter out files with zero scanner findings and no sharp-edge index entries.
6. **Add session progress tracking.** For large reviews, write `.audit/session-progress.json` so sessions can resume across context windows.
7. **Add trace logging.** JSONL traces of scanner invocations, LLM lane calls, and validation gate results.

### 7.3 Medium-Term (This Quarter)

8. **Expand to 20 intentionally vulnerable modules** covering all major Odoo vulnerability classes.
9. **Add model-based graders** (local Qwen) for evidence quality assessment.
10. **Add `pass@k` and `pass^k` metrics** to the eval harness.
11. **Implement layer-aware baselines.** Run controlled experiments varying only the control layer (e.g., different `AGENTS.md` versions) while holding model and runtime constant.
12. **Add harness self-scan.** A scanner that audits the harness itself for AI-agent-specific risks (Lurkr-style).
13. **Containerize the benchmark.** Run vulnerable modules in isolated Odoo containers for realistic exploit validation.

### 7.4 Long-Term (This Year)

14. **Odoo-specific SEC-bench variant.** A comprehensive benchmark with 50+ tasks, competitive with generic security benchmarks.
15. **Automated harness A/B testing.** Propose scanner changes, run evals, auto-merge only if metrics improve.
16. **Multi-agent coordination (Many Hands Engineering).** Separate lanes for: scanner dev, evidence validation, fix generation, and report writing — each with specialized prompts and tools.

---

## 8. Resource Quick-Reference

| Resource | Category | Key Takeaway | Odoo Harness Application |
|----------|----------|-------------|------------------------|
| [OpenAI Harness Engineering](https://openai.com/index/harness-engineering/) | Foundations | Repo as system of record; AGENTS.md as map | Expand `.audit/` into structured knowledge base |
| [Anthropic Effective Harnesses](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents) | Foundations | Initializer agent + progress tracking | Session progress JSON for large reviews |
| [CAR / HarnessCard](https://www.preprints.org/manuscript/202603.1756) | Foundations | Control–Agency–Runtime decomposition | Write `HARNESS.md` |
| [Anthropic Demystifying Evals](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents) | Evals | Three grader types; capability vs regression | Build eval harness with 3 suites |
| [Inspect AI](https://github.com/UKGovernmentBEIS/inspect_ai) | Evals | Sandbox + scorer + log-viewer primitives | Adopt JSONL log format |
| [agenttrace](https://github.com/coder/agenttrace) | Evals | Trace auditing TUI | Add `odoo-review-trace` CLI |
| [Lurkr](https://github.com/laigasus/lurkr) | Guardrails | AI-agent risk scanner | Harness self-scan for prompt injection |
| [SEC-bench](https://github.com/SecurityLab/SEC-bench) | Benchmarks | Real security tasks | Odoo-specific vulnerable modules |
| [SWE-bench Verified](https://github.com/swe-bench/swe-bench-verified) | Benchmarks | Test-suite grading | `odoo-swe-bench` fixtures |
| [SWE-agent](https://github.com/swe-bench/swe-agent) | Reference | Inspectable harness design | `odoo-review-inspect` mode |
| [Citadel](https://github.com/alexanderatallah/citadel) | Reference | Worktree isolation + campaign state | Git worktrees for hunter lanes |
| [Harness Evolver](https://github.com/codex-harness/harness-evolver) | Reference | Automated A/B testing | Auto-merge scanner changes on eval win |
| [Many Hands Engineering](https://manyhands.engineering/) | Foundations | Multi-agent commons | Separate lanes per sub-task |
| [Context Backpressure](https://humanlayer.dev/blog/context-efficient-backpressure) | Context | Prevent token burn | Candidate ledger + noise tiers |
| [12 Factor Agents](https://github.com/humanlayer/12-factor-agents) | Specs | Explicit prompts, state ownership, pause-resume | Progress files, idempotent scans |

---

## Appendix A: Current Harness Strengths (Preserve These)

Before changing anything, note what already works well:

1. **Deterministic scanner suite:** 75 modules with clear separation of concerns. This is the harness's core competitive advantage.
2. **Taxonomy enforcement:** Every rule ID maps to CWE/CAPEC/OWASP. This prevents scanner drift.
3. **Auto-fix catalog:** 135 entries with Odoo-idiomatic fixes. This differentiates from generic scanners.
4. **Multi-lane architecture:** Claude lead + Qwen triage + Codex hunters. Good separation of concerns.
5. **6-gate validation:** Evidence-backed findings before shipping. Strong quality control.
6. **OCA corpus testing:** Real-world validation against production Odoo modules.
7. **Python 3.9–3.13 matrix:** Broad compatibility.
8. **3,900+ unit tests:** Solid regression protection for scanners.
9. **Finding schema with fingerprinting:** Stable IDs for tracking findings across runs.
10. **Directive system:** Targeted reruns via `D-NNNN-<slug>.md` files. Good iteration loop.

The goal is not to replace these strengths but to **augment them** with eval infrastructure, progress tracking, and harness transparency.
