# Odoo Application Security Harness

Claude Code harness for repeatable Odoo source-code security reviews.

Provides one comprehensive command, `/odoo-code-review`. Claude Code remains the lead reviewer and final arbiter. Local Ollama/Qwen provides private hint-only triage. Codex/OpenAI handles token-heavy hunter passes, discourse drafts, chaining drafts, evidence packs, and report drafts.

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
- Runs repeatable scanner setup for Semgrep, Bandit, Ruff, pylint-odoo, CodeQL, dependency tools, and optional Joern.
- Runs local Qwen advisory notes through Ollama.
- Launches or prepares Codex hunter tasks.
- Writes a `goals.md` guide for lead-session `/goals` tracking in Codex-capable review sessions.
- Produces `.audit/` artifacts for Claude's final 6-gate validation.

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
- a convenience symlink `~/.local/bin/odoo-review-run`

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

## Output

Default output goes to:

```text
<repo>/.audit/
```

Important artifacts:

- `00-modules.md`
- `01-attack-surface.md`
- `goals.md`
- `inventory/manifests.json`
- `inventory/routes.json`
- `inventory/acl-index.json`
- `inventory/sharp-edge-index.json`
- `local-qwen/module-notes.md`
- `scans/*`
- `codex/hunters/*`
- `tooling.md`
- `tooling.json`

## Sharing Notes

This repo does not include private Odoo source code, API keys, Claude session data, or local `.audit/` outputs. Review generated reports before sharing them outside a client or team boundary.
