---
name: requirements-mode
description: Phase 4.5 — verify a codebase against a requirements/spec/threat-model document. Adapts the constitution-compile-verify-repair pipeline (IronCurtain) to source-code review. Activated by `--requirements <file>`.
---

# Requirements-Aware Mode (Phase 4.5)

Triggered by `--requirements <file>` flag. Runs **after** Phase 4 fp-check + variants and **before** the final report. Cross-checks a requirements / spec / threat-model document against the codebase to catch **missed-requirement bugs** — defects where the code never implemented a stated security claim, even though no hunter flagged a positive vulnerability.

Adapted from IronCurtain's constitution → compile → generate-scenarios → verify-with-judge → repair pipeline. Source: https://github.com/provos/ironcurtain.

## When to Run

- User passes `--requirements <path-to-doc>`. Doc can be: SOC2 control list, threat model, RFC, security spec, customer ATO requirements, internal hardening guide.
- Skip silently if flag not set.
- Skip if doc is < 200 words (probably a placeholder).
- Doc must be plain text or markdown — PDF/Word need pre-conversion.

## Why Distinct from Hunter Findings

Hunters look for **positive vulnerabilities** (a bug exists at file:line). Requirements mode looks for **negative gaps** (a claim was made but no code enforces it). These are orthogonal:

- Hunter: "SQL injection in /api/reports" → finding.
- Requirements: "All admin endpoints must enforce MFA per SOC2 CC6.1" → check whether code at the admin routes calls an MFA gate. Absent gate = finding, even if no hunter flagged the route.

Negative-space audit (insecure-defaults) is similar but driven by framework knowledge, not customer requirements. Requirements mode is customer-driven.

## The Pipeline

```
requirements.md → [Extract Claims] → [Compile to Test Predicates] → [Generate Scenarios]
                       │                       │                            │
                       ▼                       ▼                            ▼
                 claims.json          predicates.json              scenarios.json

scenarios.json + repo → [Verify with Judge] → [Targeted Repair Loop ≤2] → [Verdict per Claim]
                              │                         │                        │
                              ▼                         ▼                        ▼
                        verdicts-r1.json         verdicts-r2.json        final-verdicts.md
```

### Step 1 — Extract Claims

Dispatch one agent. Read the requirements doc. Output structured claims list.

Each claim:

```json
{
  "id": "REQ-001",
  "source": "requirements.md:42",
  "category": "auth | authz | crypto | logging | dataflow | config | other",
  "claim": "All admin endpoints require MFA",
  "actor": "admin user",
  "scope": "admin endpoints",
  "implies_code": "MFA check before admin handler executes"
}
```

Drop:

- Aspirational language ("we strive to", "best efforts").
- Process claims ("we run quarterly audits").
- Claims with no code surface (HR policies, legal disclaimers).

Keep only claims that imply a code-level enforcement. If the doc has 0 keep-able claims after extraction → stop, report "no testable claims" to user.

Save to `<OUT>/requirements/claims.json`.

### Step 2 — Compile to Test Predicates

Dispatch one agent per claim or batch. For each claim, write a test predicate: a deterministic check the orchestrator can run against the repo.

Predicate types:

| Type            | Example                                                                  |
| --------------- | ------------------------------------------------------------------------ |
| `route-guard`   | "Every route matching `/admin/*` is wrapped by middleware named `mfa_*`" |
| `crypto-algo`   | "All `crypto.createCipher` calls use AES-GCM, not AES-CBC"               |
| `secret-source` | "No hardcoded secrets in src/\*\*; all secrets read from env or vault"   |
| `log-content`   | "Logger calls in auth/\* never include `req.body.password`"              |
| `data-flow`     | "PII fields never reach `console.*` or analytics SDK calls"              |
| `config-flag`   | "Production config sets `secure: true` and `httpOnly: true` on cookies"  |

Predicate must be:

- **Deterministic** — runnable as grep / Semgrep / CodeQL query. Not "look around and see".
- **Falsifiable** — has a clear pass/fail given source bytes.
- **Bounded** — names file globs or module scope, not "the whole codebase" if specific.

Each predicate references exactly one claim ID. Save to `<OUT>/requirements/predicates.json`.

### Step 3 — Generate Scenarios

For each predicate, generate 1-3 concrete scenarios that would falsify it. Scenarios are the equivalent of unit tests — they describe what a violation looks like in code.

```json
{
  "predicate_id": "PRED-001",
  "claim_id": "REQ-001",
  "scenarios": [
    {
      "id": "SCN-001-a",
      "description": "Admin route reachable without MFA middleware in chain",
      "search": "route registration matching /admin/* whose middleware list does not include mfa_*"
    },
    {
      "id": "SCN-001-b",
      "description": "Admin handler called via internal RPC bypass",
      "search": "internal RPC entry that dispatches to admin handler skipping MFA gate"
    }
  ]
}
```

Save to `<OUT>/requirements/scenarios.json`. Mandatory + handwritten invariants (per language) added by orchestrator: e.g., "no `eval(`/`exec(` on user-controlled input in any predicate run".

### Step 4 — Verify with Judge (Round 1)

Dispatch one judge agent per claim (parallel — single message multiple Agent calls). Judge is **independent** of hunters — fresh context, no allegiance.

Judge prompt:

```markdown
# Requirements Judge — claim {REQ-N}

## Claim

{claim text + source line}

## Predicate

{predicate from claims.json}

## Scenarios to falsify

{1-3 scenarios}

## Your job

1. Search the repo for evidence the claim is enforced.
2. For each scenario, decide: does the code prevent it?
3. Cite file:line for every conclusion.
4. Return verdict:

**SATISFIED** — code enforces the claim. Cite the enforcement site.
**VIOLATED** — code does NOT enforce; show the gap. State a concrete attack that would defeat the claim.
**PARTIAL** — enforced for some surface, missed elsewhere. List covered + missed scopes.
**UNTESTABLE** — claim cannot be verified from source (runtime config, deployment-time setting, external service). State what evidence would settle it.

Be specific. No "looks like". File:line or it didn't happen.
Max 300 words per claim.
```

Save outputs to `<OUT>/requirements/verdicts-r1/{REQ-N}.md`.

### Step 5 — Targeted Repair Loop (≤2 rounds)

For each `VIOLATED` or `PARTIAL` verdict, the orchestrator:

1. Reads the judge's cited gap.
2. Verifies independently — read the bytes, confirm the gap.
3. If gap is real → finalize as a finding (Phase 4 format).
4. If judge mis-read → dispatch second judge with the orchestrator's correction notes.

Cap at 2 judge rounds total per claim. After round 2:

- Still VIOLATED → finding.
- Round 1 said VIOLATED, round 2 says SATISFIED → mark NEEDS-MANUAL with both verdicts attached.
- Conflict between rounds → NEEDS-MANUAL.

This is the IronCurtain "verify-and-repair" pattern. Their version repairs the **rules**; ours repairs the **verdict** — same shape, different artifact.

### Step 6 — Final Verdict per Claim

Compile to `<OUT>/requirements/final-verdicts.md`:

```markdown
# Requirements Verification — Summary

## Stats

- Claims extracted: 23
- Testable: 18
- SATISFIED: 12
- VIOLATED: 3 (filed as findings R-1, R-2, R-3)
- PARTIAL: 2 (filed as findings R-4, R-5 with scope notes)
- UNTESTABLE: 1 (NEEDS-MANUAL)

## Per-claim

| Claim ID | Source             | Verdict   | Finding ID |
| -------- | ------------------ | --------- | ---------- |
| REQ-001  | requirements.md:42 | VIOLATED  | R-1        |
| REQ-002  | requirements.md:58 | SATISFIED | —          |
| ...      | ...                | ...       | ...        |
```

Findings filed under R-N namespace (R for "requirements") so they don't collide with hunter finding numbers. Each R-finding gets the same Phase 4 format (file:line + PoC + impact + 6-gate fp-check) — the gap is the bug.

## Output

Requirements mode produces:

```
<OUT>/requirements/
├── claims.json              # Step 1
├── predicates.json          # Step 2
├── scenarios.json           # Step 3
├── verdicts-r1/{REQ-N}.md   # Step 4
├── verdicts-r2/{REQ-N}.md   # Step 5 (if needed)
└── final-verdicts.md        # Step 6 (summary)
```

R-findings are merged into the main `findings.md` with a `Source: requirements <REQ-ID>` field so the reader knows the origin.

## Anti-patterns

- **Treating aspirational text as a claim.** "We aim to follow OWASP" is not testable. Drop in extraction.
- **Predicate = vibes.** "Check if auth feels right" is not a predicate. Has to be grep/Semgrep/CodeQL-runnable.
- **Skipping repair round.** First-pass judge can mis-read. The repair round catches half the FPs.
- **More than 2 judge rounds.** Diminishing returns. After round 2, mark NEEDS-MANUAL.
- **Letting R-findings skip Phase 4 fp-check.** R-findings are findings — same 6 gates apply. The "gap" is the source; the "sink" is whatever the missing enforcement was supposed to gate.
- **Reporting SATISFIED without a citation.** Every SATISFIED verdict cites the enforcement file:line. Otherwise it's a guess.

## Limits

- Doesn't replace pentest. UNTESTABLE claims still need runtime validation.
- Doesn't validate the requirements themselves. If the customer's requirement is wrong (e.g., "SHA-1 is fine"), this mode happily reports SATISFIED. Out of scope.
- Cost: roughly +30-50% wall-clock on Phase 4. For HUGE repos with 50+ claims, batch claims by category to keep judge dispatch parallel.

## Integration with Other Phases

- Phase 1 surface map informs which routes/modules each claim maps to.
- Phase 1.5 scans can pre-populate predicate evidence (e.g., a hardcoded-secret scan helps PRED-secret-source).
- Phase 2 hunter findings can resolve some claims as PARTIAL automatically: if injection-hunter found SQLi in /admin, the claim "admin endpoints validate input" is auto-VIOLATED.
- Phase 3 chaining doesn't apply to R-findings directly, but R-findings can chain with hunter findings (missed MFA + hunter-found SSRF = full ATO).
