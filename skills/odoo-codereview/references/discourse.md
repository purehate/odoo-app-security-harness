# Discourse — Phase 2.5 (Cross-Hunter FP Reduction)

Runs **after** Phase 2 hunters return and **before** Phase 3 chaining. Hunters review each other's findings, agreeing, challenging, connecting, or surfacing new concerns. Cuts FPs and lifts confidence on consensus findings before they hit the validation gates.

Adapted from spencermarx/open-code-review's discourse pattern. Distinct from Phase 4 fp-check: discourse is hunter-vs-hunter; fp-check is the orchestrator reading the bytes against the 6 gates.

## When to Run

- **Default** — every engagement that uses ≥3 hunters in Phase 2.
- **Skip** — only if `--quick` flag is set or repo is SMALL (<20k LOC). For SMALL/MEDIUM, the orchestrator does the discourse work directly.

Never skip for HUGE/LARGE repos — discourse is where false positives die at scale.

## The Four Response Types

Hunters use exactly these. Don't add more.

| Type          | Purpose                                           | Effect on finding                          |
| ------------- | ------------------------------------------------- | ------------------------------------------ |
| **AGREE**     | Endorse another hunter's finding                  | +1 confidence                              |
| **CHALLENGE** | Push back with reasoning                          | -1 confidence; may REJECT in P4            |
| **CONNECT**   | Link related findings across hunters              | Flag for chaining (Phase 3)                |
| **SURFACE**   | Raise new concern that emerged from reading peers | Adds new finding (must meet hunter format) |

## Procedure

### Step 1 — Compile All Phase 2 Findings

Gather each hunter's output. Build a single discourse packet:

```markdown
## Findings for Discourse — Round 1

### auth-hunter

1. [Pre-auth account enumeration via /api/login timing] — MEDIUM
2. [Session fixation on OAuth callback] — HIGH

### authz-hunter

1. [Missing tenant check on /api/orders/:id] — HIGH
2. [Admin endpoint reachable via webhook handler] — HIGH

### injection-hunter

1. [SQL injection in ORDER BY of /api/reports] — HIGH

### ssrf-files-hunter

1. [SSRF in /api/preview via fetch(req.body.url)] — HIGH

...
```

Save to `<OUT>/agents/discourse-input.md`.

### Step 2 — Dispatch Discourse Tasks (Parallel)

For each hunter that filed findings, spawn a discourse pass — **single message, multiple Agent calls**, same as Phase 2.

Discourse prompt template:

```markdown
# Discourse Pass — {hunter}

You filed these findings in Phase 2:
{their findings}

Other hunters filed these findings in Phase 2:
{all other findings}

Respond using exactly these tags:

- **AGREE [other-hunter] [finding-N]**: You concur. State the additional reason this is a real bug.
- **CHALLENGE [other-hunter] [finding-N]**: You disagree. Give a concrete reason — a validator they missed, a precondition that won't hold, a misread API contract. Cite file:line.
- **CONNECT [your finding-M] → [other finding-N]**: These compose. Describe the combined attack path in one sentence.
- **SURFACE**: A new concern emerged from reading a peer's finding. Output a full hunter-format finding (file:line, severity, PoC).

Constraints:

- Be terse. One block per response. No filler.
- Challenges need evidence, not opinion. "Looks fine" is not a CHALLENGE.
- Don't AGREE with everything. Default to silence on findings outside your technique scope.
- SURFACE is rare. Only when reading a peer's finding made you spot a sibling bug they missed.
```

### Step 3 — Collect Discourse Output

Each hunter writes to `<OUT>/agents/discourse-{hunter}.md`:

```markdown
## Discourse from injection-hunter

AGREE authz-hunter finding-1 "Missing tenant check on /api/orders/:id"

- The same endpoint is also where my ORDER BY injection lands. Missing tenant check turns my SQLi into cross-tenant data read.

CHALLENGE ssrf-files-hunter finding-1 "SSRF in /api/preview"

- The fetch is wrapped in `validateUrl(req.body.url)` at server/preview.ts:42 which enforces an allowlist of {github.com, raw.githubusercontent.com}.
- Allowlist is not bypassable via redirect — `followRedirects: false` set at line 51.
- Suggest REJECT or downgrade to LOW (info-disclosure via timing).

CONNECT my finding-1 "SQL injection in /api/reports ORDER BY" → authz-hunter finding-1 "Missing tenant check"

- Combined: cross-tenant data read pre-auth via reports endpoint.

SURFACE

- finding: Reflected XSS in /api/reports error response
- file: server/reports.ts:128
- severity: MEDIUM
- PoC: GET /api/reports?orderBy=<svg/onload=alert(1)> → returned in error JSON, rendered raw by frontend at app/reports.tsx:88
- reasoning: Reading authz-hunter's tenant-check gap made me look at error rendering — same endpoint reflects user input unescaped.
```

### Step 4 — Compile Discourse Results

Orchestrator merges into `<OUT>/agents/discourse-summary.md`:

```markdown
# Discourse Round 1 — Summary

## Consensus (high confidence — multiple AGREE)

- **authz-hunter finding-1: Missing tenant check on /api/orders/:id**
  - Endorsed by: injection-hunter, business-logic-hunter
  - Net confidence: HIGH → VERY HIGH

- **auth-hunter finding-2: Session fixation on OAuth callback**
  - Endorsed by: external-interfaces-hunter
  - Net confidence: HIGH → VERY HIGH

## Challenged Findings

- **ssrf-files-hunter finding-1: SSRF in /api/preview** — CHALLENGED by injection-hunter
  - Reason: validateUrl allowlist + followRedirects:false at server/preview.ts:42-51
  - Disposition: provisional REJECT pending Phase 4 verification

## Connected Findings (flagged for Chaining in Phase 3)

- injection-hunter f1 + authz-hunter f1 → cross-tenant SQLi via reports endpoint
- auth-hunter f2 + external-interfaces-hunter f3 → OAuth session fixation chain

## Surfaced in Discourse

- (NEW) Reflected XSS in /api/reports error response — MEDIUM — server/reports.ts:128 (from injection-hunter)

## No-action

- 4 findings drew no discourse responses → carry forward to Phase 4 unchanged.
```

### Step 5 — Confidence Adjustment Rules

Apply before Phase 3:

| Scenario                                                         | Confidence change          |
| ---------------------------------------------------------------- | -------------------------- |
| ≥2 hunters AGREE                                                 | +1 (cap at VERY HIGH)      |
| Hunter CHALLENGED, original hunter does not defend in next round | -1 (may REJECT in P4)      |
| Hunter CHALLENGED, original hunter defends with new evidence     | hold confidence            |
| Finding CONNECTED                                                | +1 (and flag for Phase 3)  |
| SURFACED finding                                                 | Standard hunter confidence |

Confidence is metadata for Phase 4 — the orchestrator still runs the 6 gates regardless. Discourse never auto-ACCEPTs. It only adjusts the prior.

## Optional — Defense Round

If a finding is CHALLENGED, the original hunter may file a defense in a second discourse pass:

```markdown
## Defense from ssrf-files-hunter finding-1

DEFEND injection-hunter CHALLENGE

- Re-read server/preview.ts:42 — validateUrl uses URL.hostname check, not full URL.
- Allowlist matches `*.githubusercontent.com` via regex `/githubusercontent\.com$/` which DNS rebinding can defeat (attacker.githubusercontent.com.attacker.tld).
- followRedirects:false confirmed at line 51 — that defense holds.
- Net: vulnerability is narrower than my original claim. Downgrade MEDIUM (DNS rebind required) but keep finding.
```

If a defense lands, recompute confidence: original hunter's defense is worth +1 if it cites new file:line evidence the challenger missed.

Cap at one defense round. If still ambiguous after defense → run **Judge Tie-Break** (next section). Don't auto-mark NEEDS-MANUAL.

## Judge Tie-Break

Adapted from IronCurtain's verify-and-repair pattern: when CHALLENGE + DEFENSE leave the verdict ambiguous, dispatch an independent **judge agent** that reads the raw bytes — not just the hunter narratives — and rules.

### When to run

- After one defense round.
- Only for CHALLENGED findings where the defense cites evidence but the challenger's evidence still stands (both sides have file:line, conclusion unclear).
- Skip when the defense concedes (already DOWNGRADE) or when the original hunter doesn't defend (auto-REJECT).

### Judge dispatch

Use Codex for the discourse draft by default. If Codex is unavailable or `--no-codex` is set, use a single Claude Code agent with fresh context and no hunter loyalty.

Judge prompt template:

```markdown
# Tie-Break Judge — finding-{N}

You are an independent reviewer. Two hunters disagree. Read the actual code and decide.

## The finding

{original hunter's full finding block}

## Challenge

{challenger's CHALLENGE text + cited file:line evidence}

## Defense

{original hunter's DEFENSE text + cited file:line evidence}

## Your job

1. Read every cited file:line yourself. Do not trust either narrative.
2. Read 50 lines of context around each cite.
3. Determine: which side reads the code correctly?
4. Return exactly one verdict:

**VERDICT: UPHOLD** — original finding stands. State the one fact the challenger got wrong.
**VERDICT: REJECT** — challenger is right. State the safeguard the original hunter missed.
**VERDICT: DOWNGRADE <new-severity>** — finding real but narrower than claimed. State the remaining bug + why severity drops.
**VERDICT: NEEDS-MANUAL** — genuinely cannot tell from source (race window, parser-version-dependent, runtime config). State what runtime evidence would settle it.

Constraints:

- Cite file:line for every claim. No "looks like".
- One verdict only. No fence-sitting.
- Max 200 words.
```

### Confidence adjustment after judge

| Judge verdict | Confidence outcome                                         |
| ------------- | ---------------------------------------------------------- |
| UPHOLD        | Original confidence + 1 (cap VERY HIGH). Carry to Phase 4. |
| REJECT        | Auto-REJECT. Skip Phase 4 fp-check on this finding.        |
| DOWNGRADE     | Apply new severity, hold confidence, carry to Phase 4.     |
| NEEDS-MANUAL  | Tag for NEEDS-MANUAL in Phase 4 triage. Skip fp-check.     |

Judge verdicts are persisted in `<OUT>/agents/discourse-judge-{N}.md`.

### Anti-patterns

- Running judge on every CHALLENGED finding. Only ambiguous-after-defense ones — otherwise judge becomes a slow rubber stamp.
- Judge that doesn't read the bytes. The whole point is independent code reading. If judge cites only hunter narratives, the verdict is invalid; re-run.
- More than one judge round. If first judge says NEEDS-MANUAL, stop. Two judges arguing = bug needs runtime testing.

## Output

Discourse phase produces:

1. `<OUT>/agents/discourse-input.md` — packet sent to hunters
2. `<OUT>/agents/discourse-{hunter}.md` — each hunter's response
3. `<OUT>/agents/discourse-summary.md` — orchestrator's consolidated view + confidence adjustments
4. Updated finding list (with revised confidence) handed to Phase 3 chaining

## Anti-patterns

- AGREE-spamming. Hunters that AGREE with everything add no signal. Tune the prompt to reward CHALLENGE+evidence.
- Skipping discourse on "obvious" bugs. The whole point is to find the obvious bugs that aren't.
- Letting CHALLENGED findings vanish silently. Every CHALLENGED finding gets a Phase 4 verdict — REJECT, DOWNGRADE, or held with evidence.
- Discourse-as-debate. One pass per hunter, max one defense. Multi-round arguments are a sign the bug needs runtime testing, not more talk.
- Treating SURFACE as freebie findings. SURFACE findings still go through Phase 4 fp-check.
