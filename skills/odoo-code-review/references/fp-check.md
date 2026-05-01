# fp-check — 6-Gate Verification

Replaces the loose "read the bytes" Phase 4 with a structured pass per finding. Every finding (hunter-originated or scanner-originated) goes through all 6 gates before triage.

A finding can ACCEPT only if every gate is **PASS**. Any FAIL → DOWNGRADE or REJECT (rubric in `triage.md`). Any "can't tell" → NEEDS-MANUAL-TESTING.

## The 6 Gates

### Gate 1 — Source matches claim

Read the cited `file:line` plus 30-50 lines of context. The code at that location must exhibit the bug the finding describes. If the line moved, find the new location; if the code was changed and the bug is gone, REJECT as "fixed".

PASS criterion: bug pattern visible in source as described.

### Gate 2 — Reachable entry point

Trace backwards from the sink to a public entry: HTTP route, MQ consumer, scheduled job, CLI handler, gRPC method, etc. The entry must be reachable by the threat-model attacker (anonymous internet, authenticated user, etc.).

PASS criterion: at least one reachable entry point reaches the sink.

REJECT triggers:

- Sink is only callable from test code or example apps.
- Entry point is gated by `@Profile("dev")`, debug-only flags, or build-time-only paths.
- Method is private and never invoked by reachable callers.

### Gate 3 — Attacker controls the tainted parameter

Trace the source-to-sink data flow. At every transformation, confirm the attacker still controls enough of the value to weaponize the sink.

PASS criterion: a concrete attacker-supplied byte string reaches the sink unchanged or in a still-exploitable transformation.

REJECT triggers:

- Value is server-generated (UUID, current timestamp, random ID) before hitting the sink.
- Value passes through a strict validator (allowlist, type coercion to int, signed token verification) and the validator is not bypassable.
- Encoding canonicalisation removes the exploit primitive (HTML-escape kills XSS payload, parameterised query kills SQLi).

### Gate 4 — Preconditions are realistic

List every precondition the exploit needs and assess each:

| Precondition type            | OK?                                   |
| ---------------------------- | ------------------------------------- |
| Network reachability         | OK if matches threat model            |
| Auth state (anon/user/admin) | Match against advertised threat model |
| Non-default config flag      | DOWNGRADE one severity level          |
| Specific tenant role         | OK for cross-tenant findings          |
| Attacker is already root/dev | REJECT — assume-the-conclusion        |
| Browser version older than X | DOWNGRADE; cite advisory              |
| Specific runtime library     | NEEDS-MANUAL — confirm at deploy      |
| Race window < 1ms            | NEEDS-MANUAL                          |

PASS criterion: every precondition is realistic for the documented threat model.

### Gate 5 — Pseudocode PoC

Write the exploit as either:

- A concrete HTTP request (method, path, headers, body).
- A concrete CLI invocation.
- A concrete code snippet that an attacker could execute.

The PoC must reference real values (real route from this repo, real parameter name, real header). Placeholders like `<MALICIOUS_INPUT>` only acceptable when the payload is well-known and documented (e.g., `${jndi:ldap://...}` for log4shell-style).

PASS criterion: the PoC, if executed, would trigger the bug. Mental execution is enough — don't actually run it on the target.

REJECT triggers:

- PoC requires runtime behaviour you can't predict from source (DNS rebinding window, GC timing, allocator behaviour). Move to NEEDS-MANUAL.
- PoC depends on a vulnerability you didn't prove (e.g., "first compromise the JWT secret, then..."). Either prove the prerequisite separately or REJECT.

### Gate 6 — Impact matches severity

Stated severity must reflect the attacker's gain after a successful exploit:

| Severity | Required impact                                                      |
| -------- | -------------------------------------------------------------------- |
| CRITICAL | Pre-auth RCE, pre-auth full data access, persistent infra compromise |
| HIGH     | Pre-auth DoS, post-auth RCE, cross-tenant read, full ATO             |
| MEDIUM   | Post-auth privilege escalation, sensitive read with constraints      |
| LOW      | Information disclosure with limited blast radius                     |
| INFO     | No direct attacker gain; reportable for hardening only               |

PASS criterion: severity matches the demonstrated impact.

If gates 1-5 PASS but the impact is smaller than claimed → DOWNGRADE, don't REJECT. Keep the finding, lower the severity.

## Output per finding

Append this block to the finding before triage:

```
**fp-check**

| Gate | Verdict | Note                                                  |
|------|---------|-------------------------------------------------------|
| 1    | PASS    | Confirmed at <file>:<line>, code matches description. |
| 2    | PASS    | Reachable via POST /api/X (no auth).                  |
| 3    | PASS    | `req.body.url` reaches `httpClient.fetch(...)` unchanged. |
| 4    | PASS    | Anon attacker, default config.                        |
| 5    | PASS    | PoC: `curl -X POST .../api/X -d '{"url":"http://169.254.169.254/..."}'` |
| 6    | PASS    | HIGH — pre-auth SSRF to cloud metadata = creds.       |

**Triage:** ACCEPT
```

Or, if any gate fails:

```
**fp-check**

| Gate | Verdict | Note                                                  |
|------|---------|-------------------------------------------------------|
| 1    | PASS    | Source matches.                                       |
| 2    | PASS    | Reachable.                                            |
| 3    | FAIL    | Validator at line 142 enforces allowlist; payload cannot escape. |
| 4    | -       | Skipped — earlier gate failed.                        |
| 5    | -       | Skipped.                                              |
| 6    | -       | Skipped.                                              |

**Triage:** REJECT (validator blocks attacker control at line 142)
```

## Anti-patterns

- Filling the gate table with "PASS" without doing the work. Each PASS is a claim you have evidence for.
- Using NEEDS-MANUAL as a parking lot. NEEDS-MANUAL means "plausible from source, requires runtime confirmation". If the gates fail in source, REJECT.
- Letting the hunter's confidence rating drive the gate verdict. The hunter is a hint; the gates are the source of truth.
- Skipping Gate 5 because the bug "is obviously real". A finding without a PoC is not shippable.

## When to use NEEDS-MANUAL

Plausible from source but verification requires runtime/dynamic evidence:

- Race conditions where source shows the gap but timing matters.
- ReDoS where worst-case input depends on engine version.
- DNS rebinding where exploitability depends on resolver behaviour.
- File parser bugs where exploitability depends on the parser version installed at deploy.

Always document the exact test the AppSec/pentest team should run.
