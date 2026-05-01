# Triage — Rubric, Output Format, Stats

## Triage Rubric

For every finding the orchestrator must read the cited `file:line` and assign one of:

### ACCEPT

All of:

- Source confirms the bug at the cited location.
- Data flow from a reachable entry point to the dangerous sink is real.
- Preconditions are realistic (no "attacker is already root").
- Impact is meaningful: code execution, data exfil, auth bypass, persistent DoS, integrity loss.
- Not a re-report of a fixed CVE in this codebase.

### DOWNGRADE

Real bug, but smaller blast radius than the hunter claimed. Examples:

- RCE claim that's actually post-auth-only and behind a feature flag — DOWNGRADE to MEDIUM.
- "Pre-auth" SSRF that requires a config flag enabled by default `false` — DOWNGRADE.
- Theoretical RCE on a deserialization path where every entry point uses an allowlisted type — DOWNGRADE to LOW or REJECT.

Lower the severity, keep the finding, document the mitigating factor in the **Notes** field.

### REJECT

One or more of:

- Source does not match the hunter's claim. Hunter hallucinated.
- Requires impossible precondition.
- Re-report of a fixed CVE — verify the fix is in this version.
- API contract: the call is documented as "caller must validate" and the framework consumer cannot reach it without already having admin / source code access.
- Theoretical: no sink, no exploitable behavior.
- Style / lint / "best practice without exploitability".

Document **why** in the Notes field. Future audits should not re-investigate.

### NEEDS MANUAL TESTING

Plausible from source, but exploitability requires runtime confirmation:

- Race condition windows that depend on timing.
- ReDoS where worst-case input depends on engine version.
- DNS rebinding that depends on resolver cache behavior.
- File parser bugs that depend on the parser version installed at runtime.

Hand off to AppSec / pentest team with the source pointer and the test you'd run.

## Final Report Format

````markdown
# <Project> Source-Code Security Review

**Date:** <ISO date>
**Auditor:** AI-assisted (Claude-led with Codex/Qwen support)  
**Repo:** <git remote + commit hash>
**Scope:** <module list or "full repo">
**Method:** odoo-codereview skill, 4-phase technique-organized audit

## Findings Table

| #   | Title                        | Severity | Confidence | Triage    | File:Line                                                    |
| --- | ---------------------------- | -------- | ---------- | --------- | ------------------------------------------------------------ |
| 1   | SockJS pre-auth DoS          | HIGH     | HIGH       | ACCEPT    | spring-websocket/.../TransportHandlingSockJsService.java:291 |
| 2   | Jaxb2Marshaller schema XXE   | MEDIUM   | HIGH       | ACCEPT    | spring-oxm/.../Jaxb2Marshaller.java:588                      |
| 3   | CORS regex partial match     | LOW      | MEDIUM     | DOWNGRADE | spring-web/.../CorsConfiguration.java:776                    |
| 4   | TableMetaDataContext quoting | INFO     | HIGH       | REJECT    | spring-jdbc/.../TableMetaDataContext.java:291                |

## Per-Finding Detail

### Finding 1 — SockJS pre-auth DoS

**Severity:** HIGH
**Confidence:** HIGH
**Triage:** ACCEPT
**File:** spring-websocket/.../TransportHandlingSockJsService.java:291
**CWE:** CWE-770 (Allocation of Resources Without Limits)

**Description**

`createSockJsSession()` inserts a new session into `this.sessions` BEFORE `checkOrigin()` runs.
On origin rejection the early `return` skips the cleanup at lines 333-336, leaking the session.
Pre-auth attacker can fill the map by spamming forbidden-origin requests.

**Attack Path**

1. Attacker sends repeated SockJS requests with a forbidden Origin header.
2. Each request allocates a session before the origin check.
3. The 403 response path returns early, never removing the session.
4. Unbounded growth in `this.sessions` map.

**Proof of Concept**

```bash
for i in $(seq 1 1000000); do
  curl -s -H "Origin: http://evil.example" \
       https://target/sockjs/000/$i/xhr_streaming &
done
```
````

**Reproduction Steps**

1. Deploy any Spring app that exposes `/sockjs/**` with `setAllowedOrigins("https://app.example")`.
2. Run the loop above from a single attacker host.
3. Observe heap growth via JMX / `jmap -histo`.
4. Eventually OOM or GC thrashing → service unavailable.

**Impact**

Pre-auth memory exhaustion. No login required. Single attacker can DoS the app.

**Suggested Fix**

Move `checkOrigin()` before `createSockJsSession()`, or ensure cleanup runs on the origin-rejection branch.

**Notes**

Verified against commit `<hash>`. Reproduces under default config when SockJS is enabled.
Proposing upstream issue.

---

[repeat per finding]

## Engagement Stats

| Metric              | Value    |
| ------------------- | -------- |
| LOC scanned         | <number> |
| Files scanned       | <number> |
| Modules             | <number> |
| Languages           | <list>   |
| Wall-clock          | <m:ss>   |
| Parallel hunters    | 10       |
| Findings (raw)      | <number> |
| Findings (accepted) | <number> |
| ACCEPT              | <number> |
| DOWNGRADE           | <number> |
| REJECT              | <number> |
| NEEDS MANUAL        | <number> |
| Tokens consumed     | <number> |
| Estimated cost      | $<x.xx>  |

## Hunter Breakdown

| Hunter              | Wall-clock | Findings (raw) | Accepted |
| ------------------- | ---------- | -------------- | -------- |
| Auth & Session      | <m:ss>     | 2              | 0        |
| Authorization       | <m:ss>     | 1              | 0        |
| Injection           | <m:ss>     | 3              | 1        |
| Deserialization     | <m:ss>     | 2              | 1        |
| SSRF / Files        | <m:ss>     | 1              | 0        |
| Crypto & Secrets    | <m:ss>     | 0              | 0        |
| Business Logic      | <m:ss>     | 1              | 0        |
| External Interfaces | <m:ss>     | 5              | 2        |
| Supply Chain        | <m:ss>     | 2              | 0        |
| Chaining            | <m:ss>     | 0              | 0        |

## Recommended Actions

For each ACCEPT and DOWNGRADE:

- [ ] File upstream issue at `<repo URL>` (link if filed)
- [ ] Hardening PR (link if drafted)
- [ ] No action — reasoning: <one line>

## Methodology

- Phase 1: Repo recon, language/framework identification, module risk ranking, hunter assignment.
- Phase 2: 10 parallel specialist hunters dispatched concurrently.
- Phase 3: Cross-finding correlation by chaining hunter.
- Phase 4: Source-level verification of every finding by orchestrator.
- All findings backed by file:line evidence and a concrete PoC.
- Historical fixed CVEs excluded unless a regression was demonstrated.

```

## Reference: Spring Framework 7.0 Demo Run

Demo data from earlier engagement (530k LOC, ~7m wall-clock, 4 findings):

| Finding                                | Severity | Triage    | File                                          |
|----------------------------------------|----------|-----------|-----------------------------------------------|
| SockJS pre-auth DoS via session leak   | HIGH     | ACCEPT    | TransportHandlingSockJsService.java:291       |
| Jaxb2Marshaller schemaParserFactory XXE| MEDIUM   | ACCEPT    | Jaxb2Marshaller.java:588                      |
| CORS regex full-match interpretation   | LOW      | DOWNGRADE | CorsConfiguration.java:776                    |
| TableMetaDataContext identifier quoting| INFO     | REJECT    | TableMetaDataContext.java:291                 |

Use this as a baseline for what "looks right" coming out of a Spring-class engagement. Different stack will produce different finding distribution.
```
