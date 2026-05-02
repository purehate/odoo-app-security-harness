# Accepted-Risks Suppression

Mechanism for the `/odoo-code-review` pipeline to **skip findings the team has already triaged and accepted**, so audit cycles don't re-litigate known issues.

This is the only suppression mechanism in the skill. It is opt-in (no file = nothing suppressed) and deterministic (no fuzzy matching).

## When to use

- Risk is documented and signed off by an owner — but the code can't be fixed yet (vendor module, customer constraint, scheduled refactor, deferred remediation).
- A scanner or hunter consistently re-flags an issue that has been intentionally accepted (e.g., `auth='public'` route that _must_ stay public; `sudo()` on a model that audit confirmed is safe).
- A previous report ACCEPTED a finding and the team chose to live with it rather than remediate.

## When NOT to use

- "We don't have time to look at this." → not an accepted risk; that's a backlog item.
- "It's probably fine." → triage it through the pipeline first; suppress only after explicit acceptance.
- Suppressing a whole module or whole rule class → leave the suppression entry narrow (single fingerprint per entry).

If an entry has no `owner` and no `expires` it is not an accepted risk; it is rot.

## File lookup order

The runner picks up the first match in this order:

1. `--accepted-risks <path>` CLI flag (explicit override).
2. `<repo>/.audit-accepted-risks.yml` (default, **YAML preferred**).
3. `<repo>/.audit-accepted-risks.yaml` (alternate spelling).
4. `<repo>/.audit-accepted-risks.json` (fallback for environments without `pyyaml` installed).

If none exists, suppression is disabled and a single line is logged. Do not warn — absence is the default state.

The file lives at the repo root (one canonical source per repo), is committed to git, and is reviewed like any other policy file.

## Schema

```yaml
version: 1
risks:
  - id: AR-001
    fingerprint: 7c1f4a9b2e5d8a31
    title: Public events check-in submit allowed for non-conference events
    file: trustedsec_events/controllers/checkin.py
    lines: [175, 260]
    match: 'auth=[\"\\\']public[\"\\\']'
    pattern_kind: regex
    reason: |
      Conference partner program intentionally accepts walk-in registrations
      from non-conference events. Compensating control: registration_id is
      logged + emailed to security@ for human review. Accepted 2026-01-12 by
      Security Architecture Review Board (SARB-2026-014).
    owner: martin.bos@trustedsec.com
    accepted: 2026-01-12
    expires: 2026-07-12
    severity_was: HIGH
    references:
      - https://github.com/odshweb/trustedsec/pull/467
      - SARB-2026-014
```

### Field semantics

| Field          | Required | Type                 | Meaning                                                                                                                                                                                                                      |
| -------------- | -------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`           | yes      | string               | Stable identifier. `AR-NNN`. Must be unique in the file. Never reuse after delete.                                                                                                                                           |
| `fingerprint`  | no\*     | 16-hex string        | **Primary match key.** sha256-derived from finding shape (see § Fingerprint). Phase 8 emits this on every finding card so suppression is one-click via the report button. If present, short-circuits `file`/`lines`/`match`. |
| `title`        | yes      | string               | One-line human summary.                                                                                                                                                                                                      |
| `file`         | yes\*    | path or glob         | Repo-relative. Glob patterns OK (`module/controllers/**/*.py`). Required when `fingerprint` is omitted.                                                                                                                      |
| `lines`        | no       | int \| [int, int]    | Single line or `[start, end]` range. Omit to suppress anywhere in `file`.                                                                                                                                                    |
| `match`        | no       | string               | Snippet, substring, or regex per `pattern_kind`. Anchors the entry to a specific code shape inside the range.                                                                                                                |
| `pattern_kind` | no       | `literal` \| `regex` | Default `literal`. `regex` is Python `re.search`.                                                                                                                                                                            |
| `reason`       | yes      | string               | Why this risk was accepted. Free text. Must mention compensating control or business justification.                                                                                                                          |
| `owner`        | yes      | email or handle      | Person accountable. Must be reachable.                                                                                                                                                                                       |
| `accepted`     | yes      | date `YYYY-MM-DD`    | When the risk was accepted.                                                                                                                                                                                                  |
| `expires`      | yes      | date `YYYY-MM-DD`    | Mandatory. Default cadence: 365 days. Past `expires` = entry is treated as expired (see drift handling).                                                                                                                     |
| `severity_was` | no       | severity             | Original severity at time of acceptance. Helps Phase 8 stats.                                                                                                                                                                |
| `references`   | no       | string or list       | Tickets, PRs, design-doc links, SARB IDs.                                                                                                                                                                                    |

\* At least one of `fingerprint` or `file` must be present. Loader rejects entries that have neither — they would suppress everything.

### Fingerprint

A fingerprint is a deterministic 16-hex-char digest derived from the finding shape. Phase 8 emits it on every finding card; the `findings.html` "Mark as accepted risk" button copies it verbatim into the YAML stanza so suppression is one-click and format-correct.

Canonicalization (Phase 8 emits, hunters / fp-check recompute and compare):

```python
import hashlib

def fingerprint(file: str, primary_line: int, sink_kind: str, title: str) -> str:
    payload = f"{file}:{primary_line}:{sink_kind}:{title.strip().lower()}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
```

`sink_kind` is the technique class the hunter assigns (`controller_route`, `cr_execute`, `qweb_t_raw`, `ir_rule_domain`, `sudo_call`, `mass_assignment`, `safe_eval`, `webhook_csrf`, `attachment_public`, `dependency`, `chain_node`). It pins the fingerprint to the bug shape, so cosmetic edits to surrounding code don't drift the digest but moving the actual sink does.

If a finding's fingerprint matches an entry's `fingerprint`, the entry suppresses the finding regardless of `file`/`lines`/`match`. The legacy fields stay for human readability and as a fallback when `fingerprint` is omitted (e.g., entries written by hand for whole-shape suppression like "all `csrf=False` in this controller").

### Why `expires` is mandatory

Suppression rot is the failure mode: the team accepts a risk in 2024, the code is rewritten in 2025, but the entry still hides three new bugs in the same file. Forcing every entry to expire makes review unavoidable.

## Fingerprint matching

A finding (hunter output, scanner hit, evidence pack) matches an entry **if EITHER** the fingerprint check or all populated legacy fields match:

0. **`fingerprint` (primary, short-circuits the rest)** — if entry has `fingerprint` and finding's recomputed fingerprint equals it, suppress. Skip checks 1–3.
1. **`file`** — finding's primary `file` matches the entry's `file` (literal equality OR glob match via `fnmatch`).
2. **`lines`** — finding's primary `line` falls inside `[start, end]` (inclusive). If `lines` is omitted, this check passes.
3. **`match`** — Phase 7 reads the finding's cited line ±10 lines and tests for `match` per `pattern_kind`. If `match` is omitted, this check passes.

If `expires < today`, the entry is **expired**: it does NOT suppress (the finding goes through normal triage), and the runner logs a warning. The entry must be renewed or removed.

If an entry's `file` glob matches nothing in the repo at run time, the entry is **stale**: also logged as a warning. Stale entries are kept (the file may be re-added later), but the runner surfaces them in `00-accepted-risks.md` so they're visible.

If two entries match the same finding, both are recorded; the one with the highest `id` (latest) wins for the `accepted_risk_id` field on the suppressed finding.

## Runner output

After Phase 0, the runner writes:

- `<OUT>/00-accepted-risks.md` — human report. Lists every entry, status (`ACTIVE` / `EXPIRED` / `STALE`), days-to-expiry, owner, reason. Top of file shows totals + actionable summary (`N expired entries — review`).
- `<OUT>/inventory/accepted-risks.json` — machine artifact loaded by every hunter and the Phase 7 fp-check. Schema:

  ```json
  {
    "version": 1,
    "loaded_from": ".audit-accepted-risks.yml",
    "loaded_at": "2026-05-01T18:30:12Z",
    "active": [
      {
        "id": "AR-001",
        "fingerprint": "7c1f4a9b2e5d8a31",
        "title": "...",
        "file": "trustedsec_events/controllers/checkin.py",
        "lines": [175, 260],
        "match": "auth=[\"']public[\"']",
        "pattern_kind": "regex",
        "owner": "martin.bos@trustedsec.com",
        "expires": "2026-07-12",
        "days_remaining": 72
      }
    ],
    "expired": [...],
    "stale": [...]
  }
  ```

These artifacts are what hunters and the fp-check read. Entries are never injected into raw hunter prompts as YAML — only as the JSON path so each lane can deserialize once.

## Hunter-side behavior

Each hunter packet includes the path to `inventory/accepted-risks.json` and is instructed to:

1. Load the JSON.
2. Before emitting a finding, compute its 16-hex `fingerprint` per the canonical formula (see § Fingerprint).
3. If `fingerprint` matches any `active[].fingerprint`: **drop the finding silently**, do not output it. (Primary path.)
4. Else, fall back to legacy match: if `file` + (optional) `lines` + (optional) `match` from any `active` entry all match, drop silently. (Fallback path for hand-written entries.)
5. If it matches an `expired` entry by either path: emit the finding normally, **add a note**: `Expired accepted-risk: AR-NNN (expired YYYY-MM-DD, owner X) — re-review`.
6. Stale entries are not the hunter's concern.

Hunters never write into the accepted-risks file.

## Phase 7 fp-check Gate 0

Phase 7 runs Gate 0 **before Gate 1**:

| Gate | Verdict | Note                                                                               |
| ---- | ------- | ---------------------------------------------------------------------------------- |
| 0    | SKIP    | Matches accepted risk AR-NNN by `fingerprint` or legacy match (expires YYYY-MM-DD) |

If Gate 0 SKIPs:

- Finding is dropped from the report's main body.
- Finding is recorded in `00-accepted-risks.md` under "Findings suppressed this run" with the matching `id`, the original hunter, and a one-line summary.
- Gates 1–6 do not run.

If Gate 0 fires on an _expired_ entry, the finding goes through Gates 1–6 and gets a `expired_accepted_risk: AR-NNN` annotation in the report.

This keeps the suppression auditable: every accepted risk and every expired-but-still-suppressed candidate is visible in one file per run.

## Anti-patterns

- **Wildcard `file: '**/\*.py'`with no`lines`,`match`, or `fingerprint`** — suppresses everything. Always narrow at least one of `fingerprint`/`file`+`lines`/`file`+`match`.
- **Broad regex like `match: '.*'`** — same problem.
- **Hand-typed `fingerprint`** — never invent one. Either copy from the report button (Phase 8 emits it) or omit the field and use `file`/`lines`/`match` instead.
- **Omitting `expires`** — rejected by the loader.
- **Setting `expires: 9999-12-31`** — flagged by the loader as "permanent suppression"; not blocked, but recorded as a HIGH-noise entry in `00-accepted-risks.md`.
- **Suppressing a whole module** — write one entry per finding shape. If you have eight entries for the same module, that's a signal the module needs a rewrite, not suppression.
- **Suppressing a finding you haven't read** — `reason` field exists to force the writer to articulate _why_. Empty `reason` is a load error.

## Lifecycle

```
finding raised → triaged → accepted by owner → entry added with expires → entry expires → re-review → renew (new expires) OR remove
```

Re-review at expiry must be a deliberate decision. The runner logs expired entries every run; CI can grep for `EXPIRED` in `00-accepted-risks.md` to fail the build.

## Loader validation rules (enforced by runner)

The runner aborts the entire `/odoo-code-review` run if any rule below fails. Suppression is policy; failures must be visible.

1. Top-level `version` must be `1`.
2. Top-level `risks` must be a list.
3. Every entry has all required fields populated.
4. `id` is unique within the file.
5. `expires` parses as `YYYY-MM-DD`.
6. `accepted` parses as `YYYY-MM-DD` and is not in the future.
7. `accepted <= expires`.
8. `pattern_kind` ∈ {`literal`, `regex`} (default `literal`).
9. `match` (if `regex`) compiles via `re.compile`.
10. At least one of `fingerprint` (16-hex string, `[0-9a-f]{16}`) or `file` (non-empty string) is present. If both, both must be valid.
11. `reason` is non-empty after trim.
12. `owner` is non-empty after trim.
13. `fingerprint` (if present) matches `^[0-9a-f]{16}$`.

Any other unrecognised top-level key or per-entry key is a warning, not a failure (forward-compatible).

## CI integration suggestion

```bash
~/.claude/skills/odoo-code-review/scripts/odoo-review-run \
    --accepted-risks .audit-accepted-risks.yml \
    --check-only-accepted-risks
```

`--check-only-accepted-risks` validates the file, prints expired/stale, and exits non-zero on validation errors or expired entries. Useful as a pre-commit / CI gate so suppression entries don't silently rot.
