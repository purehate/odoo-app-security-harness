# Fix-It List Tracking

Mechanism for the `/odoo-code-review` pipeline to **track findings the team has confirmed as real bugs and committed to fixing**, so successive audit runs report regressions and "fixed since last run" instead of re-litigating the same finding.

This is the symmetric companion to accepted-risks suppression:

| Bucket               | Verdict              | What the next run does                                                                                                        |
| -------------------- | -------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `accepted-risks.yml` | not a bug / accepted | Gate 0 SKIP — finding never enters the report.                                                                                |
| `fix-list.yml`       | real bug, will fix   | Finding still emitted, tagged with FIX-NNN tracking metadata; flipping `status: fixed` enables auto-detection of regressions. |

Both files are opt-in (no file = nothing tracked) and deterministic (no fuzzy matching).

## Workflow

```
run /odoo-code-review → human reads findings.html → for each finding:
  ├── click "Mark as accepted risk" → paste into .audit-accepted-risks.yml → next run silently drops it
  └── click "Add to fix-it list"    → paste into .audit-fix-list.yml       → next run tags it + tracks status
```

The fix-list is the team's working backlog of confirmed bugs. As fixes ship, owners flip `status: open` → `status: fixed`. The next run's Phase 8 reconciliation tells the team:

- Which `open` items remain (still vulnerable in source).
- Which `fixed` items are gone from the report (✓ confirmed remediated, can archive).
- Which `fixed` items still appear in the report (**REGRESSION** — fix didn't land or someone re-introduced the bug).
- Which `wontfix` items still appear (passive tag — not a regression).

## When to use

- A finding has been triaged and confirmed exploitable; the team has agreed to fix it but the fix isn't shipped yet.
- A regression-canary entry: track a fix that has shipped (status `fixed`) so subsequent runs alert if the bug ever comes back.
- A `wontfix` entry: the team has decided not to fix and not to suppress (e.g., "we'll rewrite this module next quarter, no patch in the meantime"). Differs from `accepted-risk` because there is no compensating control or formal acceptance — just deferred work that the report should keep showing.

## When NOT to use

- "We don't have time to look at this." → triage first; fix-list entries require a confirmed-bug decision.
- A risk that was accepted with compensating controls → that's `accepted-risks.yml`, not the fix-list.
- A finding the team disagrees with → REJECT it in Phase 7 fp-check, don't park it in the fix-list.

## File lookup order

1. `--fix-list <path>` CLI flag (explicit override).
2. `<repo>/.audit-fix-list.yml` (default, **YAML preferred**).
3. `<repo>/.audit-fix-list.yaml` (alternate spelling).
4. `<repo>/.audit-fix-list.json` (fallback for environments without `pyyaml`).

If none exists, fix-list tracking is disabled and a single line is logged. Absence is the default state.

The file lives at the repo root, is committed to git, and reviewed like any other backlog file. It is the single source of truth for "what we've confirmed and intend to fix".

## Schema

```yaml
version: 1
fixes:
  - id: FIX-001
    fingerprint: 7c1f4a9b2e5d8a31
    title: Public events check-in submit allowed for non-conference events
    file: trustedsec_events/controllers/checkin.py
    lines: [175, 260]
    severity: HIGH
    sink_kind: controller_route
    owner: martin.bos@trustedsec.com
    status: open
    target_date: 2026-06-01
    notes: |
      Sprint 47, ticket TS-1234. Plan: add HMAC verification on
      registration_id + reject cross-event submission. PR draft #468.
    references:
      - https://github.com/odshweb/trustedsec/issues/512
      - TS-1234
```

### Field semantics

| Field         | Required | Type                                                | Meaning                                                                                                                                |
| ------------- | -------- | --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `id`          | yes      | string                                              | Stable identifier. `FIX-NNN`. Unique within the file. Never reuse after delete.                                                        |
| `fingerprint` | no\*     | 16-hex                                              | **Primary match key.** Same canonicalization as accepted-risks. If present, short-circuits `file`/`lines` for reconciliation.          |
| `title`       | yes      | string                                              | One-line human summary. Must match the original finding's title closely so reports stay readable.                                      |
| `file`        | yes\*    | path or glob                                        | Repo-relative. Required when `fingerprint` is omitted.                                                                                 |
| `lines`       | no       | int \| [int, int]                                   | Single line or `[start, end]` range. Used as a fallback locator and to keep the entry human-readable.                                  |
| `severity`    | yes      | `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW` \| `INFO` | Severity at the time of intake. Reconciliation uses this for sorting + summary stats.                                                  |
| `sink_kind`   | no       | sink-kind enum                                      | Same enum as accepted-risks (`controller_route`, `cr_execute`, `qweb_t_raw`, `ir_rule_domain`, `sudo_call`, `mass_assignment`, etc).   |
| `owner`       | yes      | email or handle                                     | Person accountable for shipping the fix. Must be reachable.                                                                            |
| `status`      | yes      | `open` \| `in-progress` \| `fixed` \| `wontfix`     | Tracking state. Reconciliation logic depends on this — see § Reconciliation.                                                           |
| `target_date` | no       | date `YYYY-MM-DD`                                   | When the team expects to ship. Reconciliation flags entries past target with `OVERDUE`. Optional for `fixed`/`wontfix`.                |
| `notes`       | no       | string                                              | Free text. Sprint, ticket, PR link, plan-of-attack. Should answer "what is the fix and why hasn't it shipped yet?"                     |
| `references`  | no       | string or list                                      | Tickets, PRs, issue links. PR URL strongly recommended once a fix is in flight — reconciliation can later auto-detect the merge state. |
| `fixed_at`    | no       | date `YYYY-MM-DD`                                   | When `status` was flipped to `fixed`. Loader auto-stamps this if the user sets `status: fixed` without a date.                         |

\* At least one of `fingerprint` or `file` must be present. Loader rejects entries with neither.

### Status semantics

- `open` — bug confirmed, fix not started. Reconciliation tags every matching finding with `(tracked: FIX-NNN, target YYYY-MM-DD)`.
- `in-progress` — fix is being implemented. Same tagging as `open` plus an "in flight" badge in `00-fix-list.md`.
- `fixed` — fix has shipped. Reconciliation expects the finding to be **gone**. If the finding is still in the report, that is a **REGRESSION** (red banner).
- `wontfix` — explicit decision not to fix and not to suppress. Reconciliation tags every matching finding with `(wontfix per FIX-NNN)`. Differs from `accepted-risks.yml` because there is no compensating control — `wontfix` is a documented gap, not an accepted risk.

### Why `target_date` is optional but encouraged

Without target dates, the fix-list rots into a parking lot. Reconciliation surfaces every `open`/`in-progress` entry past its `target_date` in an `OVERDUE` section so owners are forced to either ship, slip the date, or reclassify.

## Reconciliation

After Phase 8 emits findings.json (or after Phase 7 triage if Phase 8 is skipped), the runner reconciles every fix-list entry against the current run's ACCEPT-tier findings:

| Fix-list status        | Finding still present? | Output bucket                                  |
| ---------------------- | ---------------------- | ---------------------------------------------- |
| `open` / `in-progress` | yes                    | TRACKED (tag finding `tracked: FIX-NNN`)       |
| `open` / `in-progress` | no                     | LIKELY-FIXED (prompt owner to flip to `fixed`) |
| `fixed`                | yes                    | **REGRESSION** (red — fix didn't hold)         |
| `fixed`                | no                     | CONFIRMED-FIXED (✓; safe to archive)           |
| `wontfix`              | yes                    | WONTFIX (passive tag)                          |
| `wontfix`              | no                     | DRIFTED (the bug is gone — recommend remove)   |

Match logic: same as accepted-risks (`fingerprint` primary, `file`+`lines` fallback). One fix-list entry can match at most one finding per run.

`<OUT>/00-fix-list.md` shows the buckets in a fixed order so the human reader sees regressions at the top, then overdue, then in-progress, then fixed/confirmed, then wontfix, then drifted/likely-fixed for cleanup.

## Runner output

After Phase 0:

- `<OUT>/inventory/fix-list.json` — machine artifact loaded by Phase 8 reconciliation. Same shape as `accepted-risks.json` (`active`, `errors`; no `expired`/`stale` since target_date is advisory).
- (No `00-fix-list.md` yet — emitted after reconciliation in Phase 8.)

After Phase 8 reconciliation:

- `<OUT>/00-fix-list.md` — human report with REGRESSION / OVERDUE / TRACKED / CONFIRMED-FIXED / LIKELY-FIXED / WONTFIX / DRIFTED buckets.
- Findings in `findings.html` ACCEPT cards that match a `tracked` entry get a green "tracked" pill with the `FIX-NNN` and `target_date`; matches against `fixed` get a red "REGRESSION" pill at the top of the card; matches against `wontfix` get a grey "wontfix" pill.

## Phase 8 reconciliation pseudo-code

```python
for finding in current_run.accept_findings:
    fp = compute_fingerprint(finding)
    entry = fix_list.match(fp) or fix_list.match_legacy(finding.file, finding.line)
    if not entry:
        continue
    if entry.status in ("open", "in-progress"):
        finding.tracked_by = entry.id
        finding.tracking_target = entry.target_date
        bucket["tracked"].append((entry, finding))
    elif entry.status == "fixed":
        finding.regression = entry.id
        bucket["regression"].append((entry, finding))
    elif entry.status == "wontfix":
        finding.wontfix = entry.id
        bucket["wontfix"].append((entry, finding))

for entry in fix_list.active:
    if entry not in matched:
        if entry.status in ("open", "in-progress"):
            bucket["likely_fixed"].append(entry)
        elif entry.status == "fixed":
            bucket["confirmed_fixed"].append(entry)
        elif entry.status == "wontfix":
            bucket["drifted"].append(entry)

for entry in bucket["tracked"] + bucket["in_progress"]:
    if entry.target_date and entry.target_date < today:
        bucket["overdue"].append(entry)
```

## Anti-patterns

- **Hand-typed `fingerprint`** — never invent one. Use the report button. A fingerprint that doesn't match any real finding becomes a STALE entry in `00-fix-list.md`.
- **`status: fixed` without verifying the fix shipped** — the next run will scream REGRESSION. Only flip after the PR is merged and deployed.
- **Using `wontfix` as a permanent suppression** — that's `accepted-risks.yml` with a real `reason` and `expires`. `wontfix` is for documented gaps the team is willing to ship with, not for hiding findings.
- **Overdue entries with no plan-of-attack in `notes`** — reconciliation surfaces them. Either update `target_date`, ship the fix, or reclassify.
- **Letting `fixed` entries pile up forever** — once a fix is `CONFIRMED-FIXED` (status fixed + finding gone), archive the entry after a reasonable canary window (3–6 months). Long-term regression-canary protection lives in scope.yml/CI assertions, not in the fix-list.

## Loader validation rules (enforced by runner)

The runner aborts the run if any rule fails:

1. Top-level `version` must be `1`.
2. Top-level `fixes` must be a list.
3. Every entry has all required fields populated.
4. `id` is unique within the file.
5. `status` ∈ {`open`, `in-progress`, `fixed`, `wontfix`}.
6. `severity` ∈ {`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`}.
7. `target_date` (if present) parses as `YYYY-MM-DD`.
8. `fixed_at` (if present) parses as `YYYY-MM-DD`.
9. `fingerprint` (if present) matches `^[0-9a-f]{16}$`.
10. At least one of `fingerprint` or `file` is present.
11. `notes` is non-empty when `status` is `wontfix` (force the writer to articulate why).

Other unrecognised keys are warnings, not failures.

## CI integration suggestion

```bash
~/.claude/skills/odoo-code-review/scripts/odoo-review-run \
    --fix-list .audit-fix-list.yml \
    --check-only-fix-list
```

`--check-only-fix-list` validates the file, prints overdue entries, and exits non-zero on validation errors or any `open`/`in-progress` entry past its `target_date`. Useful as a pre-commit / CI gate so the backlog doesn't rot.

## Lifecycle

```
finding raised → triaged → confirmed bug → fix-list entry (status: open)
    → work scheduled (status: in-progress, target_date set)
    → PR merged + deployed (status: fixed, fixed_at stamped)
    → next /odoo-code-review run confirms finding is gone (CONFIRMED-FIXED)
    → entry archived after canary window
```

If at any step the team decides to defer indefinitely → either accept (move to `accepted-risks.yml` with `reason`/`expires`) or `wontfix` (with `notes` explaining the documented gap).
