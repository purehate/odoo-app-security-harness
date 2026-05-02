# Weekly Audit Workflow

`odoo-code-review` is a recurring tool. One run produces a stamped
`.audit-YYYYMMDD-HHMM/` directory; previous runs stay intact. State
carries between runs through two master files at the repo root.

## Master files (loop state)

| File                               | Purpose                                                                                             |
| ---------------------------------- | --------------------------------------------------------------------------------------------------- |
| `<repo>/.audit-accepted-risks.yml` | Findings to suppress on every run. Schema validates dates and ownership.                            |
| `<repo>/.audit-fix-list.yml`       | Findings tracked for fix. Reconciles each run for REGRESSION / CONFIRMED-FIXED / TRACKED / DRIFTED. |

Both are read on every run. Override paths via `--accepted-risks` / `--fix-list`. Bootstrap minimal stubs (`version: 1`, empty list) — full schema with comments lives in `references/accepted-risks.example.yml` and `references/fix-list.example.yml`.

## Per-run output

`<repo>/.audit-YYYYMMDD-HHMM/` — datetime-stamped. Default behaviour, no flag needed.

```
.audit-20260502-1351/
├── 00-accepted-risks.md   # validation snapshot of master file
├── 00-fix-list.md         # validation snapshot of master file
├── findings.{md,html,json}
├── attack-graphs/
├── runtime/
└── tooling.md
```

Old runs stay until you prune. Use `--prune-old-runs N` to keep only the most recent N stamped dirs.

## Weekly loop

```
Mon morning
  ~/.claude/skills/odoo-code-review/scripts/odoo-review-run \
    /Users/mbos/DEVELOPMENT/Odoo/trustedsec \
    --runtime --zap-target http://host.docker.internal:8069 \
    --joern --prune-old-runs 8
  → produces .audit-YYYYMMDD-HHMM/

Mon-Tue triage
  open .audit-YYYYMMDD-HHMM/findings.html
  for each finding:
    - already known + accepted   → click "Mark as accepted risk"
    - real bug to fix            → click "Add to fix-it list"
    - false positive             → suppress as accepted risk with reason="FP"

  click "Export YAML" on each toolbar
  paste into:
    yellow → .audit-accepted-risks.yml under `risks:`
    green  → .audit-fix-list.yml under `fixes:`

Tue-Fri
  hand fix-list open/in-progress entries to Claude/Codex
  ship fixes, flip status: open → in-progress → fixed

Next Mon
  rerun. Compare. Reconciliation auto-tags REGRESSION / CONFIRMED-FIXED.
```

## Validation-only modes

Pre-commit / CI sanity checks without running the full audit:

```
# Verify accepted-risks file parses, no expired entries past today
odoo-review-run /path/to/repo --check-only-accepted-risks

# Verify fix-list file parses, flag overdue open/in-progress
odoo-review-run /path/to/repo --check-only-fix-list
```

Both exit non-zero on validation errors so CI can gate.

## Pruning history

`--prune-old-runs 8` keeps the 8 most recent stamped runs and deletes older ones (only after the current run succeeds). Recommended cadence: weekly run, keep 8–12 weeks of history.

To keep a specific run forever, rename it (e.g., `.audit-20260101-0900-q1-baseline`) — the prune logic only matches the strict `.audit-YYYYMMDD-HHMM` shape.

## Notes

- The HTML toolbar's YAML export already includes the stable 16-hex fingerprint per entry. That fingerprint short-circuits file/line drift on the next run, so suppressions and fix tracking survive code refactors.
- `accepted-risks` `expires:` field is mandatory. 365-day cadence by default. EXPIRED entries surface in `00-accepted-risks.md` as a re-review reminder rather than silently disappearing.
- A finding that is BOTH on the fix-list and the accepted-risks list is a misconfiguration — fix-list reconciliation will warn.
