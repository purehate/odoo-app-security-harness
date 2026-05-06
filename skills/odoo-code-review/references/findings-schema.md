# findings.json Schema

Canonical machine-readable sidecar emitted when `--json` is set. Consumed by:

- `odoo-review-export` — converts to SARIF, fingerprints, bounty drafts
- `odoo-review-diff` — diffs two runs (new / fixed / unchanged)
- GitHub Action workflow — uploads SARIF, comments PR

This schema is the contract. Codex/Claude must produce it during Phase 8 when `--json` is active. Everything downstream depends on it.

## Top-Level Shape

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-05-01T22:30:00Z",
  "target": {
    "repo": "/abs/path/to/odoo-addons",
    "commit": "deadbeef...",
    "modules_scoped": ["portal", "sale"],
    "odoo_version": "16.0"
  },
  "harness": {
    "version": "0.1.0",
    "command": "odoo-review-run /path --json",
    "lanes": {
      "claude": true,
      "qwen": true,
      "codex": true
    }
  },
  "stats": {
    "modules_count": 47,
    "routes_count": 312,
    "loc_python": 184231,
    "wall_clock_seconds": 4382,
    "total_findings": 18
  },
  "findings": [ Finding, ... ],
  "chains": [ Chain, ... ],
  "tooling": { ToolingRecord }
}
```

## Finding

```json
{
  "id": "F-1",
  "fingerprint": "sha256:abcd1234...",
  "title": "Portal user can read internal sales orders via crafted attachment URL",
  "severity": "high",
  "confidence": "high",
  "triage": "ACCEPT",
  "false_positive_reason": null,
  "odoo_surface": "portal_route",
  "module": "portal",
  "file": "addons/portal/controllers/main.py",
  "line": 142,
  "function": "portal_attachment",
  "cwe": ["CWE-639", "CWE-200"],
  "capec": ["CAPEC-21"],
  "cvss": {
    "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "score": 6.5,
    "version": "3.1"
  },
  "description": "Multiline narrative description of the bug, who can trigger, what they get.",
  "attack_path": "Portal user authenticates → calls /portal/attachment with crafted ID → ORM bypass via sudo() chain → reads sale.order record outside their company.",
  "poc": "curl -b 'session_id=...' 'https://target/portal/attachment?id=42'",
  "reproduction": "Step-by-step text or path to <OUT>/runtime/reproductions/F-1.sh",
  "impact": "Cross-tenant data exposure of order line items, totals, customer addresses.",
  "fix": "Replace sudo() with explicit access_check() against res.users; restrict by company_id.",
  "fp_check": {
    "reachability": "yes",
    "attacker_control": "yes",
    "missing_validation": "yes",
    "actually_exploitable": "yes",
    "real_security_impact": "yes",
    "demonstrable_with_poc": "yes",
    "evidence": [
      "addons/portal/controllers/main.py:142 route uses sudo before ownership check",
      "addons/portal/controllers/main.py:151 response serializes sale.order fields"
    ],
    "resolution_chain": [
      "GET /portal/attachment?id=42",
      "request.params['id']",
      "env['sale.order'].sudo().browse(id)",
      "record.read(...)"
    ],
    "unresolved_hops": []
  },
  "variants": [
    {
      "file": "addons/portal/controllers/main.py",
      "line": 287,
      "note": "Same pattern, different field — likely sibling."
    }
  ],
  "second_opinion": {
    "verdict": "AGREE",
    "poc_writeable": true,
    "notes": "Codex independent session confirmed."
  },
  "references": [
    "https://github.com/odoo/odoo/blob/16.0/addons/portal/controllers/main.py#L142"
  ],
  "tags": ["portal", "idor", "sudo-misuse"]
}
```

### Required fields (minimum viable finding)

`id`, `title`, `severity`, `triage`, `module`, `file`, `line`, `description`, `fp_check`.

### Severity values

`critical | high | medium | low | info`

### Triage values

`ACCEPT | DOWNGRADE | REJECT | NEEDS-MANUAL`

### Confidence values

`high | medium | low`

### False-positive reason

`false_positive_reason` is required when `triage` is `REJECT` or `DOWNGRADE`, and should be `null` or omitted for `ACCEPT`.

Use it to preserve the lesson from rejected leads:

- `"validator at addons/x/controllers/main.py:88 coerces id to int before browse"`
- `"route is auth='user' and group guard requires base.group_system before sudo path"`
- `"demo XML only; module data file is not loaded in production manifest"`

### Evidence obligations

`fp_check.evidence`, `fp_check.resolution_chain`, and `fp_check.unresolved_hops` are optional for older reports but recommended for new reports.

- `evidence`: concrete `file:line` citations supporting the verdict.
- `resolution_chain`: source-to-sink or route-to-model hops verified during triage.
- `unresolved_hops`: aliases, wrappers, runtime config, or deployment facts that could not be resolved statically. `ACCEPT` findings should have an empty or non-critical unresolved list.

## Chain

```json
{
  "id": "C-1",
  "title": "Portal IDOR → ACL bypass → cross-tenant exfil",
  "severity": "critical",
  "finding_ids": ["F-1", "F-3", "F-7"],
  "graph": "attack-graphs/chain-1.svg",
  "narrative": "Multiline description of how F-1 → F-3 → F-7 compose."
}
```

## Fingerprint

`fingerprint` is `sha256(rule_id|file|normalized_line|snippet_first40chars)` — stable across runs unless one of those changes. Used by `odoo-review-diff` to label findings as `new | unchanged | fixed`.

`odoo-review-export` computes this if missing. Codex/Claude do not need to populate it manually.

## CWE / CAPEC

Tag every ACCEPT finding with at least one CWE. Use the CWE map at `inventory/cwe-map.json` (seeded by runner) for common Odoo bug shapes. Bug bounty programs and SARIF require CWE.

## ToolingRecord

Mirrors `tooling.json` shape (already produced by runner). Embedded in findings.json for full reproducibility.
