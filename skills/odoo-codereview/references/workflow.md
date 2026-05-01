# Workflow — Exhaustive Phase Detail (Odoo)

The phases. Run in order. Don't skip.

Pipeline:

| Phase | Name                                           | Output                                                      |
| ----- | ---------------------------------------------- | ----------------------------------------------------------- |
| 0     | Odoo Module Inventory + Manifest Map           | `00-modules.md`, `inventory/`                               |
| 1     | Odoo Attack Surface Map                        | `01-attack-surface.md`                                      |
| 1.5   | Local Qwen / Ollama advisory check             | `local-qwen/`                                               |
| 2     | Semgrep Python/Odoo (community + custom rules) | `scans/semgrep/`                                            |
| 2.5   | Bandit sweep                                   | `scans/bandit/`                                             |
| 2.6   | Ruff + pylint-odoo + OCA pre-commit            | `scans/ruff/`, `scans/pylint-odoo/`, `scans/oca-precommit/` |
| 3     | CodeQL Python dataflow                         | `scans/codeql/`, `codeql-dbs/`                              |
| 3.5   | Joern graph review (optional)                  | `scans/joern/`, `cpg.bin`                                   |
| 4     | Pysa optional taint analysis                   | `scans/pysa/`                                               |
| 4.5   | osv-scanner / pip-audit dependency scan        | `scans/deps/`                                               |
| 5     | Codex Odoo specialist hunters                  | `agents/hunter-*.md`                                        |
| 5.5   | Codex discourse draft + Claude resolution      | `agents/discourse-*.md`                                     |
| 6     | Codex chaining draft + Claude finalization     | `agents/chaining.md`                                        |
| 7     | Codex evidence packs + Claude 6-gate verdicts  | `variants/finding-*.md`                                     |
| 7.5   | Runtime testing — odoo-bin shell + ZAP (opt)   | `runtime/`                                                  |
| 7.6   | Attack graph DOT/SVG (chained findings)        | `attack-graphs/`                                            |
| 7.7   | Codex adversarial 2nd opinion                  | `codex/`                                                    |
| 7.8   | Requirements-aware verification (optional)     | `requirements/`                                             |
| 8     | Output assembly — `findings.md` + `.html`      | `findings.md`, `findings.html`, `tooling.md`                |

## Output Directory Convention

Every engagement writes to a single `<OUT>` directory. Default `<repo>/.audit/`, override with `--out <dir>`.

```
<OUT>/
├── 00-modules.md              # Phase 0 — manifest summaries, depends graph
├── 01-attack-surface.md       # Phase 1 — routes, models, ACL, cron, mail templates
├── inventory/                 # Phase 0 — raw manifest JSON, route map, ACL CSV index
├── local-qwen/                # Phase 1.5 — skipped only with --no-local-qwen
│   ├── module-notes.md        # local-only module/risk summaries
│   ├── scanner-triage.md      # local scanner-hint triage
│   └── reject-candidates.md   # obvious rejects for Phase 7 to verify
├── scans/
│   ├── semgrep/               # Phase 2 — community + custom Odoo rules
│   ├── bandit/                # Phase 2.5 — SARIF
│   ├── ruff/                  # Phase 2.6 — JSON
│   ├── pylint-odoo/           # Phase 2.6 — JSON
│   ├── oca-precommit/         # Phase 2.6 — JSON
│   ├── codeql/                # Phase 3 — SARIF per query suite
│   ├── joern/                 # Phase 3.5 — query results + cpg.bin (only with --joern)
│   ├── pysa/                  # Phase 4 — JSON taint output (optional)
│   └── deps/                  # Phase 4.5 — pip-audit + osv-scanner JSON
├── codeql-dbs/                # Phase 3 — extracted CodeQL DB(s)
├── agents/
│   ├── hunter-{name}.md       # Phase 5 — each hunter's findings
│   ├── discourse-input.md     # Phase 5.5 — packet sent to hunters
│   ├── discourse-{name}.md    # Phase 5.5 — per-hunter discourse
│   ├── discourse-summary.md   # Phase 5.5 — consolidated discourse
│   └── chaining.md            # Phase 6 — chained findings
├── variants/
│   └── finding-N.md           # Phase 7 — variant search per ACCEPT
├── runtime/                   # Phase 7.5 — only if --runtime
│   ├── reproductions/         # PoC requests + responses
│   ├── odoo-shell-output/     # validation via odoo-bin shell
│   └── zap/                   # zap-baseline.html + active-scan.json (only with --zap-target)
├── attack-graphs/             # Phase 7.6 — only for chained findings
│   ├── chain-N.dot            # source → hops → sink
│   └── chain-N.svg            # rendered, embedded in findings.html
├── codex/                     # Codex heavy-worker outputs, unless --no-codex
│   ├── hunters/               # Phase 5 hunter drafts
│   ├── evidence/              # Phase 7 evidence packs
│   ├── second-opinion/        # Phase 7.7 fresh adversarial check
│   └── drafts/                # Phase 8 report drafts
├── requirements/              # Phase 7.8 — only with --requirements flag
│   ├── claims.json
│   ├── predicates.json
│   ├── scenarios.json
│   ├── verdicts-r1/{REQ-N}.md
│   ├── verdicts-r2/{REQ-N}.md # only if repair round runs
│   └── final-verdicts.md
├── findings.md                # Phase 8 — final report (per-finding detail with fp-check tables)
├── findings.html              # Phase 8 — HTML report (default; markdown-only with --no-html)
└── tooling.md                 # Phase 8 — tool versions + commands run (reproducibility)
```

## Phase 0 — Odoo Module Inventory + Manifest Map

### Goals

- Enumerate every addon directory.
- Extract each `__manifest__.py` (name, version, depends, data, demo, license, external_dependencies, installable, application, auto_install).
- Build the depends-graph so risk weighting accounts for transitive coupling.
- Identify which modules are custom vs OCA vs Odoo S.A. enterprise vs community core.

### Steps

1. **Find manifests**
   ```bash
   find . -name '__manifest__.py' -not -path '*/node_modules/*'
   ```
2. **Parse each manifest** with a Python helper (or a small script under `inventory/parse_manifests.py`) into JSON:
   ```json
   {
     "module": "acme_tap",
     "path": "acme/acme_tap",
     "version": "17.0.1.2.3",
     "depends": ["base", "project", "sale_management"],
     "data": ["security/ir.model.access.csv", "views/project_views.xml"],
     "external_dependencies": { "python": ["requests"] },
     "license": "LGPL-3",
     "installable": true,
     "application": false,
     "auto_install": false
   }
   ```
3. **Build depends graph** — `inventory/depends.dot` + ASCII summary in `00-modules.md`.
4. **Tag each module** as: `core` (Odoo S.A.), `enterprise`, `oca-<repo>`, `custom`, `vendored-third-party`.
5. **Read every `data:` entry** — XML, CSV, JS, SCSS — record paths in `inventory/data-files.json` so Phase 1 attack surface and Phase 5 hunters can grep into them.

### Phase 0 Output (`00-modules.md`)

```
## Module Inventory

| Module                | Path                            | Origin   | LOC    | Risk |
|-----------------------|---------------------------------|----------|--------|------|
| acme            | acme/acme           | custom   | 12,400 | 5    |
| acme_tap        | acme/acme_tap       | custom   | 4,800  | 5    |
| account_invoice_oca   | oca/account-invoicing/...       | oca      | 2,100  | 3    |
| ...                   | ...                             | ...      | ...    | ...  |
```

## Phase 1 — Odoo Attack Surface Map

### Goals

- Know what reaches the public, the portal, and the internal user.
- Map controllers, models touched, ACL CSVs, ir.rule records, server actions, cron, mail templates.
- Plan hunter assignments so no hunter wastes time on dead code.

### Steps

1. **Stack identification** — Odoo version (8/13/14/15/16/17/18), edition (community/enterprise), Python version, PostgreSQL version, Werkzeug version. Read from `__manifest__.py` (max version), `requirements.txt`, and (if available) running `odoo-bin --version`.
2. **HTTP entry points**:
   ```bash
   grep -rn '@http\.route' --include='*.py' . | tee inventory/routes.txt
   ```
   Tag each route: `auth=public|none|user`, `csrf=True|False`, `type=http|json`, `methods=...`, `website=True|False`.
3. **RPC entry points** — `xmlrpc/2/db`, `xmlrpc/2/object`, `xmlrpc/2/common`, `jsonrpc` are exposed by Odoo core; map which models are reachable via `execute_kw` based on ACL/record-rules.
4. **Models touched by public/portal routes** — backward trace from `auth='public'` and `/my/*` controllers to `env['model.name']` references.
5. **ACL inventory**:
   ```bash
   find . -name 'ir.model.access.csv' | xargs cat > inventory/acl-all.csv
   grep -rn '<record model="ir\.rule"' --include='*.xml' . | tee inventory/ir-rules.txt
   grep -rn '<record model="res\.groups"' --include='*.xml' . | tee inventory/groups.txt
   ```
6. **Server actions / cron / mail templates**:
   ```bash
   grep -rn '<record model="ir\.actions\.server"' --include='*.xml' .
   grep -rn '<record model="ir\.cron"' --include='*.xml' .
   grep -rn '<record model="mail\.template"' --include='*.xml' .
   ```
7. **Risk-rank each module on 1-5 scale**:
   - **5** — has `@http.route(auth='public')` or `auth='none'`; OR overrides `res.users`/`ir.config_parameter`; OR touches mail templates or attachments; OR uses `safe_eval`.
   - **4** — has portal `/my/*` routes; touches finance/HR/sale state machines.
   - **3** — internal-only models with company-scoped data; record rules of note.
   - **2** — utility/infra (reports, computed-only models, language packs).
   - **1** — test fixtures, migration scripts, demo data.
8. **Hunter assignment plan** — which Odoo specialist (1–9) owns which modules. Keep it explicit so Phase 5 doesn't double-dip.

### Phase 1 Output (`01-attack-surface.md`)

```
## Attack Surface Map

### Stack
- Odoo version: 17.0 (community + custom + OCA account-invoicing)
- Python: 3.10
- PostgreSQL: 14
- Werkzeug: 2.3.7

### Public Surface (auth='public' / 'none')
| Module          | Route                        | Type | CSRF | Notes                       |
|-----------------|------------------------------|------|------|-----------------------------|
| website_sale    | /shop/cart/update            | http | F    | csrf disabled, mass-assign? |
| acme_tap  | /tap/webhook/<token>         | http | F    | webhook — verify HMAC       |
| ...             | ...                          | ...  | ...  | ...                         |

### Portal Surface (/my/*, /portal/*)
| Module        | Route             | Models read                  | Auth check          |
|---------------|-------------------|------------------------------|---------------------|
| portal        | /my/orders        | sale.order                   | _document_check_access |
| ...           | ...               | ...                          | ...                 |

### Module Risk
| Module          | LOC   | Risk | Public routes | Touches ACL? | sudo() count |
|-----------------|-------|------|---------------|--------------|--------------|
| acme_tap  | 4,800 | 5    | 3             | yes          | 12           |
| ...             | ...   | ...  | ...           | ...          | ...          |

### Hunter Assignments
- Access Control (#1): acme, acme_tap, oca/account-invoicing
- Controller / Route (#2): acme_tap, website_sale, portal_extra
- ORM / SQL / Domain (#3): acme, acme_hubspot
- QWeb / XSS (#4): acme_tap (mail templates), website_blog_extra
- Business Logic (#5): acme_tap, acme_subscriptions
- Secrets / Config (#6): acme, deploy/ (odoo.conf), data files
- External Integration (#7): acme_hubspot, acme_stripe, acme_fedex
- Data Exposure (#8): portal_extra, acme_tap (chatter)
- Dependency (#9): root requirements.txt, oca submodules
- Chaining (#10): all of above
```

## Phase 1.5 — Local Qwen / Ollama Advisory Check

Runs by default in the one-command Claude Code workflow. Skip only with `--no-local-qwen`. This is a local-only advisory pass, intended for cheap/private first-pass review. It never replaces Claude hunters or Phase 7 validation.

Default model: `qwen3:0.6b`. Override with `--local-model <ollama-model>`.

### Preconditions

```bash
ollama list
ollama run qwen3:0.6b "Return OK"
```

If Ollama or the requested model is unavailable, record the failed lane in `tooling.md`. In strict one-command mode, stop and tell the user which provider is missing; with `--allow-missing-lanes`, skip Phase 1.5 and continue.

### Pass A — Module Notes

Build a compact packet from Phase 0/1:

- module manifest summary
- risk rank
- public/portal routes
- ACL and `ir.rule` files
- counts of `sudo()`, `with_user()`, `cr.execute`, `t-raw`, `Markup`, `ir.config_parameter`, `ir.attachment`, `mail.message`

Run:

```bash
ollama run <local-model> < local-qwen/module-packet.txt > local-qwen/module-notes.md
```

Prompt constraints:

- Summarize risk by module.
- List suspicious files and exact symbols to inspect.
- Do not produce final findings.
- Mark every claim as `HINT`.

### Pass B — Scanner Triage

After Phases 2-4.5, pass scanner summaries and high-signal snippets to Qwen:

```bash
ollama run <local-model> < local-qwen/scanner-packet.txt > local-qwen/scanner-triage.md
```

Output buckets:

- `HUNTER_LEAD` — feed to Phase 5 hunters.
- `LIKELY_NOISE` — still verify before dropping.
- `NEEDS_CLAUDE_REVIEW` — ambiguous or high-impact paths.

### Pass C — Reject Candidates

Ask Qwen for obvious false-positive candidates only:

```bash
ollama run <local-model> < local-qwen/reject-packet.txt > local-qwen/reject-candidates.md
```

Phase 7 may use this to prioritize review order, but Qwen cannot reject a finding by itself. Rejection still requires the 6-gate fp-check.

### Output

```
local-qwen/
├── module-packet.txt
├── module-notes.md
├── scanner-packet.txt
├── scanner-triage.md
├── reject-packet.txt
└── reject-candidates.md
```

## Phase 2 — Semgrep Python/Odoo Rules

Run after Phase 1, before downstream scans. Scans are **hints not truth** — feed output to hunters as starting points; every claim is verified in Phase 7.

Community rulesets: `p/python`, `p/owasp-top-ten`, `p/trailofbits`, `p/0xdea`.
Custom rules: `.semgrep/odoo.yml` covering `auth='public'+sudo()`, `csrf=False` without HMAC, `cr.execute(f"...")`, `t-raw=` on user data, `request.params` → `write/create`, `ir.config_parameter.set_param` from controllers, `with_user(env.ref('base.user_admin'))`, `search([])` after `sudo()`, `unlink()` from public route, `Markup(` on user input, etc.

Output: `scans/semgrep/{ruleset}.json` and `scans/semgrep/odoo-custom.json`.

Full commands + custom rule examples: `automated-scans.md`.

## Phase 2.5 — Bandit Sweep

```bash
bandit -r <repo> -f sarif -o scans/bandit/results.sarif -lll --exclude tests,migrations
```

Bandit catches generic Python AppSec issues Semgrep misses (e.g., `assert` in production code, `tempfile.mktemp`, weak hash usage, hardcoded SQL passwords).

## Phase 2.6 — Ruff + pylint-odoo + OCA pre-commit

```bash
# Ruff with security rule selection
ruff check --select=S,B,PIE,BLE,ARG,RET --output-format=json <repo> > scans/ruff/results.json

# pylint-odoo with odoolint plugin
pylint --load-plugins=pylint_odoo --enable=odoolint --output-format=json <repo> \
  > scans/pylint-odoo/results.json

# OCA pre-commit
pre-commit run --all-files --config <repo>/.pre-commit-config.yaml \
  > scans/oca-precommit/output.txt
```

`pylint-odoo` is the bridge — it knows about `@api.model`, `_name`, `_inherit`, `Translation`, `<record>` XML rules. Catches Odoo-idiomatic issues no generic linter sees.

## Phase 3 — CodeQL Python Dataflow

```bash
codeql database create codeql-dbs/python-db --language=python --build-mode=none --source-root=<repo>
codeql database analyze codeql-dbs/python-db \
  python-security-and-quality.qls python-security-experimental.qls \
  --format=sarif-latest --output=scans/codeql/results.sarif
```

`--build-mode=none` always works for Odoo (interpreted Python, no compilation step).

Optional: custom QL extensions for Odoo (`models/ir_http_route.qll`, `models/odoo_orm.qll`) — out of scope for default run; document path in `automated-scans.md` if available.

## Phase 3.5 — Joern Graph Review (Optional)

Triggered by `--joern`. Runs after CodeQL, before Pysa. Joern's Code Property Graph (CPG) catches multi-hop / non-obvious flows that CodeQL's standard suites miss — especially `getattr`-dispatched calls, method-resolution paths through Odoo's metaclass ORM, and `eval`/`exec`/`safe_eval` reachability across files.

### Steps

```bash
# Build CPG (pythonsrc frontend = pysrc2cpg under the hood)
joern-parse <repo> --language pythonsrc --output scans/joern/cpg.bin

# Run query batch
joern --script - <<'EOF' > scans/joern/results.txt
importCpg("scans/joern/cpg.bin")

// Sinks: cr.execute first arg non-literal
cpg.call.name("execute").where(_.argument(1).isLiteral.not).l

// Sinks: eval / exec / compile / safe_eval
cpg.call.name("(eval|exec|compile|safe_eval)").l

// sudo() propagation: any call after .sudo()
cpg.call.name("sudo").l

// Controller → model paths: routes calling env[...]
cpg.method.where(_.annotation.name("route")).callee.name(".*env.*").l

// Deserialization: pickle.loads, yaml.load (unsafe), marshal.loads
cpg.call.name("(loads|load)").where(_.argument.codeExact("yaml.load|pickle.loads|marshal.loads")).l

// SSRF: requests.* with non-literal URL
cpg.call.name("(get|post|put|delete|patch|head|request)").where(_.argument(1).isLiteral.not).l

// Path traversal: open() / Path() with non-literal first arg
cpg.call.name("(open|Path)").where(_.argument(1).isLiteral.not).l
EOF
```

### Validate Joern hits before reporting

Joern is path-rich but noisy. Treat hits as **leads** for Phase 5 hunters, not findings. odoo-codereview Phase 7 fp-check still applies — read the bytes.

### Skip when

- Repo SMALL (<20k LOC) — CodeQL already covers it.
- `--quick` flag — too slow.
- Joern setup fails on first attempt — log skip in `tooling.md`.

Full query bank: `automated-scans.md` (Joern section).

## Phase 4 — Pysa Optional Taint Analysis

```bash
pyre analyze --no-verify --save-results-to scans/pysa/
```

Pysa requires `pyre check` to pass first; Odoo's metaclass-heavy ORM often confuses Pyre. Mark optional. Skip if pyre setup fails after one attempt.

When it works, Pysa catches taint flows Semgrep misses (multi-hop through helper functions).

## Phase 4.5 — Dependency Scan

```bash
pip-audit --format=json --output=scans/deps/pip-audit.json
osv-scanner --format=json --output=scans/deps/osv.json --recursive <repo>
```

Cross-reference with Phase 0 manifest external_dependencies. Filter to deps with reachable code paths via Phase 1 attack surface.

## Phase 5 — Codex Odoo Specialist Hunters

### Dispatch Rules

- Claude prepares compact packets; Codex performs the heavy hunter reading by default.
- Run independent `codex exec` tasks for hunters #1-#9. Parallelize outside Claude when practical.
- One TaskCreate per hunter — user sees progress.
- Each hunter receives:
  - Phase 0 module map
  - Phase 1 attack surface map
  - Hunter prompt template (`agent-prompts.md`)
  - Phase 1.5 Qwen hints
  - Scan feed paths (Phases 2–4.5)
  - Hunter scope (specific module list)
- Codex outputs are drafts/leads. Claude spot-checks claims before discourse and remains final arbiter.

### The 10 Hunters

| #   | Hunter               | Owns                                                         |
| --- | -------------------- | ------------------------------------------------------------ |
| 1   | Access Control       | ACL CSV, ir.rule, groups, sudo/with_user/with_context        |
| 2   | Controller / Route   | @http.route, request.params, CSRF, IDOR                      |
| 3   | ORM / SQL / Domain   | cr.execute, mass-assignment, domain injection                |
| 4   | QWeb / XSS           | t-raw, Markup, Html fields, mail body, OWL innerHTML         |
| 5   | Business Logic       | state machines, races, workflow bypass, server actions, cron |
| 6   | Secrets / Config     | hardcoded secrets, ir.config_parameter, odoo.conf, debug PIN |
| 7   | External Integration | requests/urllib/SSRF, webhooks, mail headers, LDAP, OAuth    |
| 8   | Data Exposure        | portal /my, attachments, chatter, reports, xmlrpc            |
| 9   | Dependency           | requirements.txt, OCA pins, base image, JS deps              |
| 10  | Chaining             | cross-hunter correlation                                     |

Hunter #10 fires after #1–#9 return.

### Hunter Output Contract

Either:

```
NO BUGS FOUND IN <scope>
```

Or one or more findings in the standard Odoo format (see `agent-prompts.md` Common Header — includes `Odoo surface:` field and standard finding template).

If a finding cannot meet that format, drop it. No prose-only "concerns".

### Hunter Anti-Patterns to Reject

- "Missing input validation" without naming the dangerous sink.
- "Could be exploited if..." — speculative.
- "Best practice violation" — style, not security.
- "Defense in depth" — find the actual defect.
- Claiming RCE on a code path that requires admin already (admin can already do RCE).
- Reporting `sudo()` without showing the sink reachable from non-admin.

## Phase 5.5 — Discourse / Cross-Hunter FP Reduction

After Phase 5 hunters return, ask Codex for a discourse draft before chaining. Hunters AGREE / CHALLENGE / CONNECT / SURFACE on each other's findings. Claude resolves CHALLENGE items and decides what enters Phase 6.

Skip only if `--quick` or repo SMALL (<20k LOC). Default ON for everything else.

Full procedure: `discourse.md`. Outputs `<OUT>/agents/discourse-summary.md` with confidence adjustments handed to Phase 6.

## Phase 6 — Cross-Agent Correlation (Chaining)

After Phase 5.5 discourse, ask Codex for the chaining draft with all hunter outputs **and** the discourse-summary CONNECT entries. Claude finalizes chained findings and severity.

### Chaining Hunter Job

Read every finding (including LOW/INFO that hunters logged). Look for combinations that uplift severity in the Odoo trust model:

- **`auth='public'` + `sudo()` + sensitive model** = unauthenticated data dump (CRITICAL)
- **Open redirect + auth_signup invite** = OAuth/signup token theft
- **SSRF from public route + cloud metadata reachable** = creds → admin
- **Mass-assignment on `res.users` + portal route** = portal → internal user
- **Mass-assignment on `res.users.group_ids` + auth='user'** = user → admin
- **QWeb `t-raw` on `mail.message` + `message_post` from portal** = stored XSS in admin's chatter
- **`ir.attachment` `public=True` + user-controlled mimetype + `/web/content`** = stored XSS via download
- **SQL injection in `cr.execute` + `database.secret` leak in logs** = session forgery + DB write
- **`safe_eval` sandbox bypass + `ir.cron` `user_root`** = persistent RCE
- **`ir.actions.server` `state='code'` + `base.group_user` + permissive `ir.rule`** = code-execution gadget
- **CSRF + state-changing action server** = drive-by RCE for admin
- **Webhook missing signature + idempotency missing on payment** = arbitrary balance write
- **`list_db=True` + weak `admin_passwd` + empty `dbfilter`** = cross-DB takeover

Output: new chained findings in the standard Odoo finding format. Severity reflects the chained impact, not the components.

## Phase 7 — Validation (6-Gate fp-check + Variant Analysis)

For every finding (hunter, chained, or surfaced in discourse), Codex first prepares an evidence pack. Claude then runs the structured 6-gate fp-check and, on ACCEPT, asks Codex to fan out variants.

### 6-Gate fp-check (per finding)

Codex evidence packs should include source context, reachability trace, attacker-control notes, assumptions, and a PoC sketch. Claude must still read the cited source and make the final gate decision.

Full rubric: `fp-check.md`. Summary:

1. **Source matches claim** — read file:line + 30-50 lines context.
2. **Reachable entry point** — trace backwards to a public/portal/RPC route, cron, webhook, or mail callback.
3. **Attacker controls tainted parameter** — confirm source-to-sink flow.
4. **Realistic preconditions** — auth state (public/portal/internal), group, company, race window, config flag.
5. **Pseudocode PoC** — concrete request (curl, XML-RPC, JSON-RPC, browser action).
6. **Impact matches severity** — CRITICAL=pre-auth RCE/data-dump, HIGH=portal→internal escalation/post-auth RCE/cross-company, MEDIUM=internal user → broader read.

ACCEPT only if all 6 PASS. Any FAIL → DOWNGRADE or REJECT (`triage.md`). Any can't-tell → NEEDS-MANUAL.

Each finding gets a 6-row gate table in the report.

### Variant Analysis (per ACCEPT)

After ACCEPT, ask Codex to draft variant search per `variant-analysis.md`, then Claude verifies grouped variants:

1. Extract bug shape (decorator + tainted-source predicate + missing safeguard).
2. Build search predicates (grep + Semgrep custom rule when shape is complex).
3. Search the **whole repo**, not just the originating module.
4. fp-check each hit through all 6 gates.
5. Group variants under the parent finding.

Save variant search to `<OUT>/variants/finding-N.md` with exact commands run.

### Triage Decision

- **ACCEPT** — All 6 gates PASS. Real. Exploitable. Ship.
- **DOWNGRADE** — 1-5 PASS, gate 6 fails (severity claim too high). Keep finding, lower severity.
- **REJECT** — Any of gates 1-3 FAIL: source doesn't match, sink unreachable, attacker has no control.
- **NEEDS MANUAL TESTING** — Plausible from source but a gate requires runtime evidence (race window, parser version, actual request shape).

### Triage Anti-Patterns

- ACCEPTing without filling the gate table. Each PASS is a claim with evidence.
- Filling gate table with "PASS" without doing the work.
- REJECTing because "it's documented as the dev's responsibility". Footguns are findings — see `sharp-edges.md`.
- DOWNGRADing to make the report shorter. Severity reflects reality.
- Skipping variant analysis on ACCEPT. Variants ship in next quarter's audit and look like a miss.

## Phase 7.5 — Runtime Validation (Optional: odoo-bin + ZAP)

Triggered by `--runtime` (and/or `--zap-target <url>`). Boots a disposable Odoo and/or hits a deployed QA target. Validates ACCEPT findings with real HTTP / `odoo-bin shell` / ZAP. Runs only on ACCEPT findings whose Gate 5 (PoC) demands runtime evidence — race windows, concrete response shapes, attachment-serving behaviour, IDOR confirmation.

Never run against production. QA only.

### Sub-pass A — odoo-bin (disposable instance)

- Boot disposable Odoo (`odoo-bin -c <conf> --workers=0` against scratch DB).
- Replay PoC via `curl` / `httpx` for HTTP, `odoo-bin shell` for ORM-level state inspection, `odoo-bin --test-enable --test-tags <module>` for unit-style replays.
- Capture request, response, and ORM state delta in `runtime/reproductions/finding-N.md`.

### Sub-pass B — ZAP (deployed QA target, with `--zap-target <url>`)

```bash
# Passive baseline scan (no auth — won't trigger SSO; safe first pass)
# Note: macOS Docker requires --user 0 due to mount permission quirk
mkdir -p <OUT>/runtime/zap && chmod 777 <OUT>/runtime/zap
docker run --rm --user 0 -v <OUT>/runtime/zap:/zap/wrk/:rw zaproxy/zap-stable \
  zap-baseline.py -t <ZAP_TARGET> \
  -r zap-baseline.html -J zap-baseline.json
```

Authenticated active scan: feed Odoo session cookie (`session_id`) via header replacer or import a `.har` of a logged-in flow. Use `zap-full-scan.py` only on QA you own — never against production or shared instances.

### Output

```
runtime/
├── reproductions/finding-N.md   # PoC request + response + state delta
├── odoo-shell-output/finding-N.txt  # ORM-level validation
└── zap/
    ├── zap-baseline.html
    ├── zap-baseline.json
    └── active-scan.json   # only when authenticated active scan run
```

### Triage uplift

- NEEDS-MANUAL → ACCEPT only with concrete evidence (HTTP response or ORM-state delta).
- ACCEPT confidence +2 when runtime confirms.
- ZAP-only finding without source-code corroboration → REJECT (false-positive risk too high).

## Phase 7.6 — Attack Graph DOT/SVG (Chained Findings Only)

Runs after Phase 6 chaining + Phase 7 fp-check, before output assembly. For every chained ACCEPT finding (and any non-chained CRITICAL with multi-step path), emit a Graphviz attack graph showing source → hops → sink with trust-boundary crossings annotated.

### Steps

1. Build DOT from chained finding's hop list:
   ```dot
   digraph chain_F3 {
     rankdir=LR;
     node [shape=box, style=rounded];
     "anonymous" -> "POST /shop/checkout/<token>" [label="auth='public'"];
     "POST /shop/checkout/<token>" -> "sale.order.write({state:'done'})" [label="sudo()"];
     "sale.order.write({state:'done'})" -> "account.payment.confirm()" [label="state machine bypass"];
     subgraph cluster_boundary {
       label = "TRUST BOUNDARY: public -> internal";
       style = dashed;
       "POST /shop/checkout/<token>";
     }
   }
   ```
2. Render SVG: `dot -Tsvg attack-graphs/chain-N.dot -o attack-graphs/chain-N.svg`.
3. Inline-embed SVG into `findings.html` per chained finding.

### Trust-boundary annotations (Odoo)

- `anonymous → authenticated` — `auth='public'` route entry
- `user → sudo` — any `sudo()` call along the path
- `portal → internal` — `/my/*` route writing internal model
- `tenant A → tenant B` — `company_id` rule gap
- `internal → root` — `with_user(env.ref('base.user_root'))` or `SUPERUSER_ID` write

### Skip when

- No chained findings AND no multi-step CRITICAL.
- `--quick` flag.

## Phase 7.7 — Fresh Codex Adversarial Check

Runs after Phase 7 fp-check + Phase 7.6 graphs, before output assembly. Skip only with `--no-codex`. Use a fresh Codex prompt/session that sees only the final finding card and source snippets, not the prior Codex hunter/evidence drafts. Skipped on MEDIUM/LOW because it is not cost-effective.

### Codex packet (per finding)

- Full finding card from Phase 7 (file:line, source, sink, attack path, fp-check gate table)
- Source and sink code with 30-50 lines surrounding context
- Tool evidence summary (Semgrep/CodeQL/Joern hits)
- For chains: DOT graph + component findings

### Codex must produce three independent judgments

1. **PoC Writeability** — Can a working exploit be written from this finding alone? Provide minimal Python/curl/HTTP request. If not writeable, name the missing precondition.
2. **Chain/Assumption Challenge** — List every assumption the finding (or chain) depends on. For each, state: holds in current code / configurable / unverified.
3. **Independent Verdict** — ACCEPT / REJECT / DOWNGRADE / NEEDS-MANUAL with one-line reason.

### Reconciliation table

| Codex                   | odoo-codereview | Result                                        |
| ----------------------- | --------------- | --------------------------------------------- |
| ACCEPT                  | ACCEPT          | keep ACCEPT, +1 confidence                    |
| REJECT                  | ACCEPT          | force NEEDS-MANUAL, log disagreement          |
| DOWNGRADE               | ACCEPT          | re-evaluate severity if limiting factor sound |
| writes PoC              | no PoC          | attach Codex PoC, raise confidence            |
| no PoC and no other PoC | n/a             | downgrade to NEEDS-MANUAL                     |
| ACCEPT                  | DOWNGRADE       | keep DOWNGRADE, note Codex stronger view      |

Record both verdicts and reconciliation reason in finding card under "Second-Opinion" section. Surface disagreements prominently in `findings.html` Executive Summary.

### Output

```
codex/second-opinion/
├── verdicts/F-N.md       # per-finding fresh Codex card
└── reconciliation.md     # summary table of all disagreements
```

## Phase 7.8 — Requirements-Aware Verification (Optional)

Triggered only by `--requirements <file>`. Runs after Phase 7.7 Codex (or Phase 7 if no CRITICAL/HIGH ACCEPT findings exist or `--no-codex` is set), before Phase 8 final report assembly.

Cross-checks customer requirements / spec / threat-model against the codebase to catch **missed-requirement bugs** — gaps where a stated security claim has no code enforcement.

Pipeline: extract claims → compile predicates → generate scenarios → verify-with-judge → targeted-repair (≤2 rounds) → R-N findings.

Adapted from IronCurtain's constitution → compile → verify-with-judge → repair pipeline.

Full procedure: `requirements-mode.md`. Outputs to `<OUT>/requirements/`. R-findings merge into main `findings.md` with `Source: requirements <REQ-ID>` field.

## Phase 8 — Output Assembly

Ask Codex to draft `findings.md`, `findings.html`, and `tooling.md` from verified Phase 7 records. Claude performs final edit and removes unsupported claims. HTML is default; `--no-html` skips it. JSON sidecar (`findings.json`) emitted on `--json`.

### `findings.md` Structure

```
# Audit Report — <project>

## Summary
| Severity | Count | Examples            |
|----------|-------|---------------------|
| CRITICAL | 2     | F-3 (RCE), F-7 (ATO)|
| HIGH     | 4     | ...                 |
| MEDIUM   | 6     | ...                 |
| LOW      | 1     | ...                 |

## Stats
| Metric              | Value     |
|---------------------|-----------|
| Modules scanned     | 47        |
| LOC                 | 412,000   |
| Wall-clock          | 9m 12s    |
| Parallel hunters    | 10        |
| Findings (raw)      | 23        |
| Findings (accepted) | 13        |
| ACCEPT              | 8         |
| DOWNGRADE           | 5         |
| REJECT              | 9         |
| NEEDS MANUAL        | 1         |

## Findings

### F-1 — <Title>
<full Odoo finding format with 6-gate table>

### F-2 — <Title>
...
```

### `findings.html` Structure

Single self-contained HTML at `<OUT>/findings.html`. No external CDN dependencies. Inline CSS in `<style>` block. Embed attack-graph SVGs inline (preferred) or reference relative `attack-graphs/chain-N.svg`. Renders cleanly in browser and when saved to PDF.

Severity color coding: Critical red, High orange, Medium yellow, Low gray. Confidence shown as numeric score plus tool-evidence badges.

HTML sections, in order:

1. **Header** — repo name, commit SHA, audit date, scope (whole repo or module list), Odoo version, Python version, Phase 0 inventory summary.
2. **Executive Summary** — counts (Critical/High/Medium/Low/Rejected/Needs-Manual), top 5 highest-impact findings (one-line each, anchor links), notable chained attack paths, Codex disagreements (if Phase 7.7 ran).
3. **Tool Coverage Matrix** — table: rows = hunters #1-#10, columns = Semgrep / Bandit / Ruff / pylint-odoo / CodeQL / Joern / Pysa / pip-audit / osv-scanner / ZAP / Codex. Cells show hit counts and confirmation rate.
4. **Findings** (sorted by severity desc, then confidence desc) — each ACCEPT or NEEDS-MANUAL renders a card:
   - Title, Severity, Confidence (score + badges), Triage status
   - Affected Files (clickable `file:line` where possible)
   - Attack Technique, Source, Sink, **Odoo surface** field
   - Description, Attack Path
   - Proof of Concept (in `<pre><code>` block)
   - Reproduction Steps, Impact, Recommended Fix, Validation Notes
   - 6-row fp-check gate table
   - Variants sub-table
   - Tool Evidence: per-tool verdict + path
   - Confidence Score, Reachability
   - Attack Graph (inline SVG when chained — Phase 7.6)
   - Codex Second Opinion (Phase 7.7 — CRITICAL/HIGH only): verdict, PoC writeability, assumption challenge, reconciliation note
   - Second-Opinion Disagreement (when Codex and odoo-codereview disagree, surface clearly)
5. **Chained Attack Paths** — each chain rendered with inline SVG from Phase 7.6, lists composing findings with anchor links.
6. **Dependency CVE Reachability Results** — table: CVE, package, vulnerable symbol, reachable yes/no, evidence path.
7. **Negative-Space Audit** — insecure-defaults missed by hunters (Odoo section).
8. **Discourse Summary** — consensus / challenged / connected / surfaced (Phase 5.5 record).
9. **Engagement Stats** — modules, LOC, wall-clock, tokens, hunter-by-hunter table.
10. **Appendix** — rejected findings (one-line reason), downgraded findings (reason), phase logs, tool versions (mirrors `tooling.md`).

### `tooling.md` Structure

```
# Tooling — Reproducibility Appendix

## Versions
- Odoo: 17.0
- Python: 3.10.12
- PostgreSQL: 14.10
- Semgrep: 1.45.0 + p/python p/owasp-top-ten p/trailofbits p/0xdea + .semgrep/odoo.yml@<sha>
- Bandit: 1.7.5
- ruff: 0.4.4
- pylint-odoo: 9.0.4
- OCA pre-commit hooks: <revision>
- CodeQL: 2.16.0 + python-security-and-quality.qls python-security-experimental.qls
- Joern: 4.0.x (skipped — `--joern` not set)
- Pysa: 0.0.101 (skipped — pyre check failed)
- pip-audit: 2.7.3
- osv-scanner: 1.7.0
- ZAP: zaproxy/zap-stable docker image (only with `--zap-target`)
- Model lanes: Claude primary, Ollama/Qwen local advisory, Codex/OpenAI adversarial/artifacts
- Graphviz: 9.0.0 (only when chained findings → Phase 7.6)

## Commands Run
<exact bash one-liners with arguments>

## Output Inventory
<paths under <OUT>/scans/, <OUT>/agents/, <OUT>/variants/, <OUT>/requirements/>
```

## Negative-Space Audit (Insecure Defaults)

Run as part of Phase 7 — separate pass from hunter findings, since dataflow tools miss "absent code" bugs.

For each Odoo subsystem identified in Phase 0/1:

1. List its known insecure defaults (see `insecure-defaults.md` Odoo section).
2. Search the repo for the override that would harden it.
3. Absent override = candidate finding → fp-check it.

Distinct from sharp-edges (which is API-called-the-unsafe-way, not config-flag-not-flipped).

## Engagement Stats

End every engagement with the Stats table inside `findings.md` (see Phase 8 above). Stats prove AI speedup. Required for client/AppSec leadership delivery.

## Templates

- Phase 0/1 module + surface map: this file
- Scans (Phases 2–4.5): `automated-scans.md` (Joern queries in §Joern, ZAP in §Runtime)
- Hunter prompts (Phase 5): `agent-prompts.md`
- Discourse pattern (Phase 5.5, incl. judge tie-break): `discourse.md`
- 6-gate verification (Phase 7): `fp-check.md`
- Variant pattern fan-out (Phase 7): `variant-analysis.md`
- Runtime mode (Phase 7.5 — odoo-bin + ZAP): this file Phase 7.5
- Attack graphs (Phase 7.6): this file Phase 7.6
- Second opinion (Phase 7.7): this file Phase 7.7
- Requirements-aware mode (Phase 7.8): `requirements-mode.md`
- Insecure-defaults checklist: `insecure-defaults.md`
- Sharp-edges (footgun APIs): `sharp-edges.md`
- Output format + final report (`findings.md` + `findings.html`): `triage.md`
- Language patterns: `lang-odoo.md`, `lang-qweb.md`, `lang-python.md`, `lang-web.md`
