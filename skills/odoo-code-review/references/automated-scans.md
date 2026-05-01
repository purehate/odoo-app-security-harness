# Automated Scans — Phases 2, 2.5, 2.6, 3, 4, 4.5

This skill is **Odoo/Python first**. The scan stack reflects that. Generic Python AppSec tools sit at the front; Odoo-specific Semgrep rules carry most of the framework-misuse signal.

Scans run **after** the attack-surface map (Phase 1) and **before** the parallel Odoo hunters (Phase 5). Hunters consume scan output as additional context; they do **not** depend on it.

## Pipeline

| Phase | Tool                           | Purpose                                             | Required? |
| ----- | ------------------------------ | --------------------------------------------------- | --------- |
| 2     | Semgrep (Python + Odoo custom) | Pattern match — fastest signal, custom Odoo ROI top | Yes       |
| 2.5   | Bandit                         | Python AST security checks                          | Yes       |
| 2.6   | ruff + pylint-odoo + OCA hooks | Quality + Odoo framework correctness                | Yes       |
| 3     | CodeQL Python                  | Dataflow / taint analysis                           | Yes       |
| 4     | Pysa                           | Targeted taint with Odoo-specific models            | Optional  |
| 4.5   | pip-audit + osv-scanner        | Dependency CVEs (Python + JS assets)                | Yes       |

**Why this stack vs generic AppSec:** Odoo bugs are framework misuse — `auth='public'` + `sudo()`, weak record rules, `t-raw` on user input. Custom Semgrep rules + Bandit + pylint-odoo catch the bulk. CodeQL/Pysa are the heavy artillery for tainted-flow that crosses many call sites. Generic Python AppSec misses the ACL/QWeb/portal class of bugs.

## Output Layout

All scan artifacts go under `<OUT>/scans/`. Default `<OUT>` is `<repo>/.audit/` (gitignore it) or `/tmp/audit-<project>/`. The slash command accepts `--out <dir>` to override.

```
<OUT>/scans/
├── semgrep/
│   ├── results.sarif
│   └── results.json
├── bandit/
│   ├── results.sarif
│   └── results.json
├── ruff/results.json
├── pylint-odoo/results.txt
├── oca-precommit/results.txt
├── codeql/results.sarif
├── pysa/results.json          # optional
└── deps/
    ├── pip-audit.json
    └── osv-scanner.json
```

## Phase 2 — Semgrep

Two layers: pinned community rulesets + **custom Odoo rules** (the high-ROI half).

### Community rulesets

```bash
semgrep \
  --config p/python \
  --config p/owasp-top-ten \
  --config p/trailofbits \
  --config p/0xdea \
  --sarif --output <OUT>/scans/semgrep/community.sarif \
  --json  --output <OUT>/scans/semgrep/community.json \
  --metrics=off \
  <repo>
```

Why these four:

- `p/python` — language-specific idioms (eval/exec/yaml.load/pickle/subprocess shell=True).
- `p/owasp-top-ten` — broad coverage, baseline expectations.
- `p/trailofbits` — high-signal patterns curated by ToB, low FP rate.
- `p/0xdea` — community ruleset focused on real-world exploit patterns.

Skip `auto` config — pulls noisy rulesets and inflates FP rate.

### Custom Odoo rules (high ROI)

Write a `.semgrep/odoo.yml` with rules targeting:

- `@http.route(... auth='public' ...)` followed within the same function by `.sudo()` or `cr.execute(`.
- `@http.route(... csrf=False ...)` on `type='http'` POST handlers.
- `request.params` / `request.jsonrequest` flowing into `write(`, `create(`, `search(`, `search_read(`, or `domain` arg.
- `cr.execute(f"..." | "%s" % | + )` — string-built SQL.
- `safe_eval(` with non-empty globals dict and user-derived first arg.
- `.search([])` / `.search_read([]` after `.sudo()`.
- `Markup(` constructor on identifier sourced from request/model.
- `t-raw="record.X"` / `t-raw="X"` patterns in XML where X resolves to a stored field.
- `fields.Html(... sanitize=False ...)`.
- `<record model="ir.rule">` whose `domain_force` is `[(1,'=',1)]` or empty `groups`.
- `<record model="ir.actions.server"> <field name="state">code</field>` reachable by `base.group_user` / `base.group_portal`.
- `with_user(` / `with_context(` whose user/context originates from a request param.
- `ir.config_parameter.sudo().set_param(` inside a controller.

Example custom rule:

```yaml
rules:
  - id: odoo-public-route-with-sudo
    pattern-either:
      - patterns:
          - pattern: |
              @http.route(..., auth="public", ...)
              def $F(...):
                ...
                $X.sudo()
                ...
          - pattern: |
              @http.route(..., auth='public', ...)
              def $F(...):
                ...
                $X.sudo()
                ...
    message: |
      Public-auth route invokes .sudo() — verify the data leaving via this route
      is intentionally public. sudo() bypasses record rules and ir.model.access.csv.
    severity: WARNING
    languages: [python]
    metadata:
      cwe: "CWE-269"
      category: security
      odoo: true
```

Run combined:

```bash
semgrep \
  --config <repo>/.semgrep/odoo.yml \
  --config p/python \
  --config p/owasp-top-ten \
  --config p/trailofbits \
  --sarif --output <OUT>/scans/semgrep/results.sarif \
  --json  --output <OUT>/scans/semgrep/results.json \
  --metrics=off \
  <repo>
```

Maintain the custom rule pack alongside the skill, not per-repo. Recommended path: `~/.config/odoo-code-review/odoo-rules/` (referenced from the slash command).

## Phase 2.5 — Bandit

```bash
bandit -r <repo> \
  -f sarif -o <OUT>/scans/bandit/results.sarif \
  -lll \
  --exclude '*/tests/*,*/test_*'
```

Flags worth using:

- `-lll` — only HIGH severity by default. Drop to `-ll` if engagement scope allows MEDIUM.
- `--exclude` — exclude test fixtures (lots of `eval` / `subprocess` for setup that's not production).

Bandit catches what Semgrep `p/python` mostly catches but with a different rule engine and AST walker — small overlap, occasional non-overlap is real signal. Hunter prompts treat both as hints.

## Phase 2.6 — Ruff + pylint-odoo + OCA Pre-commit Hooks

Quality + framework-correctness signal. Most output is non-security; we mine for security-adjacent rules.

### ruff

```bash
ruff check <repo> --output-format=json > <OUT>/scans/ruff/results.json
```

Security-relevant ruff rules: `S` (bandit-derived), `B` (bugbear), `PIE` (idioms), `BLE` (blind except). Configure in `pyproject.toml` or `ruff.toml`:

```toml
[tool.ruff.lint]
select = ["S", "B", "PIE", "BLE", "ARG", "RET"]
```

### pylint-odoo

```bash
pip install pylint-odoo
pylint --load-plugins pylint_odoo \
  --disable=all \
  --enable=odoolint \
  <repo>/addons/* > <OUT>/scans/pylint-odoo/results.txt
```

Surface-relevant pylint-odoo checks:

- `manifest-required-author`, `manifest-required-key` — manifest hygiene.
- `attribute-deprecated` — deprecated APIs (often migrated unsafely).
- `external-request-timeout` — `requests.get(url)` with no timeout (SSRF amplification).
- `method-compute` / `method-inverse` / `method-search` — naming pattern that flags compute methods missing `_check_company`-style guards.
- `sql-injection` — direct concatenation in `cr.execute`.
- `translation-required`, `print-used` — quality, not security.

### OCA pre-commit hooks

OCA (Odoo Community Association) maintains a pre-commit suite for module hygiene. If repo has `.pre-commit-config.yaml`, run it:

```bash
pre-commit run --all-files \
  --config <repo>/.pre-commit-config.yaml \
  > <OUT>/scans/oca-precommit/results.txt 2>&1 || true
```

Hooks of interest:

- `oca-checks-odoo-module` — manifest format, version pin.
- `pyupgrade` — Python version drift (older syntax often paired with older deps).
- `mypy` — type drift (occasionally surfaces wrong-shape `domain` builds).

If repo has no OCA config, skip — don't impose the suite.

## Phase 3 — CodeQL Python Dataflow

Compiled languages need a real build for accurate dataflow. **Python is interpreted — `--build-mode=none` always works**, no Maven/Gradle dance.

### Database extraction

```bash
codeql database create <OUT>/codeql-dbs/<project>-db \
  --language=python \
  --source-root=<repo> \
  --build-mode=none
```

For the rare polyglot Odoo addon with C extensions or compiled JS bundles, extract a separate DB per language.

### Analysis

```bash
codeql database analyze <OUT>/codeql-dbs/<project>-db \
  codeql/python-queries:codeql-suites/python-security-and-quality.qls \
  codeql/python-queries:codeql-suites/python-security-experimental.qls \
  --format=sarif-latest \
  --output=<OUT>/scans/codeql/results.sarif \
  --download
```

Suites:

- `python-security-and-quality` — base coverage, low-noise.
- `python-security-experimental` — newer queries; higher FP but catches recent bug classes.

### Custom CodeQL queries (optional)

Standard CodeQL Python queries don't model Odoo sources/sinks (`request.params`, `cr.execute`, `safe_eval`, ORM domain args). For a serious engagement, extend with custom QL:

- Treat `odoo.http.request.params` and `request.jsonrequest` as `RemoteFlowSource`.
- Treat `Cursor.execute(arg)` on first positional arg as a SqlSink (when not parameterised).
- Treat `safe_eval(arg, ...)` as a CodeExecutionSink.

Maintain custom QL pack in `~/.config/odoo-code-review/codeql-odoo/` and reference via `--threads`/`--ram` for HUGE repos.

## Phase 4 — Pysa (Optional)

Pysa is Meta's taint analyzer for Python. Slower setup than CodeQL but lets you express custom sources/sinks declaratively.

```bash
pip install pyre-check
cd <repo>
pyre init      # one-time
pyre analyze \
  --no-verify \
  --save-results-to <OUT>/scans/pysa/ \
  > <OUT>/scans/pysa/results.json
```

Worth running when:

- Engagement has >2 days budget.
- Custom CodeQL QL would take longer to write than the equivalent Pysa model.
- Repo has heavy framework abstraction over `request` (multiple wrapper layers) — Pysa's model is good at threading taint through.

Skip otherwise — overlapping signal with CodeQL, longer warm-up time.

## Phase 4.5 — Dependency CVEs

Two scanners, different coverage:

```bash
# Python deps
pip-audit --format json -o <OUT>/scans/deps/pip-audit.json \
  -r <repo>/requirements.txt

# Polyglot (Python + JS assets bundled in Odoo modules)
osv-scanner scan source --recursive \
  --format json --output <OUT>/scans/deps/osv-scanner.json \
  <repo>
```

`pip-audit` reads the official PyPI advisory DB. `osv-scanner` reads OSV — covers JS, Go, Ruby, Maven, etc. — useful when an Odoo module ships frontend assets in `static/lib/`.

Output feeds the **#9 Dependency Hunter** as starting evidence — hunter still has to prove reachability through app code.

## Feeding scans into hunters (Phase 5)

In Phase 5 dispatch, every hunter prompt includes:

```
Pre-computed scan output is available. Use it as a hint, not as truth:

  Semgrep SARIF:        <OUT>/scans/semgrep/results.sarif
  Bandit SARIF:         <OUT>/scans/bandit/results.sarif
  ruff JSON:            <OUT>/scans/ruff/results.json
  pylint-odoo TXT:      <OUT>/scans/pylint-odoo/results.txt
  CodeQL SARIF:         <OUT>/scans/codeql/results.sarif
  Pysa JSON (optional): <OUT>/scans/pysa/results.json
  pip-audit JSON:       <OUT>/scans/deps/pip-audit.json
  osv-scanner JSON:     <OUT>/scans/deps/osv-scanner.json

Read findings relevant to your technique class. For every scan finding
you incorporate, you must:
  1. Verify the file:line still matches the live source.
  2. Trace the data flow yourself end-to-end.
  3. Cite the originating rule ID (CodeQL ql, Semgrep rule path, Bandit
     test ID, ruff code) in your finding's "Notes" field.

You may also report bugs the scanners missed. The scans are a floor,
not a ceiling.
```

## Anti-patterns

- Running auto Semgrep config and reporting hundreds of style/lint hits as findings.
- Reporting CodeQL hits without reading the source.
- Failing the audit because CodeQL extraction failed — Python is interpreted, `--build-mode=none` always works. If it doesn't, the source tree is broken.
- Letting `pip-audit` / `osv-scanner` output dominate the report — every CVE needs reachability before it counts.
- Treating ruff / pylint-odoo output as security findings wholesale — most is style, mine for the security-adjacent subset.
- Running Pysa **and** CodeQL on a 1-day engagement. Pick one. Pysa pays off on bigger repos with custom models.
