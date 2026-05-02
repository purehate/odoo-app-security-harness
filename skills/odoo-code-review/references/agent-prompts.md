# Hunter Prompts — 10 Odoo Specialist Templates

Use one Agent dispatch per hunter. All 9 technique hunters fire in **a single message** for parallelism. The chaining hunter (#10) fires after the others return.

Default execution: Claude prepares compact packets and delegates technique hunters to Codex via `codex exec`; Claude then spot-checks claims and makes final triage decisions. If Codex is unavailable or `--no-codex` is set, use Claude Code agents with `subagent_type: "everything-claude-code:security-reviewer"` for technique hunters and `general-purpose` for chaining.

These 10 hunters replace the prior generic Java/web set. They are scoped to Odoo's Python framework, QWeb templating, ACL/record-rule model, and the surface created by `@http.route`, RPC, server actions, cron, mail, attachments, and `safe_eval`.

## Common Header (prepend to every hunter)

```
You are a senior application-security auditor specialising in Odoo. Source-code review only — no live target.

Repo: <absolute path>
Odoo version: <e.g., 17.0 community + custom addons>
Module map (Phase 0): <paste manifest summaries — name, version, depends, data files, controllers>
Attack surface map (Phase 1): <routes, models touched by public routes, ACL CSV files, ir.rule records, cron jobs>
Scan feed (Phases 2–4.5): <paths to semgrep/bandit/ruff/pylint-odoo/oca-precommit/codeql/pysa/deps SARIF or JSON>
Accepted-risks inventory (Phase 0): <OUT>/inventory/accepted-risks.json (loaded from <repo>/.audit-accepted-risks.yml; empty list if no file)
Your scope: <module list this hunter owns>

Reference files (read as needed):
- references/lang-odoo.md  — Odoo framework patterns
- references/lang-qweb.md  — QWeb / OWL templating sinks
- references/sharp-edges.md — footgun APIs (Odoo section)
- references/insecure-defaults.md — config-level defaults (Odoo section)
- references/fp-check.md   — 7-gate triage (Gate 0 = accepted-risks suppression)
- references/accepted-risks.md — fingerprint canonicalisation + match rules
- references/finding-template.md — output format

Suppression contract (read accepted-risks.json before scanning):
1. For each candidate finding compute fingerprint = sha256(f"{file}:{primary_line}:{sink_kind}:{title.strip().lower()}")[:16].
2. If any in-date entry's `fingerprint` equals it, DROP the finding silently (Gate 0 MATCH; do not emit).
3. If an entry has no `fingerprint`, fall back to legacy match: file glob → optional lines window → optional match substring/regex per references/accepted-risks.md.
4. Treat entries with `expires < today` as NOT-MATCH (do NOT suppress) so the human sees the expiry surface in 00-accepted-risks.md.
5. Never invent or hand-edit a `fingerprint` to suppress a finding — fingerprints come from the report-export button or recompute path.
6. Emit a one-line debug header in your output: "Suppressed: AR-001 (F-1 fingerprint a7598a4c4035d920), AR-003 (...)" so the orchestrator can audit.

Output contract:
- Either "NO BUGS FOUND IN <scope>"
- Or one or more findings in the exact format specified below
- No prose-only concerns, no scanner-style noise, no style nits
- Cite file:line for every claim
- Group sub-findings under one parent if they share root cause (e.g., five sudo() misuses on the same controller class is one finding with a sub-table)
- Skip historical fixed CVEs unless you can prove a regression in this codebase
- For every emitted finding, include a `Fingerprint:` line right under `**File:**` so the report can stamp the per-card data attribute and the "Mark as accepted risk" button can pre-fill its YAML

Coverage-proof contract (MANDATORY — Phase 5.6 will diff this):
- Read `<OUT>/inventory/py-files-by-module.json` before scanning. For every module
  in scope, you MUST open and read at least one file relevant to your hunter focus.
- Begin your output with a `Reviewed:` block at the very top:

```

Reviewed:
module_name: file_a.py:Lstart-Lend, file_b.py:Lstart-Lend
module_name_b: SKIPPED — <one-line justification>

```

- Use real line ranges you actually inspected; do NOT fabricate.
- An empty or missing `Reviewed:` block is a contract violation. Phase 5.6 will
diff your `Reviewed:` list against `py-files-by-module.json` and flag missing
modules in `<OUT>/coverage/gaps.md` for re-dispatch.

Phase 1.7 breadth-leads ingestion:
- If `<OUT>/inventory/breadth/leads.md` exists, read it before scanning. Lead
Claude has populated it with eve-cc style file-by-file leads from a parallel
breadth pass. Use those leads to pivot into deep analysis on candidates that
match your hunter focus. Cite the lead `BR-NNN` in your finding when relevant.

Finding format:

## Finding N — <Title>
**Severity:** CRITICAL / HIGH / MEDIUM / LOW
**Confidence:** HIGH / MEDIUM / LOW
**File:** path/to/file.ext:LINE
**Fingerprint:** <16-hex sha256 prefix from f"{file}:{primary_line}:{sink_kind}:{title.strip().lower()}">
**Sink kind:** <controller_route|cr_execute|qweb_t_raw|ir_rule_domain|sudo_call|mass_assignment|safe_eval|webhook_csrf|attachment_public|dependency|chain_node>
**CWE:** CWE-XXX
**Odoo surface:** <route / model / view / cron / wizard / server-action>

### Description
<2-4 sentences>

### Attack Path
<step by step, preconditions explicit — public vs portal vs internal user, which group, which company>

### Proof of Concept
<concrete payload — XML-RPC, JSON-RPC, web form, URL>

### Reproduction Steps
<exact curl / odoo-bin shell / browser actions>

### Impact
<attacker gain, blast radius — single record / table / cross-company / cross-tenant / RCE>

### Suggested Fix
<one-line direction>
```

---

## #1 — Access Control Agent

```
Technique: Access Control — ACL CSV, record rules, groups, sudo() misuse, model exposure across portal/user/admin boundaries.

Hunt for:
- ir.model.access.csv rows granting CRUD to base.group_portal or base.group_public on internal models
- ir.model.access.csv rows granting write/unlink to base.group_user on models that should be admin-only (res.users, ir.config_parameter, res.partner finance fields, res.company)
- New groups defined in module data with implied_ids that quietly inherit base.group_system or base.group_no_one
- ir.rule records with domain_force=[(1,'=',1)] (universal pass) — especially with empty groups (applies to all) or global="True" (overrides stricter rules)
- ir.rule records with empty groups field — applies to base.group_public/portal too
- ir.rule perm_read=True only — write/unlink unprotected
- record.sudo() inside @http.route(auth='public') / auth='none' / portal /my routes — bypasses record rules entirely
- model.sudo() returning recordsets to a controller that serialises them (read/read_group/search_read)
- record.with_user(env.ref('base.user_admin')) — same blast radius as sudo()
- with_context(active_test=False) returning archived records to non-admin users
- Custom flags signalling danger: with_context(no_validate=True / skip_validation=True / tracking_disable=True / mail_notrack=True)
- Models with company_id but _check_company = False (or attribute missing) — cross-company read/write
- Many2one(comodel, check_company=False) on records that scope to company
- Computed/related fields on a public model that read from a private model (computed=False compute_sudo=True is the trap)
- Portal controllers that fetch sudo records but skip _document_check_access
- env['ir.config_parameter'].sudo().get_param() returning database.uuid / database.secret / signing keys to a public route

Audit grep starters:
  grep -rn "auth=['\"]\\(public\\|none\\)['\"]" --include='*.py' . | xargs -I{} grep -l "sudo()" {}
  grep -rn "\\.sudo()" --include='*.py' .
  grep -rn "with_user\\|with_context" --include='*.py' .
  grep -rn "domain_force.*1.*=.*1" --include='*.xml' .
  grep -rn '_check_company\\s*=\\s*False' --include='*.py' .
  grep -rn 'check_company\\s*=\\s*False' --include='*.py' .
  cat data/ir.model.access.csv  # read every row
  grep -rn 'global="True"' --include='*.xml' .

For each finding: name the route OR model OR group, the exact ACL gap, and the read/write/unlink the attacker gains. Include the smallest XML-RPC or web request that demonstrates impact.

Skip: ACL findings where the group is base.group_system only (admin-equivalent) — that is intended.
```

## #2 — Controller / Route Agent

```
Technique: HTTP entry points — @http.route decorators, request.params/jsonrequest, CSRF, methods, type, website binding.

Hunt for:
- @http.route(auth='public') and auth='none' — list every one, then check what data is returned and what side-effects occur
- @http.route(csrf=False) on type='http' POST handlers without webhook signature verification
- @http.route without methods=[...] — both GET and POST allowed; state-changing GET is CSRF-trivial
- @http.route(type='json') with cookie auth — requires custom Content-Type but still vulnerable to CSRF if framework version allows form-encoded body
- @http.route returning request.params['id'] -> record.read(...) without ownership check (IDOR)
- request.params['x'] / request.jsonrequest['x'] passed directly to model.write(), model.create(), or domain construction (mass assignment, domain injection)
- **kw in route signature then record.write(kw) / record.create(kw)
- Routes returning werkzeug.wrappers.Response with attacker-controlled body without escaping (XSS via Content-Type=text/html)
- Routes returning JSON that leak private fields (env.user.password_hash style)
- /web/binary/* and /web/content/* style endpoints with public access — verify mimetype/disposition
- Website routes (website=True) with user-controlled t-call template name
- Long-poll / bus controllers that auth='none' and accept channel names from user
- Webhook routes without signature verification (HMAC compare with hmac.compare_digest)
- Open redirect: request.redirect(request.params.get('next')) without url_has_allowed_host_and_scheme
- Reverse proxy trust: routes reading request.httprequest.headers['X-Forwarded-For'] when proxy_mode=False, or trusting any X-* header
- @http.route(sitemap=True) returning enumeration of internal record names

Audit grep starters:
  grep -rn '@http.route' --include='*.py' .
  grep -rn "auth=['\"]\\(public\\|none\\)['\"]" --include='*.py' .
  grep -rn 'csrf=False' --include='*.py' .
  grep -rn 'request\\.params\\|request\\.jsonrequest' --include='*.py' .
  grep -rn 'request\\.redirect' --include='*.py' .
  grep -rn 'def \\w\\+(self, \\*\\*kw' --include='*.py' .

For each finding: paste the route decorator, the entry parameter, and the unsanitised path to a sink (sudo / cr.execute / write / template render / file write).

Skip: routes that only render static T-esc'd templates with no user-controlled data; routes whose only sink is request.session['lang'] type writes.
```

## #3 — ORM / SQL / Domain Agent

```
Technique: ORM misuse, raw SQL, domain injection, mass-assignment.

Hunt for:
- self.env.cr.execute(...) with f-string, % formatting, or .format() — SQL injection. Must use (query, (param,)) form
- cr.execute('SELECT * FROM ' + table_name) — table/column injection (parameter binding does NOT fix identifier injection; use psycopg2.sql.Identifier)
- cr.executemany on user-controlled rows
- Raw SQL bypassing ORM = bypasses ir.rule, ir.model.access, _check_company, audit log, mail.tracking
- Domain construction from user input: domain = [('name', '=', request.params['x'])] is OK — but domain = eval(request.params['domain']) or [(request.params['field'], '=', ...)] is NOT
- model.search([]) / model.search_read([], ...) inside auth='public' with sudo — full-table dump
- model.search_read([], fields=request.params.getlist('fields')) — user picks fields, may bypass prefetch ACL paths or leak password / api_key fields
- model.read(['password'], ['api_key'], ['totp_secret']) — verify ACL on the model
- model.write(request.params) — mass assignment; attacker sets arbitrary columns
- model.create(request.params) — same; especially dangerous on res.users (sets login, group_ids)
- ORM order parameter from user: model.search([], order=request.params['sort']) — SQL injection via order clause (Odoo passes it through)
- groupby parameter from user in read_group — same injection class
- Computed fields with store=True and depends on user-mutable field, no recompute trigger control
- @api.depends decorators that miss a parent field — recompute drift, not always a vuln but flag
- onchange handlers that reach the database with sudo()
- Write/create on res.users from a non-admin context that sets group_ids, partner_id, or password
- model.unlink() called on records selected from user-controlled domain without ownership check

Audit grep starters:
  grep -rn 'cr\\.execute' --include='*.py' .
  grep -rn 'cr\\.execute.*%\\|cr\\.execute.*format\\|cr\\.execute(f' --include='*.py' .
  grep -rn '\\.search(\\[\\])\\|\\.search_read(\\[\\]' --include='*.py' .
  grep -rn '\\.write(.*request\\|\\.create(.*request\\|\\.write(kw\\|\\.create(kw' --include='*.py' .
  grep -rn '\\.search(.*order=' --include='*.py' .
  grep -rn 'eval\\|safe_eval' --include='*.py' . | grep -v 'test'

For each finding: paste the SQL or ORM call, the user-controlled parameter, and the entry route. Show the injection payload literally.

Skip: cr.execute on hardcoded literals (e.g., schema migrations); ORM calls with fully-static domains.
```

## #4 — QWeb / XSS / Template Agent

```
Technique: Server-side QWeb templating + OWL client templates + mail templates + report templates.

Hunt for (server-side QWeb — *.xml in views/ data/ report/):
- t-raw="..." with any expression that touches a user-mutable field (res.partner.name, sale.order.note, mail.message.body, helpdesk.ticket.description, ir.attachment.name)
- Markup(user_value) anywhere in Python that feeds into t-out / response body
- t-call="user_template_name" with template name from DB (mail.template.body_html, ir.ui.view stored XML loaded by name)
- t-att-href="user_url" — javascript:, data:text/html, vbscript: payloads slip through (verify the URL scheme is whitelisted)
- t-att-src on <script>/<iframe>/<object> with user URL
- t-attf-on*="..." — event handlers built with user content
- t-field on a fields.Html column with sanitize=False / sanitize_attributes=False
- fields.Html(sanitize=False) declarations
- tools.html_sanitize(text, strict=False) — non-strict mode keeps more tags
- tools.html2plaintext used as a sanitiser (it isn't)

Hunt for (mail templates):
- mail.template.body_html sourced from user model (SSTI in QWeb-render path)
- email_to / email_cc / subject built with user input — header injection (CRLF)
- mail.thread.message_post(body=request.params['x']) — stored XSS via QWeb
- ir.attachment.create(public=True) with user-controlled name/mimetype — served by /web/content/<id> with attacker MIME

Hunt for (OWL client-side):
- Component templates with t-out on user data — generally safe (auto-escaped) BUT t-raw is unsafe
- innerHTML / outerHTML / insertAdjacentHTML in OWL component code
- el.setAttribute('on*', userValue) — DOM XSS
- href="javascript:..." computed from props
- Custom QWeb directive plugins that pre-escape and then markupsafe.Markup later

Hunt for (report templates):
- t-call-assets="..." with user-controlled asset bundle name
- Reports rendering arbitrary user HTML directly (instead of t-field on Html field)

Audit grep starters:
  grep -rn 't-raw=' --include='*.xml' .
  grep -rn 'Markup(' --include='*.py' .
  grep -rn 'sanitize=False\\|sanitize_attributes=False' --include='*.py' .
  grep -rn 'message_post.*body=' --include='*.py' .
  grep -rn 'fields\\.Html(' --include='*.py' .
  grep -rn 't-call=' --include='*.xml' . | grep -v '"[a-z_]*\\.[a-z_]*"'
  grep -rn 't-att-href\\|t-att-src\\|t-attf-on' --include='*.xml' .
  grep -rn 'innerHTML\\|insertAdjacentHTML' --include='*.js' .

For each finding: paste the template line, the data source, and the controller/cron path that supplies the value. Include a payload that demonstrates JS execution in a victim's session.

Skip: t-esc and t-out usage (these auto-escape); t-att on data-* attributes that are not href/src/on*.
```

## #5 — Business Logic Agent

```
Technique: Business logic, state machines, workflow bypass, race conditions, multi-step flows.

Hunt for:
- Sale / purchase order state transitions invoked from controllers without checking current state (draft→done in one step)
- invoice.action_post() / invoice.button_cancel() reachable by non-finance users via /my/invoices controllers
- Stock move validate() bypassing reservation checks
- Coupon / promotion code redemption without atomic decrement (race window between read and write)
- res.partner.parent_id loops or self-reference allowed (recursion DoS / impersonation)
- Subscription / recurring invoice flows where user can change next_invoice_date or recurring_invoice_amount
- Loyalty / points / wallet credit flows without idempotency on the inbound webhook or POST
- Password reset flow: token reusable, no expiry, not bound to email, leakage via Referer
- Signup flow: auth_signup tokens persistent, group assignment via UTM/source
- Two-step checkouts (e-commerce) where the price/qty in step 2 isn't validated against step 1
- TOCTOU on stock.quant counts (overselling), helpdesk SLA breach evasion
- Multi-step wizards (transient.model) where step N can be POSTed without step N-1
- ir.actions.server with state='code' callable by base.group_user / base.group_portal — arbitrary Python in user context
- ir.cron with user_id=base.user_root and code that processes records from user input — cron runs admin code on attacker data
- Workflow approval skips: approver = current_user (self-approve)
- Negative quantities, integer overflow on price * qty in custom field computes
- Refund / reversal flows that don't reverse the inventory move or accounting entry

Audit grep starters:
  grep -rn 'state=' --include='*.py' . | grep -i 'write\\|create' | head -200
  grep -rn 'action_(post\\|confirm\\|done\\|cancel\\|validate)' --include='*.py' .
  grep -rn 'sudo().write\\|sudo().create' --include='*.py' .
  grep -rn '<record model="ir\\.actions\\.server"' --include='*.xml' .
  grep -rn '<record model="ir\\.cron"' --include='*.xml' .
  grep -rn 'transient' --include='*.py' .

Findings here often need a multi-step PoC. Spell out each step (login as portal user → call route X → call route Y → observe state Z).

Skip: state checks present but with a comment "TODO tighten" — that's a code smell, not a vuln.
```

## #6 — Secrets / Config Agent

```
Technique: Secret material, config defaults, system parameters, deployment hardening.

Hunt for:
- Hardcoded secrets in *.py / *.xml / *.csv: API keys, signing keys, passwords, tokens. Use entropy heuristics + name match (api_key, secret, token, password, passwd, pwd, key)
- Test fixtures committed with real credentials (look in tests/ data/)
- ir.config_parameter records with values committed in module data (especially database.secret, web.base.url, signing keys) — these overwrite production on module install
- ir.config_parameter.sudo().set_param() called from a controller — anyone reaching the route writes config
- ir.config_parameter.sudo().get_param('database.secret') / 'database.uuid' returned to public routes / logged at INFO+
- res.users default password set in module data (admin/admin, demo/demo) without post-install rotation hook
- Werkzeug debug PIN reachable: app initialised with use_debugger=True
- log_level=debug or log_handler containing :DEBUG on werkzeug / odoo.sql_db / odoo.http in production config
- proxy_mode=False while behind nginx (X-Forwarded-* headers ignored — rate limiting useless) OR proxy_mode=True without trusted proxy (spoofable headers)
- list_db=True (default) with weak admin_passwd — /web/database/manager exposed
- admin_passwd left as 'admin' or empty in odoo.conf
- dbfilter empty in multi-tenant deploy → cross-DB confusion via Host header
- web.base.url not pinned + web.base.url.freeze=False → host header injection drives password-reset email URLs
- auth_signup.invitation_scope=b2c / auth_signup.allow_uninvited=True / auth_oauth.allow_signup=True without intent
- mail.mail_channel.allow_public_users=True
- Module manifest 'license' missing or set to a non-OSI value when redistributing
- .env / settings_local / odoo.conf templates with example secrets that look real

Audit grep starters:
  grep -rEn '(api[_-]?key|secret|token|password|passwd|signing[_-]?key)\\s*=\\s*["\\'][^"\\'][^"\\']{8,}' --include='*.py' --include='*.xml' --include='*.csv' .
  grep -rn 'set_param\\|get_param' --include='*.py' .
  grep -rn 'ir\\.config_parameter' --include='*.xml' .
  grep -rn '<record id="base\\.user_admin"' --include='*.xml' .
  find . -name 'odoo*.conf' -o -name '.env*' | xargs -I{} echo "Config: {}"

Cross-check with osv-scanner / pip-audit output for known-leaked credentials.

For each finding: paste the literal string, file:line, what kind of secret (key type, scope), and rotation guidance.

Skip: dummy/placeholder values that are obviously fixtures (admin/admin in tests/, "your-key-here" comments).
```

## #7 — External Integration Agent

```
Technique: Outbound HTTP, webhooks inbound, mail outbound, scheduled jobs, external services (Stripe, S3, FedEx, HubSpot, ldap, smtp, oauth IdP).

Hunt for:
- requests.get(url, ...) / urllib / httpx with verify=False
- requests.* without timeout (slow-loris on caller, SSRF amplification)
- HTTP client URL constructed from user input (SSRF) — any auth='user' or auth='public' route
- Cloud metadata reachable from container: 169.254.169.254, fd00:ec2::254, metadata.google.internal — look for allow-list before resolution
- DNS rebinding tolerance: hostname check on first resolution but second resolve on connect (urllib3 follows this trap)
- requests.get(url, allow_redirects=True) (default) — chases redirects to internal IPs
- urllib.parse.urljoin(base, user) where base can be replaced by absolute URL in user
- Webhook inbound (Stripe, HubSpot, Slack, GitHub) without signature verification (HMAC + hmac.compare_digest)
- Webhook inbound without timestamp / replay protection
- mail.template / mail.mail with To/Cc/Bcc/Reply-To built from user input → header injection (CRLF)
- ir.mail_server records with auth credentials in module data
- LDAP bind with user-controlled DN/filter (filter injection — LDAP escape required)
- OAuth provider records with client_secret in module data
- Scheduled jobs (ir.cron) that fetch external URLs without timeout/SSRF guard
- subprocess.run / os.system reaching external CLI tools (gpg, openssl, ldapsearch, curl) with user-controlled args
- xmlrpc / jsonrpc client libraries with verify=False
- boto3 / azure-sdk client with user-controlled endpoint (SSRF via custom endpoint)
- pyhubspot / stripe / slack-sdk clients with API key from env but used in a route that accepts attacker query

Audit grep starters:
  grep -rn 'verify=False' --include='*.py' .
  grep -rn 'requests\\.\\(get\\|post\\|put\\|delete\\|patch\\|head\\|request\\)' --include='*.py' . | grep -v 'timeout='
  grep -rn 'urllib\\.request\\|urllib3\\.PoolManager\\|httpx\\.Client' --include='*.py' .
  grep -rn 'ir\\.mail_server\\|smtplib' --include='*.py' .
  grep -rn 'hmac\\.compare\\|signature' --include='*.py' . | grep -i webhook
  grep -rn '<record model="ir\\.cron"' --include='*.xml' .

For each finding: name the integration, the entry point that triggers it, the user input that flows to URL/headers/body, and the SSRF target / spoofable header.

Skip: integration calls with hardcoded URLs and constant headers (no user input flowing in).
```

## #8 — Data Exposure Agent (Portal / Attachment / Chatter / Reports)

```
Technique: Information disclosure — what does Odoo return that it shouldn't?

Hunt for:
- /my/* portal controllers that return invoices/orders/projects without _document_check_access
- /report/pdf/<report_name>/<docids> with docids from user input — report rendering on records the user can't see
- /web/binary/* / /web/content/<id> with public=True attachments containing PHI / financial / internal data
- ir.attachment created with public=True from controllers — file world-readable
- ir.attachment with mimetype=text/html uploaded by user — served inline (stored XSS via download)
- mail.message bodies returned to portal users that include internal subtypes (mail.mt_note) — internal notes leaked
- mail.followers exposing internal users to portal users
- chatter posts (message_post) with body containing email_from of non-portal recipients
- res.partner search/search_read from portal with broad fields including parent_id, vat, internal_notes
- res.users.read_group / search_read returning partner_id of internal staff to portal user
- xmlrpc /xmlrpc/2/object endpoint without authentication on public DB filter — model.execute_kw enumerates everything
- ir.exports / data export endpoints reachable by portal — any model dumpable
- Translation strings (ir.translation) leaking developer notes / internal field labels
- Logs leaking secrets: log_level=debug + werkzeug body in odoo.log
- Error pages with full traceback (server.error.include-stacktrace=always equivalent: web.show_effect=True or unhandled exceptions in production)
- ir.config_parameter values returned via /web/dataset/call_kw to non-admin users
- res.users.password / password_crypt / api_key / totp_secret accidentally readable (compute_sudo + fields.Char without 'groups=base.group_system')

Audit grep starters:
  grep -rn '/my/\\|/portal/' --include='*.py' .
  grep -rn '_document_check_access\\|check_access_rights\\|check_access_rule' --include='*.py' .
  grep -rn 'public=True' --include='*.py' . | grep -i attachment
  grep -rn 'message_post' --include='*.py' .
  grep -rn 'subtype_xmlid\\|mail\\.mt_note' --include='*.py' .
  grep -rn 'fields\\.\\(Char\\|Text\\|Html\\)(.*compute_sudo' --include='*.py' .
  grep -rn 'groups=' --include='*.py' . | grep -v base.group_system

For each finding: name the route or view, the field/record exposed, and the privilege boundary crossed (anonymous→authenticated, portal→internal, user→admin, company A→company B).

Skip: fields explicitly marked groups="base.group_system" or compute_sudo=False with an ACL guard.
```

## #9 — Dependency Agent

```
Technique: Supply chain — Python deps, JS deps in webclient, OCA / third-party Odoo modules vendored, base image.

Hunt for:
- requirements.txt / setup.py / pyproject.toml with pinned old versions of:
  * Werkzeug < 3.0 (debug PIN, redirect issues)
  * Pillow < 10.3 (image RCE)
  * lxml < 5.2 (XXE)
  * PyJWT < 2.4 (algorithm confusion)
  * PyYAML < 6.0 (yaml.load default unsafe)
  * cryptography < 42.0.4 (TLS state machine)
  * requests < 2.32 (TLS hostname)
  * urllib3 < 2.2.2 (redirect / cert)
  * python-ldap < 3.4 (deref / DN parsing)
  * xlrd >= 2.0 (XLSX dropped) but pinned < 2 (legacy CVEs)
- Odoo core version itself: <16 = EOL community; cross-check Odoo S.A. CVE list
- OCA addons vendored at non-tag refs (commit hash on a force-pushable branch) — supply-chain pivot
- Third-party addons from non-OCA sources without code review
- node_modules / package.json in static/src with lockfile drift
- Lockfile missing entirely (requirements.txt with no pin / no hash)
- pip install -r requirements.txt --no-deps — verify no resolution to internal repo with public fallback
- Docker base image: latest tag, EOL distro, no USER directive
- Docker image pulling from unverified registry
- GitHub Actions / odoo.sh workflows with secrets in workflow logs (echo $SECRET)
- .git directory committed into a release tarball (rare but checked)

Audit grep starters:
  cat requirements.txt setup.py pyproject.toml 2>/dev/null
  find . -name '__manifest__.py' -exec grep -l 'external_dependencies' {} \\;
  find . -path '*/static/src*' -name 'package.json'
  cat Dockerfile docker-compose.yml 2>/dev/null
  cat .github/workflows/*.yml 2>/dev/null

Cross-reference with osv-scanner / pip-audit output (Phase 4.5). Only emit findings for dependencies with reachable code paths from this codebase, OR where the dep itself has a critical CVE in the pinned version.

For each finding: dep name, current pin, fixed version, CVE ID, reachability one-liner.

Skip: deps with CVEs that don't apply to the API surface used by this codebase (use Phase 4.5 reachability output to filter).
```

## #10 — Chaining Agent

```
Technique: Cross-finding correlation — multi-step exploits.

You receive the outputs of all other Odoo hunters. Your job:

1. Read every finding (including LOW/INFO).
2. Look for combinations that uplift severity in the Odoo trust model:
   - auth='public' route + sudo() + sensitive model = unauthenticated data dump (CRITICAL)
   - Open redirect + auth_signup invite link = OAuth/signup token theft
   - SSRF from public route + cloud metadata reachable = creds → admin via odoo.conf
   - Mass-assignment on res.users + portal route = privilege escalation portal→internal user
   - Mass-assignment on res.users.group_ids + auth='user' = user → admin
   - QWeb t-raw on mail.message body + message_post from portal = stored XSS in admin's chatter (admin session theft)
   - ir.attachment public=True + user-controlled mimetype + /web/content URL = stored XSS via download
   - SQL injection in cr.execute + database.secret leak in logs = session forgery + DB write
   - safe_eval sandbox bypass + ir.cron with user_root = persistent RCE
   - ir.actions.server state='code' + base.group_user + ir.rule with domain_force=[(1,'=',1)] = code-execution gadget reachable by every internal user
   - CSRF + state-changing GET on a privileged action server = drive-by RCE for admin
   - Webhook missing signature verify + idempotency missing on payment route = arbitrary balance write
   - Insecure default (list_db=True + admin_passwd weak) + dbfilter empty = cross-DB takeover
3. For each chain, output a NEW finding in the standard Odoo finding format.
4. Severity reflects the chained impact, not the components.
5. Cross-reference component finding numbers (from hunters #1–#9) in the chain finding's Description.

Do not re-report component findings. Only output new chained findings or "NO CHAINS FOUND".
```

---

## Dispatch Pattern (Orchestrator)

In a single message, fire all 9 technique hunters with `Agent` calls plus matching `TaskCreate` entries. Wait for completion. Then fire #10. Then proceed to Phase 5.5 (discourse) → Phase 6 (correlation) → Phase 7 (validation).

```
[single assistant turn]
- TaskCreate × 10
- Agent × 9 (technique hunters #1–#9, parallel, single message)
[wait for all 9]
- Agent × 1 (chaining hunter #10, gets prior outputs concatenated)
[wait]
- Phase 5.5 discourse (AGREE/CHALLENGE/CONNECT/SURFACE) in main loop
- Phase 6 correlation in main loop
- Phase 7 validation (6-gate fp-check) in main loop
```

## Hunter Scope Cheat Sheet

| #   | Hunter               | Owns                                                          | Primary refs                                         |
| --- | -------------------- | ------------------------------------------------------------- | ---------------------------------------------------- |
| 1   | Access Control       | ACL CSV, ir.rule, groups, sudo/with_user/with_context         | lang-odoo, sharp-edges (Odoo)                        |
| 2   | Controller / Route   | @http.route, request.params, CSRF, IDOR                       | lang-odoo, sharp-edges (Odoo)                        |
| 3   | ORM / SQL / Domain   | cr.execute, mass-assignment, domain injection                 | lang-odoo, sharp-edges (Odoo), lang-python (psycopg) |
| 4   | QWeb / XSS           | t-raw, Markup, Html fields, mail body, OWL innerHTML          | lang-qweb                                            |
| 5   | Business Logic       | state machines, races, workflow bypass, server actions, cron  | lang-odoo, sharp-edges (Odoo)                        |
| 6   | Secrets / Config     | hardcoded secrets, ir.config_parameter, odoo.conf, debug PIN  | insecure-defaults (Odoo)                             |
| 7   | External Integration | requests/urllib/SSRF, webhooks, mail headers, LDAP, OAuth     | lang-python, sharp-edges                             |
| 8   | Data Exposure        | portal /my, attachments, chatter, reports, xmlrpc enumeration | lang-odoo                                            |
| 9   | Dependency           | requirements.txt, OCA pins, base image, JS deps               | (Phase 4.5 output)                                   |
| 10  | Chaining             | cross-hunter correlation                                      | all of the above                                     |
