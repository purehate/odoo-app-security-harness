# Language Patterns — Odoo

Odoo (8.0 → 18 / Enterprise + Community) is Python on top of an opinionated ORM, RPC layer, QWeb templating engine, and access-control model. **Generic Python AppSec misses the real bugs.** The money in Odoo audits is framework misuse: public route + `sudo()`, weak record rules, portal data leakage, unsafe QWeb, attachment/chatter exposure, cron/integration abuse.

Pair this file with:

- `lang-python.md` — generic Python (Werkzeug, requests, crypto, deser).
- `lang-qweb.md` — templating sinks (`t-raw`, `t-att`, `Markup()`, mail templates).

## Mental Model

| Layer                    | Where bugs live                                                   |
| ------------------------ | ----------------------------------------------------------------- |
| Module manifest          | `__manifest__.py` declares deps + data files (XML/CSV)            |
| Models                   | `models/*.py` — `_inherit`, `_inherits`, `_sql_constraints`       |
| Controllers              | `controllers/*.py` — HTTP entry points                            |
| Views / Templates        | `views/*.xml`, `data/*.xml` — QWeb + actions + menus              |
| Access (CSV)             | `security/ir.model.access.csv` — model-level CRUD                 |
| Access (Record Rules)    | `security/*.xml` `<record model="ir.rule">` — row-level domain    |
| Static                   | `static/src/*.js`, `static/src/**` — frontend, often public       |
| Server actions / Wizards | `models/*.py` `TransientModel`, `ir.actions.server` from XML data |
| Cron                     | `data/*.xml` `<record model="ir.cron">`                           |

**Two trust boundaries** that hunters often confuse:

1. **Public vs authenticated** — `@http.route(auth='public')` is reachable by anyone.
2. **User vs root** — `sudo()` runs as superuser, **bypassing record rules**. Combined: `auth='public'` + `sudo()` = pre-auth admin-context query.

## Decorators That Matter

### `@http.route` (controllers)

```python
@http.route('/my/path', type='http', auth='user', csrf=True, methods=['POST'])
```

| Argument        | Default           | Hunt for                                                                              |
| --------------- | ----------------- | ------------------------------------------------------------------------------------- |
| `auth='user'`   | `'user'`          | `auth='public'` — internet-reachable. Verify what data leaves.                        |
| `auth='none'`   | —                 | Even more permissive than `public` — no DB cursor. Often misused for callbacks.       |
| `csrf=True`     | `True` for `http` | `csrf=False` on `type='http'` POST — CSRF gone, verify why.                           |
| `type='json'`   | —                 | JSON-RPC: CSRF defaults different, body parsed as JSON. Mass-assignment via `params`. |
| `methods=[...]` | any               | Missing → both GET and POST allowed; state-changing GET = CSRF-trivial.               |
| `website=True`  | False             | Adds website-context (lang, currency, layout) — pulls in public visitor logic.        |
| `sitemap=False` | True              | Hidden routes still reachable, just not crawled.                                      |

Audit grep:

```bash
grep -rn "auth='public'" --include='*.py' .
grep -rn "auth=\"public\"" --include='*.py' .
grep -rn "csrf=False" --include='*.py' .
grep -rn "@http.route" --include='*.py' . | grep -v test
```

### `@api.model`, `@api.model_create_multi`, `@api.depends`, `@api.constrains`

Mostly informational. Bug-relevant:

- `@api.model` on a method that takes record IDs from kwargs → caller can pass any ID (no record context check).
- `@api.constrains('field')` not firing when records are written via `cr.execute()` (raw SQL bypass).

## ORM Sharp Edges

### `sudo()` — superuser context

```python
self.env['res.partner'].sudo().search([('email', '=', login)])
self.sudo().write({'state': 'done'})
```

`sudo()` **bypasses record rules and `ir.model.access.csv`**. It is the #1 Odoo footgun.

Findings worth filing:

- `sudo()` inside an `auth='public'` controller — verify what fields leak / what writes happen.
- `sudo()` on a search/read that filters by user-controlled domain — cross-tenant data read.
- `sudo()` on `unlink()`, `write()`, `create()` reachable from an HTTP route → unauthenticated mutation.
- `sudo()` followed by `.with_user(public_user)` to "scope back" — verify the scope-back actually applies. Many don't.
- `sudo(user_id)` with `user_id` from `request.params` — privilege escalation.

Safe-ish uses (still cite):

- `sudo()` on `mail.template` send (intentional — needs to write `mail.message` regardless of caller perms).
- `sudo()` on `ir.config_parameter` reads of public values (`web.base.url`).

### `with_user(user)` and `with_context(...)`

- `with_user(env.ref('base.user_admin'))` — same blast radius as `sudo()`.
- `with_context(active_test=False)` — disables the standard `active=True` filter; can return archived/soft-deleted records.
- `with_context(prefetch_fields=False)` — perf, not security.
- `with_context(no_validate=True)` / `with_context(skip_validation=True)` — custom flags that signal danger; grep for them.
- `with_context(tracking_disable=True)` — silences chatter/audit log on writes. Combined with sensitive write = stealth.

### `self.env.cr.execute(...)`

Direct SQL. Bypasses the ORM, record rules, ACL, audit log, and `_check_company`. Findings:

- `cr.execute(f"SELECT ... WHERE id = {x}")` / `cr.execute("... %s" % x)` — SQL injection.
- `cr.execute("SELECT ... WHERE name = %s", (name,))` — parameterised, safe.
- `cr.execute("SELECT * FROM " + table)` — table name injection (parameterise won't help).
- `cr.execute("UPDATE res_users SET ... ")` — raw write, bypasses audit.
- `cr.execute(query)` where `query` is built from QWeb domain or `request.params['order']` — second-order.

Grep:

```bash
grep -rn 'cr\.execute' --include='*.py' .
grep -rn 'self\.env\.cr' --include='*.py' .
```

### Domains

Domains are the WHERE clause of Odoo searches. They are tuple lists:

```python
domain = [('partner_id', '=', user.partner_id.id), ('state', 'in', ['draft','open'])]
records = self.env['sale.order'].search(domain)
```

Bug shapes:

- Domain literal with string interpolation: `[('name','=', f'%{user_input}%')]` followed by `'ilike'` — usually safe, but verify operator.
- `domain = literal_eval(request.params['domain'])` — attacker controls the WHERE entirely. Filed as critical.
- `safe_eval(domain_text, ...)` — depending on globals, can reach arbitrary callables.
- `_search_*` and `_compute_*` methods that build domains with attacker-controlled fields.

### `search([])` — empty domain

`self.env['res.partner'].search([])` returns **everything visible to the current user**. Combined with `sudo()` = every partner in the database.

- `auth='public'` + `sudo().search([])` + JSON return = full table dump. File as CRITICAL data exposure.
- `search_read([], fields=['email','phone'])` — same, but worse: explicit field projection bypasses some prefetch ACL paths.

### `read_group`, `read`, `search_read`

- `read_group(domain, fields=user_fields, groupby=user_groupby)` — user-controlled group/field selection can leak fields the caller couldn't read individually.
- `read(['email','password'])` — `password` field exists on `res.users`; if access is misconfigured, raw read leaks hash.
- Field-level ACL (`ir.model.fields` `groups`) is enforced on `read` but **not on raw SQL**.

### `write(vals)` and `create(vals)`

- `write(request.params)` / `create(request.params)` — mass assignment. Attacker sets `state='approved'`, `user_id=admin`, `partner_id=victim`.
- Pop only known-safe keys, never the inverse (allowlist > denylist).
- Computed fields with `inverse=` allow writes to be redirected to a stored field — verify the inverse handler.
- `write({'company_id': X})` — in multi-company instances, can punt records into a different company; verify `_check_company`.

### `unlink()`

- Public route reaching `unlink()` = unauthenticated delete.
- `sudo().unlink()` = unaudited delete.
- Cascading deletes (`ondelete='cascade'`) on `Many2one` — deleting a parent silently deletes children that may be authored by other users.

## Access Control Model

### `ir.model.access.csv`

Per-model CRUD per group. Format:

```csv
id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink
access_my_model_user,my.model.user,model_my_model,base.group_user,1,0,0,0
```

Hunt:

- Group `base.group_public` (anonymous portal visitors) granted `perm_*=1` on a non-public model.
- Group `base.group_portal` granted broad CRUD on internal models.
- Missing entries — without an ACL record, **only the implicit superuser has access**, but `sudo()` bypasses anyway. So missing ACL ≠ safe.
- Models with no ACL entries at all are a code-smell flag, not a bug per se.

### Record rules (`ir.rule`)

Row-level filtering. Typically:

```xml
<record id="rule_my_model_user" model="ir.rule">
    <field name="name">My Model: own records</field>
    <field name="model_id" ref="model_my_model"/>
    <field name="domain_force">[('user_id','=',user.id)]</field>
    <field name="groups" eval="[(4, ref('base.group_user'))]"/>
    <field name="perm_read" eval="True"/>
    <field name="perm_write" eval="True"/>
    <field name="perm_create" eval="True"/>
    <field name="perm_unlink" eval="True"/>
</record>
```

Hunt:

- `domain_force = [(1,'=',1)]` — universal pass. Often used as placeholder; left in production = ACL gone.
- Rules that filter by `user.partner_id` but not by `user.company_ids` in multi-company → cross-company leak.
- Rules that apply to `base.group_user` only — portal users (`base.group_portal`) bypass; verify a separate portal rule exists.
- Rules with `groups` empty — applies to everyone, including portal/public.
- `global="True"` rules with permissive domain — can override stricter group-scoped rules.
- Rules whose domain references `request.uid` directly (not `user.id`) — request env may be different from rule eval env.

### Group hierarchy

Groups inherit (`implied_ids`). `base.group_user` < `base.group_system` (admin). A user added to `base.group_system` gains everything.

- Hunt for unintended `implied_ids` adding `base.group_system` to a feature group.

## Controllers (HTTP)

### `request.params`, `request.jsonrequest`, `request.httprequest`

```python
class MyCtrl(http.Controller):
    @http.route('/api/things', type='json', auth='user')
    def list_things(self, **kw):
        domain = kw.get('domain', [])
        return request.env['my.model'].search_read(domain, kw.get('fields', []))
```

That code is a CRITICAL bug. `domain` and `fields` come from the request → user controls the WHERE and the projection. Standard Odoo audit finding.

- `request.params['xxx']` for sensitive fields (`user_id`, `partner_id`, `state`) — verify ownership/transition rules.
- `request.jsonrequest` (Odoo 16+) gives the raw JSON-RPC body. Same risks.
- `kwargs` / `**kw` swallowing — every unrecognised arg gets accepted by the route. Combined with `write(kw)` = mass assign.

### Portal controllers (`/my/...`)

`portal.py` controllers serve authenticated portal users. Common bugs:

- Object access by ID without `_check_access_rights` / `_check_access_rule` after `browse`:

  ```python
  order = request.env['sale.order'].browse(int(order_id))
  return request.render(...)  # IDOR
  ```

- Use the `CustomerPortal._document_check_access(model, doc_id, access_token=None)` helper — that's the official IDOR-resistant pattern. Skipping it is the bug.
- Access-token routes (`?access_token=...`): verify the token is unguessable (32+ bytes, `secrets.token_urlsafe`). Some modules use `uuid4` (fine) or `id + sha256(salt)` (not).

### Website controllers (`@http.route(... website=True)`)

- `website.layout` template includes user-supplied data via `t-raw` or `Markup()` → stored XSS.
- Free-text fields (`description`, `comment`) rendered raw on public website pages.

### Webhook / external callback controllers

- `auth='none'` for inbound webhooks — verify HMAC/signature check before any DB write.
- `csrf=False` + `type='http'` POST — same.
- Replay protection: nonce/timestamp window check.

## Server Actions (`ir.actions.server`)

Defined in XML, can run arbitrary Python in `code` field:

```xml
<record id="sa_send_email" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code">
        for record in records:
            record.send_email()
    </field>
</record>
```

Hunt:

- `state='code'` actions reachable by `base.group_user` or `base.group_portal` via menu / button.
- `state='code'` calling `safe_eval` with attacker-influenced expression.
- Server actions chained (`child_ids`) where one child is a code action and the parent is reachable from a user button.

## Wizards (`TransientModel`)

Short-lived records used for forms / dialogs. Bug shapes:

- Wizard `action_apply()` that does sensitive writes without re-checking the underlying records (user might modify the wizard's `partner_id` field via web client before triggering apply).
- Wizard `default_get` returning data the user shouldn't see (uses `sudo()` to fetch defaults).

## Cron Jobs (`ir.cron`)

```xml
<record id="cron_my_task" model="ir.cron">
    <field name="model_id" ref="model_my_model"/>
    <field name="state">code</field>
    <field name="code">model.do_thing()</field>
    <field name="user_id" ref="base.user_root"/>
</record>
```

Hunt:

- `user_id` set to `base.user_root` (admin) on a cron that processes user-supplied data — privileged context.
- Cron code that hits `requests.get(url)` on URLs from records → SSRF amplification.
- Cron writing `mail.message` or `mail.tracking.value` based on user records — log-poisoning.

## Mail / Chatter / Attachments

Chatter (`mail.thread`) is the sidebar with messages, log notes, followers, attachments.

### `mail.message`

- `request.env['mail.message'].search([])` from an `auth='public'` route — message body, author, subject, attachments all leak.
- Internal log notes (`subtype_id == mail.mt_note`) are normally not visible to portal users — verify the access rule. Some modules accidentally include `mt_note` in portal queries.
- Posting a message via `message_post(body=request.params['x'])` → stored XSS via QWeb rendering.

### Attachments (`ir.attachment`)

- Public download: `/web/content/<id>` and `/web/image/<id>` are public **iff the attachment has `public=True` or no `res_model`/`res_id`**. Otherwise ACL applies.
- Hunt for `ir.attachment` creation with `public=True` set from user input.
- `mimetype` set from user input + `ir.attachment` accessed via `/web/content` → MIME confusion (HTML uploaded as PDF, reflected via `Content-Disposition: inline`).
- Attachment access via `access_token` field — verify the token is on the attachment and not just the parent record.

### Mail templates

- `mail.template` with `body_html` containing Jinja2/QWeb expressions evaluating user data → SSTI / XSS.
- `email_to` / `email_from` rendering with `safe_eval` — RCE if expression context is loose.
- `report_template` (PDF) with QWeb expressions — same SSTI risks but harder to exploit (no JS in PDF).

## Multi-Company

- `_check_company = True` on a model adds an automatic `company_id` filter to record rules. Missing on a model that has `company_id` field = cross-company read.
- Many2one without `check_company=True` → can point at a record in a company the user can't access.
- `with_company(company_id)` from `request.params` — switching company context per-request; verify the user is in `company_ids`.

## `ir.config_parameter` and System Parameters

```python
self.env['ir.config_parameter'].sudo().get_param('mailgun.api_key')
self.env['ir.config_parameter'].sudo().set_param('foo', request.params['v'])
```

Hunt:

- Reads of secrets via `get_param` followed by logging the value.
- `set_param` from a controller — anyone hitting that route writes config.
- Public-facing keys (`web.base.url`) read with `sudo()` is fine; secret keys (`auth_signup.invitation_scope`, OAuth client secrets) need ACL.
- `database.secret` / `database.uuid` exposure — base for cookie signatures; leak = session forgery.

## File Imports / `base_import`

- `base_import` lets users CSV-upload records. Verify post-import hooks don't bypass `create()`'s constrains.
- `import_compat=False` mode lets users set field IDs directly — chosen-ID attacks.
- File parsers (xls, csv) hitting `xlrd`/`openpyxl` versions with CVEs — separate finding.

## `safe_eval`

`odoo.tools.safe_eval` is Odoo's restricted Python eval used in:

- Domain literals from XML (`<field name="domain">`)
- Server action `code`
- Mail/report template Jinja-style expressions
- `_compute_default` lambdas read from XML

Hunt:

- `safe_eval(user_string, globals_dict)` where `globals_dict` includes callables (`env`, `time`, `datetime`, `_`).
- Custom `eval_globals` that re-add `__import__` or `__builtins__` (yes, this happens).
- Sandbox bypasses are well documented — Odoo hardens it but every release has had bypasses (`{}.__class__.__mro__[1].__subclasses__()` style).

## Versions to Flag (April 2026)

- Odoo < 16.0 — no longer receiving security fixes for community edition.
- Odoo < 17.0 — Enterprise still supported but late-cycle.
- Odoo OWL < 2.0 — XSS in template expressions on older versions.
- `python-ldap` and `xlrd` shipped in old Odoo bundles — known CVEs.
- `Werkzeug` < 3.0 (Odoo bundles its own version inside community releases).

## Audit Greps (Quick Reference)

```bash
# Public routes
grep -rn "auth=['\"]public['\"]" --include='*.py' .
grep -rn "auth=['\"]none['\"]" --include='*.py' .

# CSRF off
grep -rn 'csrf=False' --include='*.py' .

# Superuser escalation
grep -rn '\.sudo()' --include='*.py' .
grep -rn 'with_user(' --include='*.py' .
grep -rn 'with_context(' --include='*.py' . | grep -E '(no_check|skip|bypass|tracking_disable|active_test)'

# Raw SQL
grep -rn 'cr\.execute' --include='*.py' .
grep -rn 'self\.env\.cr\.' --include='*.py' .

# Mass assignment surface
grep -rn 'request\.params' --include='*.py' .
grep -rn 'request\.jsonrequest' --include='*.py' .
grep -rn '\*\*kw' --include='*.py' . | grep route

# safe_eval
grep -rn 'safe_eval' --include='*.py' .

# Wide search / read
grep -rn '\.search(\[\])' --include='*.py' .
grep -rn '\.search_read(\[\]' --include='*.py' .

# Public attachments
grep -rn "public.*=.*True" --include='*.py' . | grep -i attachment

# Record rule literal pass
grep -rn '\[(1, *=, *1)\]' --include='*.xml' .
grep -rn 'domain_force' --include='*.xml' . | grep -E "\(1, *['\"]?=['\"]?, *1\)"
```

## Anti-Patterns (Hunter Output)

- "`sudo()` is used in this controller" — without showing the data flow / impact, that's a style nit.
- "Missing record rule" — without naming the model AND the data it leaks, drop.
- "Empty domain" — only a finding when reachable from a route AND the model holds sensitive data.
- "`csrf=False`" — only a finding on a state-changing endpoint with cookie auth. JSON-RPC type='json' has different CSRF model.
- "Public route" — `auth='public'` itself is fine for legitimate public pages. The bug is what the public route then reads/writes.
