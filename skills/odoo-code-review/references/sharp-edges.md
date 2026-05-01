# Sharp Edges — Footgun APIs in Use

Bug class: an API is **safe in some uses, unsafe in others**, and the safety contract is non-obvious. The application called the API in the unsafe way. Dataflow tools often miss this because the call site looks clean — the bug is in **how** the API is being used, not in tainted-flow.

Distinct from **insecure-defaults** (`insecure-defaults.md`): insecure-defaults are about a config flag the app didn't flip. Sharp-edges are about an API the app _did_ call, but in a way the API contract treats as "caller's responsibility to validate".

## Common Sharp Edges (Audit Checklist)

### Odoo (Python framework)

The whole `lang-odoo.md` file is sharp-edge territory. Highlights for grep/audit:

- `record.sudo()` / `model.sudo()` — runs as superuser, **bypasses record rules and `ir.model.access.csv`**. The #1 Odoo footgun. Hunt every call inside an `auth='public'`/`auth='user'` controller.
- `sudo(user_id)` with attacker-controlled `user_id` → privilege escalation.
- `record.with_user(env.ref('base.user_admin'))` — explicit "run as admin". Same blast radius as `sudo()`.
- `record.with_context(active_test=False)` — disables soft-delete filter; can return archived records.
- `record.with_context(no_validate=True)` / `skip_validation=True` / `tracking_disable=True` — custom flags that signal danger; grep for them.
- `@http.route(auth='public')` — internet-reachable; verify what data is returned.
- `@http.route(auth='none')` — no DB cursor, even more permissive than public; common on webhooks.
- `@http.route(csrf=False)` — CSRF gone; only acceptable on `type='json'` or signed webhook routes. Verify justification.
- `@http.route(... methods=...)` missing — both GET and POST allowed; state-changing GET = CSRF-trivial.
- `request.params['x']` / `request.jsonrequest['x']` — attacker controls; never feed to `write()`/`create()`/domains directly.
- `**kw` in route handler then `record.write(kw)` / `record.create(kw)` — mass assignment.
- `self.env.cr.execute(...)` with f-string / `%` formatting → SQL injection. Bypasses ORM, record rules, audit log, `_check_company`. Use `(query, (param,))` form.
- `cr.execute("SELECT * FROM " + table)` — table/column name injection (parameter binding doesn't fix this).
- `model.search([])` / `model.search_read([], ...)` — empty domain returns everything visible. Combined with `sudo()` = full-table dump.
- `model.search_read([], fields=user_fields)` — user-controlled field list bypasses some prefetch ACL paths.
- `model.read(['password'])` — `password` field exists on `res.users`; verify ACL.
- `safe_eval(user_string, globals_with_callables)` — Odoo's restricted eval. Sandbox bypass history; verify `eval_globals`.
- `tools.html_sanitize(text, strict=False)` — non-strict mode keeps more tags. Verify input source.
- `fields.Html(sanitize=False)` / `sanitize_attributes=False` — stored XSS surface.
- `t-raw` in QWeb templates with user-controlled value → server-side XSS (see `lang-qweb.md`).
- `Markup(user_value)` → bypasses QWeb escape; same as `t-raw`.
- `t-call="dynamic_template_name"` — template name from DB → arbitrary template render.
- `ir.attachment` create with `public=True` from user input — file made world-readable via `/web/content/<id>`.
- `ir.attachment` with `mimetype` from user → MIME confusion (HTML uploaded, served `inline`).
- `ir.config_parameter.sudo().set_param(...)` from a controller — anyone hitting that route writes config.
- `ir.config_parameter.sudo().get_param('database.secret')` then logged — session-forgery baseline leak.
- `mail.message` body posted via `message_post(body=request.params['x'])` — stored XSS via QWeb.
- `mail.template.body_html` sourced from user model — SSTI in delivered emails.
- `domain_force = [(1,'=',1)]` in `ir.rule` XML — universal pass; ACL gone for that group.
- `<record model="ir.rule">` with empty `groups` — applies to everyone, including `base.group_portal` and `base.group_public`.
- `<record model="ir.rule">` with `global="True"` and permissive domain — overrides stricter group-scoped rules.
- `model._check_company = False` (or missing) on a model with `company_id` field — cross-company read.
- `Many2one(comodel, check_company=False)` — pointer can cross company boundary.
- `<record model="ir.actions.server">` with `state='code'` reachable by `base.group_user` / `base.group_portal` — arbitrary Python in user context.
- `<record model="ir.cron">` with `user_id="base.user_root"` and `state='code'` over user records — cron runs admin code on attacker data.

Quick grep set:

```bash
grep -rn "auth=['\"]\(public\|none\)['\"]" --include='*.py' .
grep -rn 'csrf=False' --include='*.py' .
grep -rn '\.sudo()' --include='*.py' .
grep -rn 'with_user(\|with_context(' --include='*.py' .
grep -rn 'cr\.execute' --include='*.py' .
grep -rn 'request\.params\|request\.jsonrequest' --include='*.py' .
grep -rn 'safe_eval' --include='*.py' .
grep -rn '\.search(\[\])\|\.search_read(\[\]' --include='*.py' .
grep -rn 't-raw=\|Markup(' --include='*.py' --include='*.xml' .
grep -rn 'public.*=.*True' --include='*.py' . | grep -i attachment
grep -rn 'domain_force.*1.*=.*1' --include='*.xml' .
grep -rn 'ir\.config_parameter.*set_param' --include='*.py' .
```

### Java / JVM

- `String.format()` with user-controlled format string → format-string injection (CWE-134), DoS via `%99999d`.
- `MessageFormat.format()` with user-controlled pattern.
- `Runtime.exec(String)` (single-string form) — splits on whitespace, attacker can inject args. The safe form takes `String[]`.
- `ProcessBuilder(List<String>)` is safe; `ProcessBuilder(String...).command(String)` may be unsafe depending on the shell.
- `URL` constructor — no validation, accepts `file://`, `jar://`, `gopher://`. Use `URI` then `toURL()` after validation.
- `URI.resolve()` against attacker-controlled input — produces `file://` URIs from absolute paths.
- `Path.resolve()` and `Paths.get()` — accept absolute paths, including `/etc/passwd`. No traversal protection.
- `ZipFile.getEntry()` — entry name unsanitised; no zip-slip protection. Use `zip4j` or manual canonicalisation.
- `ClassLoader.loadClass()` with user-controlled name.
- `MethodHandles.Lookup.findVirtual()` from reflection on user input.
- `JdbcTemplate.queryForList(String sql, Object... args)` — `args` are parameterised, but `sql` is not. ORDER BY / LIMIT are not parameterisable.
- `Pattern.compile(userRegex)` — ReDoS surface.
- `URLDecoder.decode(s, "UTF-8")` — accepts `%00` and `+` differently across versions; not idempotent under double-encoding.

### Python

- `subprocess.run(cmd, shell=True)` — splits on shell; injection if `cmd` is f-string.
- `subprocess.run(cmd_list, shell=False)` — safe.
- `os.path.join("/safe/", user)` — `os.path.join("/a", "/etc/passwd")` returns `/etc/passwd`. Absolute path replaces the prefix.
- `pathlib.Path(user_input).resolve()` — resolves through symlinks, may escape root.
- `pickle.load()` / `pickle.loads()` on any data not generated locally and not signed.
- `yaml.load()` without `Loader=SafeLoader` (older PyYAML) — RCE.
- `json.loads()` with `object_hook=dict_to_obj` — can construct arbitrary objects depending on hook implementation.
- `requests.get(url, allow_redirects=True)` (default) — chases redirects to internal IPs (SSRF).
- `urllib.parse.urljoin(base, user)` — base can be replaced by absolute URL in `user`.
- `lxml.etree.parse(...)` without `parser=etree.XMLParser(resolve_entities=False)`.
- `f"... {user_input} ..."` into a SQL string built for `cursor.execute()`. The `%s` placeholders are correct; f-strings are not.
- `tempfile.mktemp()` — TOCTOU race. Use `tempfile.mkstemp()` or `NamedTemporaryFile`.

### Node / JavaScript

- `child_process.exec(cmd)` — uses shell. Use `execFile` with array args.
- `fs.readFile(path, ...)` — accepts absolute path; no traversal protection.
- `path.join("/safe/", req.body.path)` — `path.join` doesn't validate; `path.resolve` collapses `..`.
- `eval()`, `new Function()`, `vm.runInNewContext()` on user input.
- `JSON.parse` with reviver function that constructs class instances.
- `require(userPath)` — module load from attacker path; `require` cache poisoning.
- `JSON.parse(user)` then accessing `user.__proto__` — prototype pollution chain into Express middleware.
- `merge(a, user)` lodash-style — prototype pollution.
- `fetch(url)` in Node with default agent — no SSRF guard.
- `mongoose.Model.find({id: req.body.id})` — operator injection if `id` is `{$ne: null}`.
- React `dangerouslySetInnerHTML` — name says it.

### Go

- `os/exec.Command(cmd, args...)` — first arg is path, rest are args; no shell. Safe IF `cmd` is not user-controlled.
- `os/exec.Command("sh", "-c", userInput)` — explicitly unsafe.
- `filepath.Join("/safe/", user)` — does NOT clean `..` traversal in the result.
- `filepath.Clean()` after Join, then re-check prefix.
- `template.HTML(userInput)` — bypasses escaping. Use `html/template` and don't cast.
- `text/template` (vs `html/template`) — context-unaware, no auto-escape.
- `net/http.Get(url)` — no redirect cap, no SSRF guard.
- `database/sql` `db.Exec(query, args...)` — args parameterised, query is not. Same trap as Java.
- `gob.Decode` from untrusted source — type confusion.
- `regexp.Compile(userRegex)` — ReDoS surface (Go regex is RE2 so worst case is bounded, but DoS still possible with large input).

### Ruby / Rails

- `eval` / `instance_eval` on user input.
- `Object.send(method)` with user-controlled method name (RCE on `system`).
- `YAML.load` without `safe_load`.
- `Marshal.load` on untrusted source.
- `params.permit(:role)` after `current_user.update(params)` — mass-assignment if `permit` not first.
- `find_by_sql(query)` — string SQL.
- `redirect_to params[:url]` — open redirect.

## How to hunt

1. **Pick the language(s) from Phase 1.**
2. **Grep for each footgun API.**
3. **For every hit, read the call site.** Is the dangerous parameter user-controlled? Trace one or two hops.
4. **fp-check.** Most sharp-edges findings fail Gate 3 (attacker control) or Gate 4 (precondition) — many call sites pass static config, not user input.
5. **Group by API.** A single ACCEPT plus 4 REJECT for the same API is one finding with a sub-table — not five findings.

## Output

Same format as standard findings. Note CWE per sub-class (e.g., CWE-78 for command injection, CWE-22 for path traversal, CWE-918 for SSRF).

## Anti-patterns

- Reporting every `eval()` call as a finding without checking what's passed to it.
- Treating all `os.path.join` calls as findings — most are safe.
- Confusing safe variants with unsafe variants (e.g., `subprocess.run([cmd, arg], shell=False)` is safe; `shell=True` is the trap).
- Reporting `Runtime.exec(String[])` as a string-form misuse — that's the safe form.
- Reporting one finding per call site instead of grouping under the API.
