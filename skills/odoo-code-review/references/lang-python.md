# Language Patterns — Python

Generic Python AppSec patterns. For Odoo-specific framework misuse see `lang-odoo.md`. For QWeb templating sinks see `lang-qweb.md`.

## Web Frameworks

### Django

- **`{% autoescape off %}`** — XSS. Hunt template files.
- **`mark_safe`** in views — same.
- **`extra(where=[...])`, `raw()`** with format strings — SQL injection.
- `QuerySet.filter(**user_dict)` — query parameter injection if user controls keys.
- `request.GET.get('next')` used in redirect — open redirect. `django.utils.http.url_has_allowed_host_and_scheme` to validate.
- `django.contrib.auth` `set_password` not called on user creation flow — passwords stored plain (rare but checked).
- CSRF middleware — verify `@csrf_exempt` is justified per view.
- `ALLOWED_HOSTS = ['*']` in prod = host header injection.
- `DEBUG = True` in prod = data exposure on error pages.
- File uploads via `FileField` — `upload_to` callable using user input → traversal.

### Flask

- `request.form['field']` raw into SQL → injection.
- Jinja2 with `Markup()` on user content → XSS.
- `render_template_string(user)` — SSTI → RCE.
- `send_file(path)` with user-controlled path → traversal.
- `flask_cors.CORS(app, origins="*")` with `supports_credentials=True` → ATO.

### FastAPI

- Pydantic models validate by default — main XSS/injection risks live in handler logic, not parsing.
- `Depends()` chain order — auth dependency ordered after data-load dependency = info leak.
- Response models — `response_model` strips fields, but logging the raw object before response leaks.
- WebSocket endpoints — auth via `WebSocket.cookies` or query param, easy to forget.

### Werkzeug (used by Flask, Odoo)

- Debugger PIN bypass (CVE history) — `WERKZEUG_DEBUG_PIN` or `werkzeug.debug.console.Console` reachable via `/console`.
- `secure_filename` — strips `..` but keeps Unicode tricks; not a full sanitizer.
- `redirect(target_url, code=302)` with attacker `target_url` — open redirect.

## Database / ORM

### SQLAlchemy

- `session.execute(text(f"SELECT ... {user}"))` = SQL injection.
- `session.query(User).filter(User.id == request.args['id'])` safe via SQLA's parameterization.
- `Sort` direction from user — `desc(getattr(User, request.args['col']))` lets attacker pick any column.
- `text()` constructs are not auto-parameterized — `text("WHERE id = :id").bindparams(id=user_id)` is safe; `text(f"WHERE id = {user_id}")` is not.

### psycopg2 / psycopg3

- `cursor.execute("SELECT ... %s", (val,))` — safe.
- `cursor.execute("SELECT ... %s" % val)` — string formatting, NOT parameterised. Injection.
- `cursor.execute(f"SELECT ... {val}")` — same trap.
- Identifier quoting: `psycopg2.sql.Identifier` for table/column names; never f-string.

## Crypto / Auth

- `hashlib.md5/sha1` for passwords = bad. Use `passlib`, `argon2-cffi`, or `bcrypt`.
- `secrets.token_urlsafe(32)` good. `random.random()` / `random.choice()` for security tokens = bad (Mersenne Twister, predictable).
- `jwt` (PyJWT) — `decode(token, key, algorithms=['HS256'])` required in 2.x; default failures in 1.x.
- `cryptography` library — `Fernet` for symmetric, good defaults. Avoid raw `Cipher` unless you know what you're doing.
- `hmac.compare_digest` for token comparison; `==` is timing-side-channel.
- `Crypto` (PyCryptodome) — verify mode (ECB → AES.MODE_ECB is bad), IV reuse on CBC.

## Deserialization

- `pickle.load`, `pickle.loads`, `cPickle.loads` on untrusted = RCE. Banned.
- `yaml.load` without `Loader=SafeLoader` = RCE. PyYAML 6+ defaults to `FullLoader` which is also dangerous on untrusted input.
- `marshal.load` — same risk.
- `xml.etree.ElementTree`, `lxml` — use `defusedxml` for untrusted XML to prevent XXE / billion-laughs.
- `shelve` is pickle under the hood — never load attacker shelve files.

## Process / Filesystem

- `subprocess.run(cmd, shell=True)` with user input = command injection.
- `subprocess.run([cmd, arg], shell=False)` — safe IF `cmd` is not user-controlled.
- `os.system`, `os.popen` — same trap as `shell=True`.
- `eval`, `exec`, `compile` on user input = RCE. Period.
- `open(user_path)` traversal — use `os.path.realpath` and prefix check (`startswith(base)` after `realpath`).
- `shutil.copy`, `shutil.move` with user paths — same.
- `os.walk` rooted at user path — symlink follow defaults to `True`; can escape root.
- `tempfile.mktemp()` — TOCTOU race. Use `tempfile.mkstemp()` or `NamedTemporaryFile`.

## Templating SSTI

- Jinja2: `{{ config.items() }}`, `{{ self.__class__.__mro__[1].__subclasses__() }}` style payloads.
- Django templates are safer (sandboxed) but `{% include user_template %}` with user input → template inclusion.
- Mako, Genshi: same SSTI surface as Jinja.
- `string.Template` — limited substitution, but `Template(user).safe_substitute(env)` exposes `env` keys.

## HTTP Clients

- `requests.get(url, verify=False)` = MITM. Banned.
- `requests.get(url)` with no timeout — hang surface, but also SSRF amplification (slow loris on caller).
- `urllib.request.urlopen(url)` — same SSRF surface, no SSL verify control on older versions.
- `httpx.AsyncClient(verify=False)` — same as requests.
- `Session()` with user-controlled URL = SSRF. Combine with cloud metadata reachable = creds.
- `boto3` — verify region/endpoint not from user. SSRF via custom endpoint.

## Ecosystem-Specific Notes

- **Celery** — task arg deser. If broker is Redis/RabbitMQ exposed, attacker can inject tasks. `pickle` serializer banned. Use `json` serializer.
- **Pillow** — image parser. Old versions had RCEs. Verify version.
- **xlrd / openpyxl** — XLS / XLSX parsers. `xlrd` 2.0+ dropped XLSX support; older versions had macro/format CVEs.
- **lxml** — disable network access on parser (`no_network=True`), disable entity resolution (`resolve_entities=False`).
- **pymongo** — operator injection if attacker can inject `{"$ne": null}` or similar via JSON parse → query.

## Sharp Edges (Python-Specific)

See also `sharp-edges.md` Python section. Highlights:

- `subprocess.run(cmd, shell=True)` with f-string = injection.
- `os.path.join("/safe/", user)` — absolute path in `user` replaces prefix.
- `pathlib.Path(user).resolve()` follows symlinks; can escape root.
- `pickle.loads()` on any non-locally-generated, non-signed data.
- `f"... {user_input} ..."` into SQL string built for `cursor.execute()`.
- `tempfile.mktemp()` — TOCTOU.
- `urllib.parse.urljoin(base, user)` — `user` can be absolute and replace base.

## Versions to Flag (April 2026)

- Django < 4.2 — multiple CVEs.
- Flask < 3.0 — review CVE list.
- Werkzeug < 3.0 — debug PIN issues, redirect issues.
- Pillow < 10.3 — image parser RCEs.
- requests < 2.32 — verify TLS hostname behaviors.
- urllib3 < 2.2.2 — redirect / cert validation.
- cryptography < 42.0.4 — TLS state machine.
- PyJWT < 2.4 — `algorithms` argument default fails open.
- PyYAML < 6.0 — `yaml.load` default unsafe.
- lxml < 5.2 — XXE in some parsers.
- pip < 23.3 — wheel install pre-verify issues (supply chain).

## Audit Greps

```bash
# Eval / exec
grep -rn 'eval(' --include='*.py' . | grep -v test
grep -rn 'exec(' --include='*.py' . | grep -v test
grep -rn 'compile(' --include='*.py' . | grep -v 're.compile'

# Shell injection
grep -rn 'shell=True' --include='*.py' .
grep -rn 'os\.system\|os\.popen' --include='*.py' .

# Pickle / yaml
grep -rn 'pickle\.loads\?' --include='*.py' .
grep -rn 'yaml\.load(' --include='*.py' . | grep -v 'safe_load\|SafeLoader'

# SQL string construction
grep -rn '\.execute(.*%' --include='*.py' .
grep -rn '\.execute(f["\']' --include='*.py' .

# SSL verify off
grep -rn 'verify=False' --include='*.py' .

# Weak random
grep -rn 'random\.\(choice\|random\|randint\)' --include='*.py' . | grep -iE 'token|secret|password|key|salt'
```

## Anti-Patterns (Hunter Output)

- "Uses `requests` library" — not a finding. Find the call site that takes user URL.
- "`pickle` is unsafe" — only when called on attacker-controlled data.
- "Missing input validation on Pydantic field" — Pydantic validates types by default; finding requires showing the type accepts attacker input that bypasses business invariants.
- Reporting `random.random()` without checking what value is used for. RNG matters in security context only.
