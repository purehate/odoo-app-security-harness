# Insecure Defaults — Config-Level Bug Class

Bug class: software ships with a default configuration that is exploitable, and the application doesn't override it. Dataflow tools (CodeQL, Semgrep dataflow) usually miss these because the dangerous behaviour is **absent code** (a hardening flag was never set), not a tainted-flow path.

Hunters #6 (Crypto), #7 (Business Logic), #8 (External Interfaces) own pieces of this. Insecure-defaults is a focused pass that runs as part of Phase 1.5 / Phase 2 to catch what the dataflow agents skip.

## Common Insecure Defaults (Audit Checklist)

### Web frameworks

- **Spring Boot**: `server.error.include-stacktrace=always`, `management.endpoints.web.exposure.include=*`, default H2 console exposed on `/h2-console`, default actuator endpoints (`/env`, `/heapdump`, `/threaddump`) without auth.
- **Django**: `DEBUG=True` in production, `ALLOWED_HOSTS=['*']`, `SECRET_KEY` from default settings.
- **Express/Node**: missing `helmet()`, `app.disable('x-powered-by')` not set, default `cookie-session` without `secure`/`httpOnly`.
- **Next.js**: API routes without explicit auth middleware, default ISR cache bypass exposed.
- **FastAPI**: docs (`/docs`, `/redoc`) exposed in production, default `allow_origins=["*"]` on CORSMiddleware.

### Odoo

Server config (`odoo.conf`):

- `list_db = True` (default) — `/web/database/manager` reachable; database listing + drop/duplicate UI exposed if `admin_passwd` weak.
- `admin_passwd = admin` (default placeholder) — master password unchanged in `odoo.conf`.
- `dbfilter` empty — any database name acceptable via Host header → cross-DB confusion in multi-tenant.
- `proxy_mode = False` while behind nginx — `request.httprequest.remote_addr` is the proxy IP; rate limiting / IP audit useless. Inverse: `proxy_mode = True` without trusted proxy → attacker spoofs `X-Forwarded-For`.
- `log_level = debug` in production — leaks tracebacks, SQL, cookies in logs.
- `log_handler = ":DEBUG"` on `werkzeug` or `odoo.sql_db` — request bodies and SQL with parameters in logs.
- `unaccent = False` while DB has `unaccent` extension — `ilike` searches inconsistent (perf, not security).
- `workers = 0` (single-process) accepted on production — prevents `--workers` based isolation; not a vuln directly but indicates dev config in prod.

System parameters (`ir.config_parameter`):

- `web.base.url` not pinned + `web.base.url.freeze = False` — Host header injection sets `web.base.url`, then password-reset emails leak attacker URLs.
- `database.uuid` / `database.secret` exposed via debug pages or `auth='public'` controllers — session signing baseline.
- `auth_signup.invitation_scope = b2c` — anyone can self-register; verify intended.
- `auth_signup.allow_uninvited = True` — same.
- `auth_oauth.allow_signup = True` with public OAuth providers — automatic account creation.

Module data:

- `base.user_admin` / `base.user_root` password not rotated post-install (`admin/admin`).
- `base.group_public` granted unintended `implied_ids` via custom module — anonymous users gain authenticated-user perms.
- `base.group_portal` granted broad CRUD on internal models (`ir.model.access.csv` row).
- `mail.mail_channel.allow_public_users = True` — anonymous users can read internal channels.

Deployment:

- `--load=base,web` only on production (default `--load=base,web,session_store_*`) — sessions in memory, scaling/security regression.
- `--db-filter` not aligned with hostname → cross-database confusion.
- Reverse-proxy not stripping `X-Odoo-Dbfilter-*` request headers.
- `static/` served by Odoo (default) instead of nginx — log poisoning via crafted filenames possible.

### XML/parser libraries

- `DocumentBuilderFactory.newInstance()` without `setFeature(FEATURE_SECURE_PROCESSING, true)`.
- `SAXParserFactory` without `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`.
- `XMLInputFactory` with `IS_SUPPORTING_EXTERNAL_ENTITIES=true` (default in some libs).
- `SchemaFactory` without secure processing. Schema parser is often configured separately from source parser — both need hardening.

### TLS / HTTP clients

- `HttpClient` / `RestTemplate` accepting all hostnames (`NoopHostnameVerifier`).
- `OkHttpClient.Builder()` without `.followRedirects(false)` when handling user URLs.
- Default `TrustManager` accepts any cert (test fixtures bleeding into prod).
- HTTP/2 client without ALPN or with downgrade-on-error tolerated.

### Crypto libraries

- `Cipher.getInstance("AES")` (defaults to ECB on most providers).
- `MessageDigest.getInstance("MD5")` / `SHA-1` for security purposes.
- `SecureRandom.getInstance("SHA1PRNG")` on legacy JVMs (use default constructor).
- `KeyPairGenerator.initialize()` defaulting to 1024-bit RSA on old JCE.

### CI/CD & supply chain

- GitHub Actions: `permissions:` not declared (defaults to write-all on org level).
- Default `branch protection` allowing force-push to main on personal forks of internal mirror.
- Docker base images: `latest` tag, no `USER` directive (runs as root by default).
- Helm charts: `securityContext` not set; pod runs as root.

### Cloud / IaC

- S3 bucket without `Block Public Access` (default off when created via SDK before 2023).
- IAM role trust policy with `Principal: "*"` from copy-pasted templates.
- Default SG `0.0.0.0/0:22` from Terraform examples.
- DynamoDB tables without encryption-at-rest until 2018 default flipped.

### Auth / session

- Spring Security `csrf().disable()` left in for an API that takes cookies.
- `SameSite` default unset on session cookies (browsers default to `Lax` but server should be explicit).
- JWT libs with `algorithms=None` accepted on the verify path.
- OAuth2 `state` parameter validation not enforced because the default config didn't set it.

## How to hunt

1. **Inventory every framework / library** from Phase 1 manifest reads.
2. **For each, list its known insecure defaults** (use the checklist plus framework-specific advisories).
3. **Search the repo for the override** that would harden it. Absence = potential finding.
4. **Confirm exposure** — does the app ship with the unhardened component reachable in production?
5. **fp-check** the finding through the 6 gates. Many insecure-default findings fail Gate 4 (precondition) because the unhardened component is dev-only or behind a flag — that's DOWNGRADE, not REJECT.

## Output format

Same format as a standard finding. Note `CWE-1188 (Insecure Default Initialization)` or class-specific CWE.

## Anti-patterns

- Listing every documented "secure default" override that's missing without confirming the unhardened component is reachable.
- Reporting the framework's own example config as a vuln in this codebase.
- Confusing "default behaviour changed in v2" with "the project is on v2 — old default no longer applies".
- Reporting `DEBUG=True` in `settings_local.py.example` as a finding without checking which file the deploy actually uses.
