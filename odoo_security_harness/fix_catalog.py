"""Odoo-idiomatic auto-fix catalog.

Maps rule IDs to concrete, actionable fix recommendations that go beyond
generic "validate input" advice. Each fix cites the Odoo APIs, patterns,
and precedent a developer should use.
"""

from __future__ import annotations

# Access Control
RULE_FIXES: dict[str, str] = {
    # sudo() misuse
    "odoo-deep-sudo-user-input": (
        "Replace `sudo()` with `with_user(self.env.user)` or enforce ownership checks "
        "via `ir.model.access` + `ir.rule` with a `company_id` filter. "
        "If the record must be accessed across companies, use `with_company()` "
        "and verify `env.company_ids` contains the target."
    ),
    "odoo-deep-sudo-route-param": (
        "Never call `sudo().browse(id)` directly from a controller. "
        "Use `env['model'].with_user(request.env.user).browse(id)` "
        "or `_document_check_access(model, id, access_token=token)` for portal routes."
    ),
    "odoo-portal-sudo-route-id-read": (
        "Portal routes reading records through sudo must verify ownership. "
        "Use `env['ir.http']._verify_update_hash()` or `_document_check_access()` "
        "before returning data. Add `access_token` validation for unauthenticated shares."
    ),
    "odoo-portal-route-no-auth": (
        "Add `auth='user'` to the `@http.route` decorator, or if public access is required, "
        "implement `_document_check_access()`, `access_token`, or record-rule ownership checks."
    ),
    "odoo-route-auth-none": (
        "Change `@http.route(..., auth='none')` to `auth='user'` or `auth='public'`. "
        "If the route must remain open, add explicit CSRF checks and ownership validation."
    ),
    "odoo-deep-auth-none-env": (
        "Do not use `env['model'].sudo()` in `auth='none'` routes. "
        "Authenticate the user first or switch to `auth='public'` with portal helpers."
    ),
    # ACL / Record rules
    "odoo-acl-missing-company-filter": (
        "Add `domain_force="
        "[('company_id', 'in', company_ids)]"
        "` to the `ir.rule` record. "
        "For multi-company models, `company_id` must be a required field with a default "
        "of `lambda self: self.env.company.id`."
    ),
    "odoo-acl-public-write": (
        "Remove write access from the public group ACL. "
        "Create a dedicated portal group with `implied_ids` to `base.group_portal` "
        "and limit write permissions to owned records via `ir.rule`."
    ),
    "odoo-acl-public-read-sensitive": (
        "Restrict read access to the sensitive model. "
        "Move the field to a separate model with stricter ACLs, or use "
        'groups="base.group_user" on the field definition.'
    ),
    "odoo-acl-universal-pass": (
        "Remove the `perm_read=True, perm_write=True, perm_create=True, perm_unlink=True` "
        "on the `base.group_user` ACL for this model. "
        "Apply principle of least privilege: only the necessary groups."
    ),
    # XML data groups
    "odoo-xml-privileged-group-missing-admin-users": (
        'Add `<field name="users" eval='
        "[(4, ref('base.user_root')), (4, ref('base.user_admin'))]"
        "/>` "
        "to the `res.groups` XML record to ensure admin users retain access during install."
    ),
    # SQL injection
    "odoo-deep-raw-sql": (
        "Use parameterized queries: `cr.execute('SELECT * FROM table WHERE id=%s', (record_id,))`. "
        "Never interpolate user data into SQL strings. "
        "For dynamic table/column names, use `psycopg2.sql.Identifier()` with a hardcoded allowlist."
    ),
    "odoo-raw-sql-fstring": (
        "Replace f-string interpolation with `%s` placeholders and a tuple argument. "
        "If the query is built dynamically, use `psycopg2.sql.SQL()` with `psycopg2.sql.Literal()`."
    ),
    "odoo-raw-sql-format-string": (
        "Replace `.format()` or `%` formatting with parameterized queries. "
        "Use `cr.execute('... WHERE id = %s', (value,))`. "
        "For IN clauses, use `sql.SQL(',').join(sql.Placeholder() * len(values))`."
    ),
    "odoo-raw-sql-tainted-query": (
        "Move the query to a `tools.sql` helper or use the ORM `search()` / `search_count()`. "
        "If raw SQL is unavoidable, validate all query parts against a hardcoded allowlist."
    ),
    # XSS / Markup
    "odoo-deep-markup-user-input": (
        "Do not pass user input directly to `Markup()`. "
        "Use `html_sanitize()` from `odoo.tools` first, or render via QWeb `t-esc` which auto-escapes. "
        "If HTML formatting is required, escape each user-controlled fragment with `html.escape()`."
    ),
    "odoo-deep-markup-fstring": (
        "Replace `Markup(f'...')` with `Markup('...').format(...)` using explicitly escaped values, "
        "or better, return the data to a QWeb template and use `t-esc` for auto-escaping."
    ),
    "odoo-qweb-t-raw": (
        "Replace `t-raw` with `t-esc` unless the HTML is fully trusted and sanitized. "
        "If rich text is required, use `fields.Html(sanitize=True)` and render via `t-field`."
    ),
    "odoo-deep-html-sanitize-false": (
        "Remove `sanitize=False` from `fields.Html()`. "
        'If the field must store raw HTML for trusted admins, add groups="base.group_system" '
        "on the field and sanitize on display."
    ),
    # Path traversal
    "odoo-controller-path-traversal": (
        "Validate the basename: `filename = os.path.basename(request.params['file'])`. "
        "Restrict to an allowlisted directory: `path = ALLOWED_DIR / filename`. "
        "Block traversal sequences: `if '..' in filename: raise Forbidden()`. "
        "For attachments, use `env['ir.attachment']._check_contents()` or `file_open()`."
    ),
    "odoo-controller-unsafe-send-file": (
        "Use `env['ir.http']._serve_attachment()` or `file_open(module, path)` "
        "instead of `send_file()` with user paths. "
        "If serving static assets, validate the path is under the module's static directory."
    ),
    "odoo-file-upload-tainted-path-read": (
        "Never use user-controlled paths with `open()`. "
        "Store uploads via `env['ir.attachment']` and serve through `_serve_attachment()`. "
        "If filesystem storage is required, use a content-addressable store (SHA-256 filename)."
    ),
    "odoo-file-upload-tainted-path-write": (
        "Write uploads to a temp directory with `tempfile.mkstemp()`, then move to `ir.attachment`. "
        "Never write to paths derived from user input."
    ),
    # Secrets
    "odoo-config-param-hardcoded-sensitive-write": (
        "Remove hardcoded secrets from source code. "
        "Store in `ir.config_parameter` via a setup wizard, or use environment variables "
        "read through `os.environ.get()` with a fallback in `odoo.conf`."
    ),
    "odoo-deep-hardcoded-secret": (
        "Move the secret to an environment variable or `ir.config_parameter`. "
        "Use `env['ir.config_parameter'].get_param('my_module.secret_key')` at runtime. "
        "Rotate the exposed credential immediately."
    ),
    "odoo-api-key-config-parameter-request-secret": (
        "Never store API keys in `ir.config_parameter` if they are user-specific. "
        "Use `res.users.api_key_ids` or a dedicated `api.key` model with per-user scoping."
    ),
    # Controller / Route issues
    "odoo-controller-open-redirect": (
        "Validate redirect URLs against an allowlist or ensure they are local paths. "
        "Use `request.redirect('/local/path')` instead of `request.redirect(user_url)`. "
        "If external redirects are required, check the hostname against a configured allowlist."
    ),
    "odoo-controller-tainted-html-response": (
        "Return data to a QWeb template instead of raw HTML from the controller. "
        "If JSON is required, use `json.dumps()` and set `Content-Type: application/json`."
    ),
    "odoo-controller-cookie-missing-security-flags": (
        "Add `secure=True, httponly=True, samesite='Lax'` to `response.set_cookie()`. "
        "For session cookies, use `samesite='Strict'`."
    ),
    # CSRF
    "odoo-route-csrf-disabled": (
        "Remove `csrf=False` from state-changing routes (POST, PUT, DELETE, PATCH). "
        "If the route is an API endpoint, implement token-based authentication instead."
    ),
    "odoo-route-csrf-ignored-on-mutation": (
        "For browser-backed HTTP routes, remove `csrf=False` and submit Odoo's CSRF token. "
        "For external API or webhook routes, require `auth='bearer'` or verify a signed request with "
        "`hmac.compare_digest()`, restrict methods, and do not rely on the route type or Content-Type as CSRF protection."
    ),
    # Model lifecycle
    "odoo-deep-onchange-database-mutation": (
        "Move database mutations from `@api.onchange` to `@api.model_create_multi` / `write()` overrides, "
        "or use a computed field with `store=True` and `inverse` instead. "
        "Onchange methods should only return warning dicts or domain updates."
    ),
    "odoo-deep-constraint-database-mutation": (
        "Constraints must only raise `ValidationError`, never mutate records. "
        "If pre-validation normalization is needed, override `write()` / `create()` "
        "and call `super()` after sanitizing values."
    ),
    "odoo-deep-monkey-patch-base-model": (
        "Do not monkey-patch `BaseModel` methods. "
        "Use `_inherit` to extend the specific model, or register a model-method override "
        "via `odoo.api` decorators. If framework-wide behavior is required, submit an upstream PR."
    ),
    # Mail / Thread
    "odoo-field-tracking-without-mail-thread": (
        "Add `_inherit = ['mail.thread']` to the model, or remove `tracking=True` from fields. "
        "Tracking requires the `mail.thread` mixin to store change messages."
    ),
    # QWeb
    "odoo-qweb-dynamic-t-component": (
        "Use a literal `t-component` value or validate the component name against an allowlist. "
        "Dynamic component selection can lead to template injection if user data controls the name."
    ),
    "odoo-qweb-fa-icon-missing-label": (
        "Add `aria-label`, `aria-hidden='true'`, or `title` to the `<i>` tag. "
        "Example: `<i class='fa fa-check' aria-label='Completed'/>`"
    ),
    # ORM read
    "odoo-deep-orm-read-empty-fields": (
        "Pass an explicit `fields` list to `read()`: `record.read(['name', 'email'])`. "
        "Empty `read()` fetches all fields including sensitive ones; limit to what the controller needs."
    ),
    "odoo-deep-orm-read-tainted-fields": (
        "Validate the `fields` parameter against a hardcoded allowlist before calling `read()`. "
        "Example: `allowed = {'name', 'email'}; fields = [f for f in requested_fields if f in allowed]`"
    ),
    # getattr/setattr
    "odoo-deep-getattr-setattr-tainted-name": (
        "Do not use `getattr(obj, user_input)` or `setattr(obj, user_input, value)`. "
        "Validate the attribute name against a hardcoded allowlist, or use a `fields_get()` "
        "check to ensure the field exists on the model."
    ),
    # Server actions / eval
    "odoo-server-action-eval": (
        "Replace `eval` context with `model_method` type server actions that call a defined method. "
        "If dynamic logic is required, use `safe_eval` with a restricted builtins dict."
    ),
    "odoo-deep-safe-eval": (
        "Avoid `safe_eval` with user-controlled code. "
        "Use `ast.literal_eval()` for simple data, or refactor to a whitelist of permitted operations."
    ),
    # Integration / HTTP
    "odoo-model-method-onchange-cleartext-http-url": (
        "Change `http://` to `https://`. "
        "If the upstream only supports HTTP, add a configuration flag defaulting to HTTPS "
        "and document the exception."
    ),
    "odoo-model-method-onchange-tls-verify-disabled": (
        "Remove `verify=False` from `requests` calls. "
        "If the upstream uses a self-signed certificate, bundle the CA cert in the module "
        "and pass `verify=ca_bundle_path`."
    ),
    "odoo-model-method-url-embedded-credentials": (
        "Remove credentials from the URL. "
        "Use `requests.get(url, auth=(user, password))` or store credentials in "
        "`ir.config_parameter` / environment variables."
    ),
    # Pickle / Serialization
    "odoo-serialize-pickle-user-input": (
        "Never unpickle user-controlled data. "
        "Use `json.loads()` for data interchange, or `ast.literal_eval()` for trusted Python literals."
    ),
    "odoo-serialize-yaml-unsafe-user-input": (
        "Use `yaml.safe_load()` instead of `yaml.load()`. "
        "If full YAML features are needed, validate the input source is trusted."
    ),
    # Critical: ACL / Access Control
    "odoo-acl-security-model-non-admin": (
        "Restrict the model to admin groups only. "
        "Change the ACL to `group_id=ref('base.group_system')` or a dedicated admin group. "
        "If portal/public users need limited access, create a separate lightweight model."
    ),
    "odoo-acl-public-rule-broad-sensitive": (
        "Narrow the `ir.rule` domain or remove the public group. "
        "Sensitive models should never have broad public read access. "
        "Add `('create_uid', '=', user.id)` or `('company_id', 'in', company_ids)` to the domain."
    ),
    "odoo-acl-public-rule-sensitive-mutation": (
        "Remove write/create/unlink permissions from the public group on this model. "
        "Use portal groups with `ir.rule` ownership filters instead. "
        "Never allow anonymous users to mutate sensitive records."
    ),
    # Critical: AI integration
    "odoo-ai-hardcoded-api-key": (
        "Move the API key to `ir.config_parameter` or an environment variable. "
        "Use `env['ir.config_parameter'].get_param('my_module.ai_key')`. "
        "Rotate the exposed key immediately."
    ),
    # Critical: Deep analyzer
    "odoo-deep-public-sudo-search": (
        "Remove `sudo()` from public routes. "
        "Use `with_user(request.env.user)` and enforce record rules. "
        "If the data must be public, add a dedicated `ir.rule` with a narrow domain."
    ),
    "odoo-deep-public-write-route": (
        "Public routes must not write to the database. "
        "Add `auth='user'` or `auth='portal'`, and verify ownership before any write. "
        "Use `_document_check_access()` for portal-facing mutations."
    ),
    "odoo-deep-request-sudo-write": (
        "Never use `sudo()` with request-derived data for writes. "
        "Validate the record belongs to the current user via `record.check_access_rights('write')` "
        "and `record.check_access_rule('write')` before calling `write()`."
    ),
    "odoo-deep-request-to-sql": (
        "Do not pass request data directly to raw SQL. "
        "Use ORM `search()` / `search_count()` instead. "
        "If raw SQL is unavoidable, use parameterized queries with `cr.execute(query, (param,))`."
    ),
    "odoo-deep-safe-eval-user-input": (
        "Never pass user input to `safe_eval`. "
        "Use `ast.literal_eval()` for simple data structures, or refactor to a whitelist of allowed operations. "
        "If dynamic logic is required, use `model_method` server actions instead."
    ),
    # Critical: Server actions
    "odoo-loose-python-eval-exec": (
        "Replace `eval` / `exec` with `ast.literal_eval()` or a predefined method call. "
        "If dynamic execution is required, use `safe_eval` with a restricted builtins dict "
        "and never include user input in the code string."
    ),
    # Critical: Publication
    "odoo-publication-public-route-mutation": (
        "Publication fields (`website_published`, `is_published`) must not be toggled by public routes. "
        "Require authentication and verify the user owns the record or has publisher rights. "
        "Add `groups` attribute to the field or gate mutations through `check_access_rights()`."
    ),
    # High: ACL / Access Control
    "odoo-acl-global-read-sensitive": (
        "Remove the global read ACL on the sensitive model. "
        "Assign a specific group and add `ir.rule` with `company_id` or owner scope."
    ),
    "odoo-acl-rule-sensitive-unlink": (
        "Remove unlink permission from broad groups on sensitive models. "
        "Limit unlink to admin groups or add `('create_uid', '=', user.id)` domain rules."
    ),
    "odoo-acl-sensitive-unlink": (
        "Restrict unlink access to the model. "
        "Use `perm_unlink=False` on broad group ACLs and grant it only to a dedicated admin group."
    ),
    "odoo-acl-sensitive-write": (
        "Restrict write access to the sensitive model. "
        "Use `perm_write=False` on broad group ACLs and add `ir.rule` with ownership filters."
    ),
    # High: AI integration
    "odoo-ai-tainted-prompt": (
        "Sanitize user input before including it in AI prompts. "
        "Use a templating system with explicit variable substitution and validate each variable "
        "against an allowlist of permitted content."
    ),
    "odoo-ai-unsanitized-output": (
        "Treat AI-generated output as untrusted. "
        "Run HTML output through `html_sanitize()` before rendering in QWeb. "
        "For text output, use `t-esc` instead of `t-raw`."
    ),
    # High: Deep analyzer
    "odoo-deep-attachment-sudo-access": (
        "Do not use `sudo()` to access attachments. "
        "Use `env['ir.attachment']._check_contents()` or `with_user(request.env.user)` "
        "and verify the user has read access via record rules."
    ),
    "odoo-deep-empty-search-sudo": (
        "Empty `search([])` with `sudo()` returns all records bypassing access control. "
        "Add a domain filter or remove `sudo()` and rely on `ir.rule` scoping."
    ),
    "odoo-deep-html-sanitize-relaxed-option": (
        "Avoid `sanitize_tags=False` or `sanitize_attributes=False` on `fields.Html()`. "
        "If the field must allow rich content, use `fields.Html(sanitize=True)` "
        "and validate allowed tags/attributes in the frontend."
    ),
    "odoo-deep-mass-assignment": (
        "Whitelist fields before passing request data to `write()` or `create()`. "
        "Example: `allowed = {'name', 'email'}; vals = {k: v for k, v in data.items() if k in allowed}`. "
        "Never pass `request.params` or `kwargs` directly to ORM write methods."
    ),
    "odoo-deep-portal-idor-sudo-browse": (
        "Remove `sudo()` from portal record lookups. "
        "Use `env['model'].with_user(request.env.user).browse(id)` "
        "or `_document_check_access(model, id, access_token=token)`."
    ),
    "odoo-deep-public-sudo": (
        "Remove `sudo()` from public-facing code paths. "
        "Authenticate the user and enforce access control via `ir.model.access` and `ir.rule`."
    ),
    "odoo-deep-route-id-sudo-browse": (
        "Controller routes must not use `sudo().browse(id)` directly. "
        "Use `with_user(request.env.user).browse(id)` and verify access with `check_access_rights('read')`."
    ),
    "odoo-deep-sql-built-query-var": (
        "Do not build SQL by concatenating variables. "
        "Use `cr.execute('SELECT ... WHERE id=%s', (value,))` or ORM `search()`. "
        "For dynamic identifiers, use `psycopg2.sql.Identifier()` with a hardcoded allowlist."
    ),
    "odoo-deep-sql-concat": (
        "Replace string concatenation in SQL with parameterized queries. "
        "Use `%s` placeholders and a tuple of values passed to `cr.execute()`."
    ),
    "odoo-deep-sql-format": (
        "Replace `.format()` in SQL strings with `%s` placeholders. "
        "Use `cr.execute('SELECT ... WHERE id=%s', (value,))`."
    ),
    "odoo-deep-sql-fstring": (
        "Replace f-string interpolation in SQL with `%s` placeholders. "
        "Use `cr.execute('SELECT ... WHERE id=%s', (value,))`."
    ),
    "odoo-deep-sql-percent": (
        "Replace `%` string formatting in SQL with `%s` placeholders. "
        "Use `cr.execute('SELECT ... WHERE id=%s', (value,))`."
    ),
    "odoo-deep-tainted-search-domain": (
        "Validate and normalize domains before use. "
        "Use `expression.normalize_domain()` and `expression.AND()` / `expression.OR()`. "
        "Whitelist field names against `model.fields_get().keys()`."
    ),
    # High: Server actions
    "odoo-loose-python-sensitive-model-mutation": (
        "Server actions mutating sensitive models must be restricted to admin groups. "
        "Add `groups_id` to the `ir.actions.server` record referencing `base.group_system`."
    ),
    "odoo-loose-python-sql-injection": (
        "Do not construct SQL with string operations in server actions. "
        "Use ORM methods or parameterized `cr.execute()` with placeholder tuples."
    ),
    "odoo-loose-python-sudo-method-call": (
        "Avoid `sudo()` in server action Python code. "
        "If elevated access is required, create a dedicated model method with `groups='base.group_system'` "
        "and call that method instead."
    ),
    "odoo-loose-python-sudo-write": (
        "Do not use `sudo().write()` in server action Python code. "
        "Use `with_user(request.env.user)` and validate access rights before writing."
    ),
    "odoo-loose-python-tls-verify-disabled": (
        "Remove `verify=False` from `requests` calls in server actions. "
        "Bundle the CA certificate in the module and pass `verify=ca_bundle_path`."
    ),
    "odoo-loose-python-url-embedded-credentials": (
        "Remove credentials from URLs in server action code. "
        "Use `requests.get(url, auth=(user, password))` with credentials from `ir.config_parameter`."
    ),
    # High: Multi-company
    "odoo-mc-sudo-search-no-company": (
        "Multi-company searches with `sudo()` must include a company filter. "
        "Add `('company_id', 'in', company_ids)` to the domain, or use `with_company()` "
        "and verify `env.company_ids` contains the target."
    ),
    # High: Publication
    "odoo-publication-sensitive-default-published": (
        "Remove `default=True` from publication fields on sensitive models. "
        "Set `default=False` and require explicit approval before publishing."
    ),
    "odoo-publication-sensitive-runtime-published": (
        "Runtime publication of sensitive records must require authentication. "
        "Gate `write({'is_published': True})` through `check_access_rights('write')` "
        "and a dedicated publisher group."
    ),
    # High: QWeb / XSS
    "odoo-qweb-dynamic-event-handler": (
        "Do not use dynamic `t-on-*` event handler names. "
        "Use literal event names or validate against an allowlist of permitted handlers."
    ),
    "odoo-qweb-dynamic-script-src": (
        "Do not use dynamic `t-att-src` on `<script>` tags. "
        "Use a hardcoded allowlist of script URLs or serve scripts from the module's static directory."
    ),
    "odoo-qweb-iframe-sandbox-escape": (
        "Remove `allow-same-origin` or `allow-scripts` from the iframe sandbox if both are present. "
        "This combination allows the iframe to break out of sandbox restrictions."
    ),
    "odoo-qweb-js-url": (
        "Do not use user-controlled data in `<script>` tag URLs. "
        "Validate the URL against a hardcoded allowlist or use relative paths to the module's static files."
    ),
    "odoo-qweb-raw-output-mode": (
        "Avoid rendering raw HTML in QWeb. "
        "Use `t-esc` for auto-escaping, or `fields.Html(sanitize=True)` with `t-field`. "
        "If raw HTML is required, sanitize with `html_sanitize()` first."
    ),
    "odoo-qweb-script-expression-context": (
        "Do not pass user data into `<script>` tag content via QWeb expressions. "
        "Use `t-esc` for JSON data inside `<script type='application/json'>` blocks."
    ),
    "odoo-qweb-sensitive-field-render": (
        "Sensitive fields rendered in QWeb must use `t-esc` or `t-field`, not `t-raw`. "
        "If the field contains HTML, ensure it uses `fields.Html(sanitize=True)`."
    ),
    "odoo-qweb-srcdoc-html": (
        "Sanitize `srcdoc` HTML content before rendering. "
        "Use `html_sanitize()` from `odoo.tools` to strip dangerous tags and attributes."
    ),
    "odoo-qweb-url-embedded-credentials": (
        "Remove credentials from URLs in QWeb templates. "
        "Use environment variables or `ir.config_parameter` for authentication."
    ),
    # High: UI exposure
    "odoo-ui-sensitive-menu-external-groups": (
        "Restrict sensitive menu items to internal groups only. "
        "Add `groups='base.group_user'` to the `<menuitem>` record or inherit from a secure parent menu."
    ),
    # High: Website form
    "odoo-website-form-route-csrf-disabled": (
        "Remove `csrf=False` from website form submission routes. "
        "Odoo's website form controller handles CSRF automatically; disabling it allows cross-site form submissions."
    ),
    "odoo-website-form-sanitize-disabled": (
        "Enable HTML sanitization on website form fields. "
        "Set `sanitize=True` on `fields.Html()` or use `html_sanitize()` before storing user-submitted HTML."
    ),
    # Medium: ACL / Access Control
    "odoo-acl-global-write": (
        "Remove global write ACLs. " "Assign specific groups and add `ir.rule` with ownership or company filters."
    ),
    "odoo-acl-missing-sensitive": (
        "Add an ACL for the sensitive model. "
        "At minimum define `perm_read=True` for a restricted group and `perm_write=False` for broad groups."
    ),
    # Medium: Deep analyzer
    "odoo-deep-csrf-write": (
        "For browser-backed state changes, remove `csrf=False` and submit Odoo's CSRF token. "
        "For non-browser APIs and webhooks, use bearer authentication or verify an HMAC signature with "
        "`hmac.compare_digest()`; changing the route type does not provide CSRF protection."
    ),
    "odoo-deep-field-compute-sudo": (
        "Avoid `sudo()` in computed fields. "
        "Use `compute_sudo=True` on the field definition if cross-user computation is required, "
        "or refactor to store the data on a related record accessible through normal access control."
    ),
    "odoo-deep-html-sanitize-strict-false": (
        "Do not disable HTML sanitization. "
        "Keep `sanitize=True` on `fields.Html()`. If specific tags are needed, use `sanitize_tags` and `sanitize_attributes` "
        "instead of disabling sanitization entirely."
    ),
    "odoo-deep-orm-read-no-fields": (
        "Pass an explicit `fields` list to `read()`. "
        "Example: `record.read(['name', 'email'])`. Empty `read()` fetches all fields including sensitive ones."
    ),
    "odoo-deep-with-user-admin": (
        "Do not use `with_user(SUPERUSER_ID)` or `with_user(admin)` in public code paths. "
        "Use `with_user(request.env.user)` and enforce record rules. If admin access is required, gate it behind `check_access_rights()`."
    ),
    # Medium: Server actions
    "odoo-loose-python-cleartext-http-url": (
        "Change `http://` to `https://` in server action code. "
        "If the upstream only supports HTTP, add a configuration flag defaulting to HTTPS."
    ),
    "odoo-loose-python-http-no-timeout": (
        "Add `timeout=` to all `requests` calls in server actions. "
        "Example: `requests.get(url, timeout=30)`. Set a reasonable default to prevent resource exhaustion."
    ),
    "odoo-loose-python-manual-transaction": (
        "Use the ORM's automatic transaction management instead of manual `cr.commit()`. "
        "If a separate transaction is required, use `self.env.cr.savepoint()` with proper exception handling."
    ),
    # Medium: Multi-company
    "odoo-mc-check-company-disabled": (
        "Re-enable `check_company=True` on the relational field. "
        "If cross-company references are required, validate the target company is in `env.company_ids`."
    ),
    "odoo-mc-company-context-user-input": (
        "Do not allow user input to control `allowed_company_ids` or `company_id` in the context. "
        "Use `with_company()` with validated company IDs from the user's `company_ids`."
    ),
    "odoo-mc-missing-check-company": (
        "Add `check_company=True` to relational fields on multi-company models. "
        "This prevents users from linking records across unauthorized companies."
    ),
    "odoo-mc-rule-missing-company": (
        "Add an `ir.rule` with `domain_force=[('company_id', 'in', company_ids)]` to the model. "
        "Multi-company models must enforce company scoping at the record-rule level."
    ),
    "odoo-mc-with-company-user-input": (
        "Validate the company ID before calling `with_company()`. "
        "Ensure the requested company is in `request.env.user.company_ids` to prevent cross-company access."
    ),
    # Medium: Migration
    "odoo-migration-missing-lifecycle-hook": (
        "Add `pre_init_hook`, `post_init_hook`, or `uninstall_hook` to the manifest for data migration safety. "
        "Use these hooks to validate prerequisites and clean up external data on uninstall."
    ),
    # Medium: QWeb
    "odoo-qweb-dangerous-tag": (
        "Avoid rendering dangerous HTML tags (`script`, `iframe`, `object`, `embed`) from user data. "
        "Use `html_sanitize()` to strip dangerous tags, or validate against an allowlist."
    ),
    "odoo-qweb-dynamic-style-attribute": (
        "Do not use dynamic `t-att-style` with user-controlled data. "
        "Use static CSS classes or validate each style property against an allowlist."
    ),
    "odoo-qweb-dynamic-stylesheet-href": (
        'Do not use dynamic `t-att-href` on `<link rel="stylesheet">` tags. '
        "Use hardcoded stylesheet URLs from the module's static directory."
    ),
    "odoo-qweb-dynamic-t-call": (
        "Validate the template name in dynamic `t-call` against an allowlist. "
        "Never pass user input directly as a `t-call` target."
    ),
    "odoo-qweb-external-script-missing-sri": (
        "Add `integrity` attribute with a SHA-384 hash to external `<script>` tags. "
        'Use `crossorigin="anonymous"` to ensure the integrity check works with CORS.'
    ),
    "odoo-qweb-html-widget": (
        "Ensure HTML widgets render sanitized content. "
        "Use `fields.Html(sanitize=True)` for stored HTML, and `t-esc` for plain text output."
    ),
    "odoo-qweb-iframe-broad-permissions": (
        "Restrict iframe `allow` attribute to only required permissions. "
        'Avoid `allow="*"` or broad permission lists; enumerate only what is necessary.'
    ),
    "odoo-qweb-iframe-missing-sandbox": (
        "Add `sandbox` attribute to `<iframe>` tags. "
        'Use the most restrictive sandbox value that still allows functionality, e.g., `sandbox="allow-scripts"`.'
    ),
    "odoo-qweb-inline-event": (
        "Remove inline event handlers (`onclick`, `onload`, etc.) from QWeb templates. "
        "Use Odoo's event delegation in JavaScript widgets instead."
    ),
    "odoo-qweb-insecure-asset-url": (
        "Use HTTPS for all asset URLs. "
        "Replace `http://` with `https://` in `<script>`, `<link>`, and `<img>` src attributes."
    ),
    "odoo-qweb-markup-escape-bypass": (
        "Do not bypass Markup escaping with concatenation. "
        "Use `html.escape()` on user-controlled fragments before including them in Markup."
    ),
    "odoo-qweb-post-form-missing-csrf": (
        "Add CSRF token to custom POST forms. "
        'Use `<input type="hidden" name="csrf_token" t-att-value="request.csrf_token()"/>`.'
    ),
    "odoo-qweb-sensitive-url-token": (
        "Do not expose sensitive tokens in URLs rendered by QWeb. "
        "Use POST forms or HTTP headers for authentication tokens instead of query parameters."
    ),
    "odoo-qweb-t-att-url": (
        "Validate URLs in dynamic `t-att-href` or `t-att-src` attributes. "
        "Use a hardcoded allowlist or ensure the URL starts with `/` or a trusted domain."
    ),
    "odoo-qweb-t-js-inline-script": (
        "Do not render inline JavaScript via QWeb `t-js` or `t-set` blocks. "
        "Move JavaScript logic to static JS files and use Odoo's module system."
    ),
    "odoo-qweb-target-blank-no-noopener": (
        'Add `rel="noopener noreferrer"` to links with `target="_blank"`. '
        "This prevents the opened page from accessing `window.opener`."
    ),
    # Medium: UI exposure
    "odoo-ui-sensitive-menu-no-groups": (
        "Add `groups` attribute to sensitive menu items. "
        "Use `groups='base.group_user'` or a more specific group to restrict access."
    ),
    # Low: ACL
    "odoo-acl-rule-no-groups": (
        "Add a `group_id` to the `ir.rule` record, or explicitly set `global=True` if the rule is intended to be global. "
        "Global rules without groups apply to all users including portal and public."
    ),
    # Low: Multi-company
    "odoo-mc-search-no-company": (
        "Add `('company_id', 'in', company_ids)` to search domains on multi-company models. "
        "Or use `with_company()` to scope the search to the active company."
    ),
    # Low: QWeb
    "odoo-qweb-dynamic-class-attribute": (
        "Validate dynamic CSS class names against an allowlist. "
        "Avoid directly embedding user input in `t-att-class` to prevent CSS injection."
    ),
    "odoo-qweb-external-stylesheet-missing-sri": (
        'Add `integrity` attribute with a SHA-384 hash to external `<link rel="stylesheet">` tags. '
        'Use `crossorigin="anonymous"` to ensure the integrity check works with CORS.'
    ),
}


def get_fix_for_rule(rule_id: str) -> str | None:
    """Return the Odoo-idiomatic fix text for a rule ID, or None if not catalogued."""
    return RULE_FIXES.get(rule_id)
