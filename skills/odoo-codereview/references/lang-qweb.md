# Language Patterns — QWeb (Odoo Templating)

QWeb is Odoo's XML-based templating engine. Two flavours:

- **Server-side QWeb** — rendered by Python on request (controllers, reports, mail templates, website pages).
- **OWL / client-side QWeb** — rendered in the browser by the OWL framework (web client UI).

Both are XSS surfaces. Different sinks, different escapes, different bug shapes.

Pair this file with `lang-odoo.md` (controllers, mail, attachments) and `lang-python.md` (Werkzeug, Markup).

## Server-Side QWeb

Templates live in:

- `views/*.xml` — UI views, often `<template>` elements.
- `data/*.xml` — mail templates, report templates.
- `report/*.xml` — PDF/HTML reports.

### Escaping Defaults

| Directive         | Escaped?                | Notes                                                                                          |
| ----------------- | ----------------------- | ---------------------------------------------------------------------------------------------- |
| `t-esc="expr"`    | YES                     | HTML-escapes the rendered string.                                                              |
| `t-out="expr"`    | YES (Odoo 14+)          | Newer alias for `t-esc`. Same escape.                                                          |
| `t-raw="expr"`    | NO                      | Inserts raw HTML. **Bug surface.** Removed in newer Odoo, replaced by `t-out` with `Markup()`. |
| `t-att-X="expr"`  | YES (attribute-context) | Sets attribute X. Properly attribute-escaped.                                                  |
| `t-attf-X="..."`  | YES (attribute-context) | Format-string attribute set; same escape as `t-att`.                                           |
| `t-field="rec.f"` | depends on field type   | `Html` field type renders raw — same risk as `t-raw`.                                          |
| `t-foreach`       | n/a                     | Iteration; safety depends on body.                                                             |
| `t-call="tpl"`    | n/a                     | Inline another template. Safety depends on what `tpl` does.                                    |

### Sinks That Bite

#### `t-raw` / `t-out` with `Markup()`

```xml
<div t-raw="record.body"/>                  <!-- raw HTML -->
<div t-out="Markup(record.body)"/>          <!-- equivalent escape bypass -->
```

If `record.body` is user-controlled (forum post, chatter message, free text), this is stored XSS.

Hunt:

```bash
grep -rn 't-raw=' --include='*.xml' .
grep -rn 'Markup(' --include='*.py' --include='*.xml' .
grep -rn 't-out=' --include='*.xml' . | grep -i markup
```

Common safe uses to ignore:

- `t-raw="0"` — render the t-call body. Safe (no user data).
- `t-raw` on a hardcoded constant.
- `t-raw` on a server-rendered chunk that itself was assembled with `t-esc` — verify by reading the chunk source.

#### `t-field` on `Html` fields

```xml
<div t-field="record.body"/>
```

If `record.body` has `widget="html"` (or the field is `fields.Html()`), it renders raw. Same XSS risk as `t-raw`. The HTML sanitizer (`odoo.tools.html_sanitize`) runs on **write**, not on render — so legacy unsanitized data, or `sudo()` writes that bypass the sanitizer, leak through.

Hunt:

- `fields.Html(sanitize=False)` — allows raw HTML stored.
- `fields.Html(sanitize_attributes=False)` — allows `onclick=` and friends.
- `tools.html_sanitize(text, strict=False)` followed by storage — `strict=False` keeps more tags.
- `sanitize_form` parameter — turning off form sanitization. Verify usage.

#### Attribute injection via `t-att-href`

```xml
<a t-att-href="record.url">click</a>
```

QWeb attribute-escapes the value, so `"><script>` becomes `&quot;&gt;&lt;script&gt;`. Safe.

But:

```xml
<a t-attf-onclick="doThing('{{record.name}}')">click</a>
```

Inside an event handler, attribute escaping is not enough — the value lands in JavaScript context. Single-quote / double-quote escape is application-level, not framework-level.

Hunt for `t-attf-on*` and `t-att-on*` with user data.

Also `t-att-href` and `t-attf-href` with `javascript:` schemes:

```xml
<a t-att-href="record.url"/>
<!-- record.url = "javascript:fetch('/admin/delete')" -->
```

The href value is attribute-escaped but not URL-scheme-validated. `javascript:` URIs work.

#### `t-call` with user-controlled template name

```xml
<t t-call="record.template_name"/>
```

If `template_name` comes from the database and an attacker can write to the model, they can render arbitrary templates including ones with privileged data.

Search:

```bash
grep -rn 't-call=' --include='*.xml' . | grep -v '"[a-z_.]*"'
```

#### QWeb expression context (`safe_eval`-like)

QWeb expressions run in a restricted Python eval. The exposed globals include `request`, `user`, `record`, `env`, and common helpers. Bug shapes:

- Custom evaluator that exposes additional callables (`__import__`, `subprocess`).
- Templates that pass `eval=True` to a custom render call.
- `_render_qweb_xml` / `_render_template` invocations with attacker-influenced `values` dict that includes shadowing of globals.

### Mail Templates (`mail.template`)

Mail template `body_html`, `subject`, `email_to`, `email_cc`, `report_template` are rendered with QWeb (or Jinja2 in older Odoo) on send.

Bugs:

- Template body sourced from a user model (e.g., `template_id.body_html` set from controller) → SSTI / XSS in delivered emails.
- `email_to = "${object.email}"` — if `object.email` is attacker-controlled, header injection (CRLF in the value).
- Attachment expressions (`report_template`) executing on user records — same risks as server actions.

### Report Templates

PDF/HTML reports use QWeb. Same `t-raw` / `t-field Html` traps.

- Reports rendered for "preview" via a controller with `auth='user'` but no record-ownership check → IDOR on report data.
- Report template `xml_id` user-supplied (`/report/html/<report_name>/<id>`) — verify the access check on `record(id)` matches the report's expected model.

### Website / Portal templates

`website` module adds page editor that lets admins write QWeb directly into pages. If non-admin users can write to `ir.ui.view`, they can XSS. Verify ACL on `ir.ui.view` and `website.page`.

## Client-Side QWeb (OWL)

OWL is Odoo's frontend framework (replaced legacy `widget.js` from 16.0). Templates are XML, compiled to JS in the browser.

Compiled output uses `textContent` for `t-esc`/`t-out`, so the default is safe. The unsafe forms:

- `t-out="expr" t-out-mode="raw"` (rare, custom OWL builds).
- Direct DOM manipulation in component code: `el.innerHTML = userValue`.
- React-style `dangerouslySetInnerHTML` equivalents — search component code for `innerHTML`.

Hunt:

```bash
grep -rn 'innerHTML' --include='*.js' addons/
grep -rn 'outerHTML' --include='*.js' addons/
grep -rn 'document\.write' --include='*.js' addons/
```

OWL-specific:

- Custom directives (`t-on-X="..."`) that pass user data into `eval`-like helpers.
- `useService('rpc')` calls returning HTML that's then injected via `innerHTML`.

## Special Cases

### Studio / Customisation

Odoo Enterprise's Studio lets admins edit views in the database (`ir.ui.view`). XSS from Studio is "admin owns admin" — usually not a finding unless cross-tenant.

### Forum / Survey / Slides modules

These modules let users submit HTML content. Verify:

- `tools.html_sanitize()` runs on the input.
- Render uses `t-field` (which respects sanitize policy) not `t-raw`.
- Custom module inherits don't replace `t-field` with `t-raw` to "fix formatting".

### `mail.message` body rendering

Chatter messages render via `t-field="message.body"` (which is `Html`). The body is sanitized on write by `mail_thread.message_post`. But:

- `message_post(body=raw_html)` from Python with no sanitize call → XSS on display.
- `mail.message.write({'body': raw_html})` — the write override sanitizes; verify a custom override doesn't skip it.

## Audit Checklist

1. `grep -rn 't-raw=' --include='*.xml' .` — review every hit.
2. `grep -rn 'Markup(' --include='*.py' .` — every site that constructs Markup from user data is suspect.
3. `grep -rn 'fields.Html(' --include='*.py' .` — verify `sanitize=` not disabled.
4. `grep -rn 'html_sanitize' --include='*.py' .` — verify each call's input is the right thing.
5. `grep -rn 't-call=' --include='*.xml' . | grep -v '"[a-z_.]*"'` — dynamic template names.
6. `grep -rn 't-attf-on' --include='*.xml' .` — event handler injection.
7. `grep -rn 't-att-href\|t-attf-href' --include='*.xml' .` — `javascript:` URI risk.
8. `grep -rn 'innerHTML\|outerHTML' --include='*.js' addons/` — client-side XSS.

## Anti-Patterns (Hunter Output)

- "`t-raw` is unsafe" — only a finding when the rendered value is user-controlled. `t-raw="record.computed_html"` where `computed_html` is server-built from constants is fine.
- "Missing `t-esc`" — if the surrounding directive (`t-att-`, `t-out`) already escapes, no finding.
- "QWeb is templating, prefer Jinja2" — style nit, drop.
- "Use `t-out` instead of `t-raw`" — also a style nit unless paired with proven user-controlled input.
- Reporting every `Markup()` call — many are intentional and safe (constructing UI fragments from constants).
