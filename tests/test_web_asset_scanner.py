"""Tests for Odoo frontend/static asset scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.web_asset_scanner import WebAssetScanner, scan_web_assets


def test_dom_xss_sink_detected(tmp_path: Path) -> None:
    """innerHTML assignments should be review leads."""
    path = tmp_path / "widget.js"
    path.write_text("this.el.innerHTML = payload;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dom-xss-sink" and f.sink == "innerHTML" for f in findings)


def test_dom_html_parser_sink_detected(tmp_path: Path) -> None:
    """DOMParser text/html parsing should be reviewed as a DOM XSS sink."""
    path = tmp_path / "widget.js"
    path.write_text(
        """parser.parseFromString(response.html, 'text/html');
$.parseHTML(response.html);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dom-xss-sink" and f.sink == "DOMParser.parseFromString" for f in findings)
    assert any(f.rule_id == "odoo-web-dom-xss-sink" and f.sink == "jquery.parseHTML" for f in findings)


def test_dom_fragment_and_srcdoc_sinks_detected(tmp_path: Path) -> None:
    """Fragment parsing and iframe srcdoc writes should be DOM XSS review leads."""
    path = tmp_path / "widget.js"
    path.write_text(
        """range.createContextualFragment(payload);
iframe.srcdoc = response.html;
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dom-xss-sink" and f.sink == "Range.createContextualFragment" for f in findings)
    assert any(f.rule_id == "odoo-web-dom-xss-sink" and f.sink == "iframe.srcdoc" for f in findings)


def test_unsafe_html_parser_apis_detected(tmp_path: Path) -> None:
    """Modern unsafe HTML parser APIs should be reviewed as DOM XSS sinks."""
    path = tmp_path / "widget.js"
    path.write_text(
        """this.el.setHTMLUnsafe(response.html);
const doc = Document.parseHTMLUnsafe(payload.html);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dom-xss-sink" and f.sink == "setHTMLUnsafe" for f in findings)
    assert any(f.rule_id == "odoo-web-dom-xss-sink" and f.sink == "Document.parseHTMLUnsafe" for f in findings)


def test_legacy_jquery_html_insertion_sinks_detected(tmp_path: Path) -> None:
    """Legacy Odoo widgets often inject HTML through jQuery helpers."""
    path = tmp_path / "widget.js"
    path.write_text(
        """this.$el.html(response.html);
this.$('.target').append(payload.fragment);
this.$footer.replaceWith(rendered);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert sum(1 for f in findings if f.rule_id == "odoo-web-dom-xss-sink" and f.sink == "jquery.html") == 3


def test_legacy_jquery_html_getter_ignored(tmp_path: Path) -> None:
    """Reading existing HTML should not be reported as an insertion sink."""
    path = tmp_path / "widget.js"
    path.write_text("const current = this.$el.html();\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-dom-xss-sink" and f.sink == "jquery.html" for f in findings)


def test_dom_event_handler_assignment_detected(tmp_path: Path) -> None:
    """String and request-derived DOM event handlers should be reviewed as DOM XSS leads."""
    path = tmp_path / "widget.js"
    path.write_text(
        """button.onclick = payload.handler;
image.onerror = 'alert(1)';
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert sum(1 for f in findings if f.rule_id == "odoo-web-dom-xss-sink" and f.sink == "dom-event-handler") == 2


def test_dom_event_handler_setattribute_detected(tmp_path: Path) -> None:
    """setAttribute('on...') handlers can execute JavaScript from dynamic values."""
    path = tmp_path / "widget.js"
    path.write_text("button.setAttribute('onclick', response.handler);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-dom-xss-sink" and f.sink == "setAttribute-event-handler" for f in findings
    )


def test_dom_event_handler_trusted_function_reference_ignored(tmp_path: Path) -> None:
    """Trusted function references are common UI wiring and should not be noisy."""
    path = tmp_path / "widget.js"
    path.write_text(
        """button.onclick = this.onClick;
select.onchange = handleChange;
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(
        f.rule_id == "odoo-web-dom-xss-sink" and "event-handler" in f.sink for f in findings
    )


def test_string_eval_sink_detected(tmp_path: Path) -> None:
    """String code execution should be reported."""
    path = tmp_path / "widget.js"
    path.write_text("setTimeout('refresh()');\nconst fn = new Function(code);\n$.globalEval(script);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert sum(1 for f in findings if f.rule_id == "odoo-web-string-code-execution") == 3
    assert any(f.rule_id == "odoo-web-string-code-execution" and f.sink == "jquery.globalEval" for f in findings)


def test_external_dynamic_import_detected(tmp_path: Path) -> None:
    """Runtime module imports from external origins should be reviewed."""
    path = tmp_path / "widget.js"
    path.write_text("await import('https://cdn.example.com/widget.mjs');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dynamic-code-import" and f.severity == "high" for f in findings)


def test_request_derived_dynamic_import_detected(tmp_path: Path) -> None:
    """Request/RPC-derived import targets are runtime code loading leads."""
    path = tmp_path / "widget.js"
    path.write_text("await import(response.module_url);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dynamic-code-import" and f.sink == "import" for f in findings)


def test_local_literal_dynamic_import_ignored(tmp_path: Path) -> None:
    """Local lazy-loaded modules are common bundler output."""
    path = tmp_path / "widget.js"
    path.write_text("await import('/web/static/src/js/widget.mjs');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-dynamic-code-import" for f in findings)


def test_external_worker_script_detected(tmp_path: Path) -> None:
    """External Worker script URLs are runtime code loading leads."""
    path = tmp_path / "widget.js"
    path.write_text("const worker = new Worker('https://cdn.example.com/worker.js');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dynamic-worker-script" and f.severity == "high" for f in findings)


def test_request_derived_shared_worker_script_detected(tmp_path: Path) -> None:
    """Request/RPC-derived SharedWorker scripts should be reviewed."""
    path = tmp_path / "widget.js"
    path.write_text("const worker = new SharedWorker(response.worker_url);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dynamic-worker-script" and f.sink == "SharedWorker" for f in findings)


def test_local_literal_worker_script_ignored(tmp_path: Path) -> None:
    """Local worker scripts are common reviewed bundle assets."""
    path = tmp_path / "widget.js"
    path.write_text("const worker = new Worker('/web/static/src/js/worker.js');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-dynamic-worker-script" for f in findings)


def test_external_import_scripts_detected(tmp_path: Path) -> None:
    """Worker importScripts should not load external runtime code."""
    path = tmp_path / "worker.js"
    path.write_text("importScripts('https://cdn.example.com/worker-helper.js');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dynamic-import-scripts" and f.sink == "importScripts" for f in findings)


def test_request_derived_import_scripts_detected(tmp_path: Path) -> None:
    """Worker importScripts targets should not be request-derived."""
    path = tmp_path / "worker.js"
    path.write_text("importScripts(response.workerScriptUrl);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dynamic-import-scripts" and f.severity == "high" for f in findings)


def test_local_literal_import_scripts_ignored(tmp_path: Path) -> None:
    """Local importScripts targets are expected reviewed worker assets."""
    path = tmp_path / "worker.js"
    path.write_text("importScripts('/web/static/src/js/worker-helper.js');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-dynamic-import-scripts" for f in findings)


def test_external_service_worker_registration_detected(tmp_path: Path) -> None:
    """External Service Worker registration targets should be reviewed."""
    path = tmp_path / "widget.js"
    path.write_text("navigator.serviceWorker.register('https://cdn.example.com/sw.js');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dynamic-service-worker" and f.severity == "high" for f in findings)


def test_request_derived_service_worker_registration_detected(tmp_path: Path) -> None:
    """Request/RPC-derived Service Worker script targets are persistent execution leads."""
    path = tmp_path / "widget.js"
    path.write_text("navigator.serviceWorker.register(response.service_worker_url);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dynamic-service-worker" and f.sink == "serviceWorker.register" for f in findings)


def test_local_literal_service_worker_registration_ignored(tmp_path: Path) -> None:
    """Local Service Worker scripts are expected when explicitly reviewed."""
    path = tmp_path / "widget.js"
    path.write_text("navigator.serviceWorker.register('/service-worker.js');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-dynamic-service-worker" for f in findings)


def test_dynamic_wasm_external_fetch_detected(tmp_path: Path) -> None:
    """External WebAssembly modules should be reviewed like runtime code loads."""
    path = tmp_path / "widget.js"
    path.write_text("WebAssembly.instantiateStreaming(fetch('https://cdn.example.com/mod.wasm'));\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-dynamic-wasm-loading" and f.sink == "WebAssembly.instantiateStreaming" for f in findings
    )


def test_dynamic_wasm_request_derived_fetch_detected(tmp_path: Path) -> None:
    """Request-derived WebAssembly fetch targets should be reviewed."""
    path = tmp_path / "widget.js"
    path.write_text("WebAssembly.compileStreaming(fetch(params.wasm_url));\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dynamic-wasm-loading" and f.severity == "high" for f in findings)


def test_static_local_wasm_fetch_ignored(tmp_path: Path) -> None:
    """Static same-origin WebAssembly assets are not dynamic by themselves."""
    path = tmp_path / "widget.js"
    path.write_text("WebAssembly.instantiateStreaming(fetch('/web/assets/module.wasm'));\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-dynamic-wasm-loading" for f in findings)


def test_request_derived_stylesheet_replace_detected(tmp_path: Path) -> None:
    """Constructable stylesheet writes from RPC data should be reviewed."""
    path = tmp_path / "widget.js"
    path.write_text("sheet.replaceSync(response.css);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dynamic-css-injection" and f.sink == "replaceSync" for f in findings)


def test_request_derived_insert_rule_detected(tmp_path: Path) -> None:
    """CSSOM insertRule calls with dynamic text can restyle privileged UI."""
    path = tmp_path / "widget.js"
    path.write_text("document.styleSheets[0].insertRule(payload.rule);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dynamic-css-injection" and f.severity == "medium" for f in findings)


def test_dom_style_text_injection_detected(tmp_path: Path) -> None:
    """DOM-created style tags populated from RPC data can restyle privileged UI."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const style = document.createElement('style');
style.textContent = response.css;
document.head.appendChild(style);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dynamic-css-injection" and f.sink == "style.text" for f in findings)


def test_dom_style_static_literal_ignored(tmp_path: Path) -> None:
    """Static DOM-created style blocks are reviewed source literals."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const style = document.createElement('style');
style.textContent = '.o_form_button_save { display: block; }';
document.head.appendChild(style);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-dynamic-css-injection" and f.sink == "style.text" for f in findings)


def test_static_literal_stylesheet_replace_ignored(tmp_path: Path) -> None:
    """Static reviewed CSS literals should not be reported."""
    path = tmp_path / "widget.js"
    path.write_text("sheet.replaceSync('.o_form_button_save { display: block; }');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-dynamic-css-injection" for f in findings)


def test_external_websocket_endpoint_detected(tmp_path: Path) -> None:
    """External browser realtime endpoints should be reviewed."""
    path = tmp_path / "widget.js"
    path.write_text("const socket = new WebSocket('wss://stream.example.com/orders');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dynamic-live-connection" and f.sink == "WebSocket" for f in findings)


def test_request_derived_eventsource_endpoint_detected(tmp_path: Path) -> None:
    """Request/RPC-derived EventSource endpoints can bind UI to untrusted feeds."""
    path = tmp_path / "widget.js"
    path.write_text("const feed = new EventSource(response.feed_url);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dynamic-live-connection" and f.severity == "medium" for f in findings)


def test_local_literal_live_connection_ignored(tmp_path: Path) -> None:
    """Same-origin realtime endpoints are expected in Odoo frontend assets."""
    path = tmp_path / "widget.js"
    path.write_text("const socket = new WebSocket('/websocket');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-dynamic-live-connection" for f in findings)


def test_document_domain_relaxation_detected(tmp_path: Path) -> None:
    """document.domain assignments weaken browser origin isolation."""
    path = tmp_path / "widget.js"
    path.write_text("document.domain = 'example.com';\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-document-domain-relaxation" and f.sink == "document.domain" for f in findings)


def test_document_domain_read_ignored(tmp_path: Path) -> None:
    """Reading document.domain is not origin relaxation by itself."""
    path = tmp_path / "widget.js"
    path.write_text("const currentDomain = document.domain;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-document-domain-relaxation" for f in findings)


def test_sensitive_document_cookie_write_detected(tmp_path: Path) -> None:
    """JavaScript-readable token cookies should be reviewed."""
    path = tmp_path / "widget.js"
    path.write_text("document.cookie = `session_token=${response.token}; Secure; SameSite=Lax`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-document-cookie" and f.severity == "high" for f in findings)


def test_dynamic_document_cookie_secret_detected(tmp_path: Path) -> None:
    """Sensitive cookie writes assembled through concatenation should be flagged."""
    path = tmp_path / "widget.js"
    path.write_text("document.cookie = 'api_key=' + props.apiKey + '; path=/';\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-document-cookie" and f.sink == "document.cookie" for f in findings)


def test_non_sensitive_document_cookie_ignored(tmp_path: Path) -> None:
    """Cosmetic client-side cookies should not be reported as credential storage."""
    path = tmp_path / "widget.js"
    path.write_text("document.cookie = 'theme=dark; path=/';\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-sensitive-document-cookie" for f in findings)


def test_sensitive_window_name_write_detected(tmp_path: Path) -> None:
    """window.name should not persist runtime credentials across navigations."""
    path = tmp_path / "widget.js"
    path.write_text("window.name = `session=${response.session}`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-window-name" and f.sink == "window.name" for f in findings)


def test_sensitive_window_name_concatenation_detected(tmp_path: Path) -> None:
    """Concatenated window.name credential writes should be flagged."""
    path = tmp_path / "widget.js"
    path.write_text("window.name = 'access_token=' + props.accessToken;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-window-name" and f.severity == "medium" for f in findings)


def test_plain_window_name_ignored(tmp_path: Path) -> None:
    """Plain window names are common popup or flow identifiers."""
    path = tmp_path / "widget.js"
    path.write_text("window.name = 'portal_popup';\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-sensitive-window-name" for f in findings)


def test_sensitive_indexeddb_put_detected(tmp_path: Path) -> None:
    """IndexedDB object stores should not persist credential-like values."""
    path = tmp_path / "widget.js"
    path.write_text("store.put({ id: userId, session_token: response.token });\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-indexeddb-storage" and f.sink == "put" for f in findings)


def test_sensitive_indexeddb_add_detected(tmp_path: Path) -> None:
    """Object-store add calls with API key data should be reviewed."""
    path = tmp_path / "widget.js"
    path.write_text("objectStore.add({ api_key: props.apiKey, partner_id: partnerId });\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-indexeddb-storage" and f.severity == "high" for f in findings)


def test_non_sensitive_indexeddb_write_ignored(tmp_path: Path) -> None:
    """Non-credential IndexedDB cache entries should not be reported."""
    path = tmp_path / "widget.js"
    path.write_text("store.put({ id: productId, name: displayName });\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-sensitive-indexeddb-storage" for f in findings)


def test_sensitive_cache_api_put_detected(tmp_path: Path) -> None:
    """Cache API writes of token-bearing URLs should be reviewed."""
    path = tmp_path / "widget.js"
    path.write_text("cache.put(`/portal/data?access_token=${token}`, response.clone());\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-cache-api-storage" and f.sink == "put" for f in findings)


def test_sensitive_cache_api_add_detected(tmp_path: Path) -> None:
    """Cache.add calls with credential-shaped URLs should be reviewed."""
    path = tmp_path / "widget.js"
    path.write_text(
        "caches.open('portal').then(cache => cache.add('/download?session=' + session));\n", encoding="utf-8"
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-cache-api-storage" and f.severity == "high" for f in findings)


def test_non_sensitive_cache_api_write_ignored(tmp_path: Path) -> None:
    """Static public asset cache entries should not be reported."""
    path = tmp_path / "widget.js"
    path.write_text("cache.put('/web/assets/app.css', response.clone());\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-sensitive-cache-api-storage" for f in findings)


def test_sensitive_console_logging_detected(tmp_path: Path) -> None:
    """Credential-like frontend values should not be logged."""
    path = tmp_path / "widget.js"
    path.write_text("console.debug('session_token', response.token);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-console-logging" and f.sink == "console.debug" for f in findings)


def test_sensitive_template_console_logging_detected(tmp_path: Path) -> None:
    """Template-literal logs can expose runtime credentials."""
    path = tmp_path / "widget.js"
    path.write_text("console.log(`api_key=${props.apiKey}`);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-console-logging" and f.severity == "medium" for f in findings)


def test_static_sensitive_console_message_ignored(tmp_path: Path) -> None:
    """Static words in diagnostic text are not credential exposure by themselves."""
    path = tmp_path / "widget.js"
    path.write_text("console.warn('missing access_token configuration');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-sensitive-console-logging" for f in findings)


def test_sensitive_send_beacon_url_detected(tmp_path: Path) -> None:
    """sendBeacon should not carry credential-like values in URLs."""
    path = tmp_path / "widget.js"
    path.write_text("navigator.sendBeacon(`/portal/audit?access_token=${token}`, payload);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-send-beacon" and f.sink == "navigator.sendBeacon" for f in findings)


def test_sensitive_send_beacon_payload_detected(tmp_path: Path) -> None:
    """sendBeacon payloads should not include runtime credentials."""
    path = tmp_path / "widget.js"
    path.write_text(
        "navigator.sendBeacon('/portal/audit', JSON.stringify({ session: props.sessionId }));\n", encoding="utf-8"
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-send-beacon" and f.severity == "medium" for f in findings)


def test_plain_send_beacon_ignored(tmp_path: Path) -> None:
    """Generic telemetry beacons are not sensitive by themselves."""
    path = tmp_path / "widget.js"
    path.write_text("navigator.sendBeacon('/metrics', JSON.stringify({ event: 'opened' }));\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-sensitive-send-beacon" for f in findings)


def test_sensitive_clipboard_write_text_detected(tmp_path: Path) -> None:
    """Clipboard writes of runtime credentials should be reviewed."""
    path = tmp_path / "widget.js"
    path.write_text("navigator.clipboard.writeText(props.accessToken);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-clipboard-write" and f.sink == "clipboard.writeText" for f in findings)


def test_sensitive_template_clipboard_write_detected(tmp_path: Path) -> None:
    """Template-literal clipboard writes can expose credentials."""
    path = tmp_path / "widget.js"
    path.write_text("navigator.clipboard.writeText(`session=${payload.session}`);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-clipboard-write" and f.severity == "medium" for f in findings)


def test_static_sensitive_clipboard_label_ignored(tmp_path: Path) -> None:
    """Static sensitive words in copied help text are not credentials."""
    path = tmp_path / "widget.js"
    path.write_text("navigator.clipboard.writeText('paste your access_token here');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-sensitive-clipboard-write" for f in findings)


def test_sensitive_notification_title_detected(tmp_path: Path) -> None:
    """Browser notifications should not expose runtime credentials."""
    path = tmp_path / "widget.js"
    path.write_text("new Notification(`session=${payload.session}`);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-notification" and f.sink == "new Notification" for f in findings)


def test_sensitive_show_notification_body_detected(tmp_path: Path) -> None:
    """Service Worker notifications can persist sensitive values in OS history."""
    path = tmp_path / "widget.js"
    path.write_text(
        "registration.showNotification('Export ready', { body: `api_key=${props.apiKey}` });\n", encoding="utf-8"
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-notification" and f.severity == "medium" for f in findings)


def test_static_sensitive_notification_label_ignored(tmp_path: Path) -> None:
    """Static notification labels are not credentials by themselves."""
    path = tmp_path / "widget.js"
    path.write_text("new Notification('Session expired, sign in again');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-sensitive-notification" for f in findings)


def test_sensitive_broadcast_channel_name_detected(tmp_path: Path) -> None:
    """BroadcastChannel names should not embed runtime credentials."""
    path = tmp_path / "widget.js"
    path.write_text("const channel = new BroadcastChannel(`session-${props.sessionId}`);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-broadcast-channel" and f.sink == "BroadcastChannel" for f in findings)


def test_sensitive_broadcast_channel_message_detected(tmp_path: Path) -> None:
    """BroadcastChannel messages should not spread credentials across tabs."""
    path = tmp_path / "widget.js"
    path.write_text("channel.postMessage({ access_token: response.token });\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-sensitive-broadcast-channel" and f.sink == "channel.postMessage" for f in findings
    )


def test_plain_broadcast_channel_message_ignored(tmp_path: Path) -> None:
    """Generic cross-tab events are not sensitive by themselves."""
    path = tmp_path / "widget.js"
    path.write_text("channel.postMessage({ event: 'cart_updated' });\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-sensitive-broadcast-channel" for f in findings)


def test_dynamic_odoo_bus_channel_detected(tmp_path: Path) -> None:
    """Odoo frontend bus channels should not be request-selected."""
    path = tmp_path / "widget.js"
    path.write_text("this.busService.addChannel(response.channel);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-dynamic-bus-channel" and f.sink == "bus.addChannel" and f.severity == "medium"
        for f in findings
    )


def test_broad_odoo_bus_channel_detected(tmp_path: Path) -> None:
    """Broad browser bus subscriptions should be reviewed for recipient scoping."""
    path = tmp_path / "widget.js"
    path.write_text("env.services.bus_service.subscribe('public_notifications');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dynamic-bus-channel" and f.sink == "bus.subscribe" for f in findings)


def test_scoped_static_odoo_bus_channel_ignored(tmp_path: Path) -> None:
    """Static scoped channels are expected when they are tied to a reviewed surface."""
    path = tmp_path / "widget.js"
    path.write_text("this.busService.addChannel('project.task:42');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-dynamic-bus-channel" for f in findings)


def test_math_random_token_detected(tmp_path: Path) -> None:
    """Math.random around token generation should be reported."""
    path = tmp_path / "widget.js"
    path.write_text("const csrfToken = Math.random().toString(36);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-weak-random-token" for f in findings)


def test_rpc_without_visible_csrf_detected(tmp_path: Path) -> None:
    """RPC calls without visible CSRF should become low-severity review leads."""
    path = tmp_path / "widget.js"
    path.write_text("jsonrpc('/my/action', {id: recordId});\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-rpc-without-visible-csrf" and f.severity == "low" for f in findings)


def test_dynamic_owl_orm_call_detected(tmp_path: Path) -> None:
    """OWL ORM service calls should not let request data choose model or method."""
    path = tmp_path / "widget.js"
    path.write_text("await this.orm.call(params.model, payload.method, [payload.ids]);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-dynamic-orm-service-call" and f.sink == "orm.call" and f.severity == "medium"
        for f in findings
    )


def test_owl_orm_search_read_with_request_domain_detected(tmp_path: Path) -> None:
    """Request-derived domains in frontend ORM searchRead calls are review leads."""
    path = tmp_path / "widget.js"
    path.write_text("const rows = await orm.searchRead('res.partner', response.domain, ['name']);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dynamic-orm-service-call" and f.sink == "orm.searchRead" for f in findings)


def test_static_owl_orm_call_ignored(tmp_path: Path) -> None:
    """Static reviewed ORM calls are common OWL service usage."""
    path = tmp_path / "widget.js"
    path.write_text("await this.orm.call('res.partner', 'name_search', [], {limit: 8});\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-dynamic-orm-service-call" for f in findings)


def test_fetch_post_without_visible_csrf_detected(tmp_path: Path) -> None:
    """Raw frontend POST calls should show a visible CSRF token/header."""
    path = tmp_path / "widget.js"
    path.write_text(
        """fetch('/portal/order/update', {
    method: 'POST',
    body: JSON.stringify({id: orderId}),
});
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-unsafe-request-without-csrf" and f.severity == "medium" for f in findings)


def test_ajax_post_with_visible_csrf_ignored(tmp_path: Path) -> None:
    """Visible CSRF token handling should suppress raw HTTP CSRF leads."""
    path = tmp_path / "widget.js"
    path.write_text(
        """$.ajax({
    url: '/portal/order/update',
    type: 'POST',
    headers: {'X-CSRF-Token': csrfToken},
});
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-unsafe-request-without-csrf" for f in findings)


def test_axios_delete_without_visible_csrf_detected(tmp_path: Path) -> None:
    """Axios unsafe method helpers should be covered too."""
    path = tmp_path / "widget.js"
    path.write_text("axios.delete('/portal/order/' + orderId);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-unsafe-request-without-csrf" and f.sink == "http-request" for f in findings)


def test_sensitive_browser_storage_detected(tmp_path: Path) -> None:
    """Frontend assets should not persist credential-like values in browser storage."""
    path = tmp_path / "widget.js"
    path.write_text(
        "localStorage.setItem('access_token', token);\nsessionStorage.setItem('api-key', response.key);\n",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-browser-storage" and f.severity == "high" for f in findings)


def test_sensitive_browser_storage_assignment_detected(tmp_path: Path) -> None:
    """Property and bracket writes should get the same browser-storage coverage as setItem."""
    path = tmp_path / "widget.js"
    path.write_text(
        "localStorage.access_token = response.token;\nsessionStorage['api-key'] = payload.key;\n",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    matches = [f for f in findings if f.rule_id == "odoo-web-sensitive-browser-storage"]
    assert len(matches) == 2
    assert all(f.severity == "high" and f.sink == "browser-storage" for f in matches)


def test_sensitive_browser_storage_read_detected(tmp_path: Path) -> None:
    """Reading credential-like values from browser storage is also an exposure signal."""
    path = tmp_path / "widget.js"
    path.write_text(
        "const token = localStorage.getItem('access_token');\n"
        "const apiKey = sessionStorage.getItem('api-key');\n",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    matches = [
        f
        for f in findings
        if f.rule_id == "odoo-web-sensitive-browser-storage" and "read from browser storage" in f.title
    ]
    assert len(matches) == 2
    assert all(f.severity == "high" and f.sink == "browser-storage" for f in matches)


def test_static_browser_storage_assignment_ignored(tmp_path: Path) -> None:
    """Static non-sensitive preference writes should not create storage noise."""
    path = tmp_path / "widget.js"
    path.write_text("localStorage.theme = 'dark';\nsessionStorage['last_menu'] = 'sales';\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-sensitive-browser-storage" for f in findings)


def test_sensitive_url_token_detected(tmp_path: Path) -> None:
    """Frontend assets should not place credential-like values in URLs."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const url = `/portal/pay?access_token=${response.token}`;
window.open('/reset#password=' + token);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    matches = [f for f in findings if f.rule_id == "odoo-web-sensitive-url-token"]
    assert matches
    assert all(f.severity == "medium" and f.sink == "url-token" for f in matches)


def test_urlsearchparams_sensitive_token_detected(tmp_path: Path) -> None:
    """URLSearchParams should not receive dynamic secret-like values."""
    path = tmp_path / "widget.js"
    path.write_text("url.searchParams.set('access_token', response.token);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-url-token" for f in findings)


def test_urlsearchparams_sensitive_token_read_detected(tmp_path: Path) -> None:
    """Reading token-like values from browser URLs points to credential-bearing links."""
    path = tmp_path / "widget.js"
    path.write_text(
        "const token = new URLSearchParams(window.location.search).get('access_token');\n"
        "const reset = new URL(window.location.href).searchParams.get('reset_password_token');\n",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    matches = [f for f in findings if f.rule_id == "odoo-web-sensitive-url-token"]
    assert len(matches) == 2
    assert all(f.severity == "medium" and f.sink == "url-token" for f in matches)


def test_static_sensitive_url_token_ignored(tmp_path: Path) -> None:
    """Static examples/defaults should not be noisy sensitive URL findings."""
    path = tmp_path / "widget.js"
    path.write_text("url.searchParams.set('access_token', 'example');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-sensitive-url-token" for f in findings)


def test_sensitive_history_url_detected(tmp_path: Path) -> None:
    """Credential-bearing URLs should not be persisted in browser history."""
    path = tmp_path / "widget.js"
    path.write_text("history.pushState({}, '', `/portal/pay?access_token=${response.token}`);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-history-url" and f.sink == "history.pushState" for f in findings)


def test_sensitive_history_replace_state_url_detected(tmp_path: Path) -> None:
    """replaceState has the same address bar and history leakage risk."""
    path = tmp_path / "widget.js"
    path.write_text("history.replaceState({}, '', '/reset#password=' + token);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-history-url" and f.sink == "history.replaceState" for f in findings)


def test_static_history_url_ignored(tmp_path: Path) -> None:
    """Static local history updates are common router behavior."""
    path = tmp_path / "widget.js"
    path.write_text("history.pushState({}, '', '/web#action=12');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-sensitive-history-url" for f in findings)


def test_sensitive_credential_store_detected(tmp_path: Path) -> None:
    """Credential Management API persistence should be reviewed for Odoo auth data."""
    path = tmp_path / "widget.js"
    path.write_text("navigator.credentials.store({ id: login, password: response.password });\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-sensitive-credential-management"
        and f.sink == "navigator.credentials.store"
        and f.severity == "high"
        for f in findings
    )


def test_sensitive_password_credential_constructor_detected(tmp_path: Path) -> None:
    """PasswordCredential construction with runtime secrets should be flagged."""
    path = tmp_path / "widget.js"
    path.write_text(
        "const credential = new PasswordCredential({ id: login, password: payload.password });\n", encoding="utf-8"
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-sensitive-credential-management" and f.sink == "PasswordCredential" for f in findings
    )


def test_non_sensitive_credential_store_ignored(tmp_path: Path) -> None:
    """Credential API feature checks should not create credential storage noise."""
    path = tmp_path / "widget.js"
    path.write_text(
        "const supported = Boolean(navigator.credentials && navigator.credentials.store);\n", encoding="utf-8"
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-sensitive-credential-management" for f in findings)


def test_raw_crypto_import_hardcoded_key_detected(tmp_path: Path) -> None:
    """Hard-coded raw WebCrypto keys in frontend assets should be reviewed."""
    path = tmp_path / "widget.js"
    path.write_text(
        "await crypto.subtle.importKey('raw', new TextEncoder().encode('hardcoded-api-key'), 'AES-GCM', false, ['encrypt']);\n",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-frontend-raw-crypto-key" and f.sink == "crypto.subtle.importKey" and f.severity == "high"
        for f in findings
    )


def test_jwk_crypto_import_request_secret_detected(tmp_path: Path) -> None:
    """Request-derived JWK secret material should not be imported in frontend code."""
    path = tmp_path / "widget.js"
    path.write_text(
        "await crypto.subtle.importKey('jwk', response.api_key, algorithm, false, ['verify']);\n", encoding="utf-8"
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-frontend-raw-crypto-key" for f in findings)


def test_generated_public_crypto_import_ignored(tmp_path: Path) -> None:
    """Generated or supplied public key material should not be treated as hard-coded secret material."""
    path = tmp_path / "widget.js"
    path.write_text(
        "await crypto.subtle.importKey('spki', publicKeyBytes, algorithm, false, ['verify']);\n", encoding="utf-8"
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-frontend-raw-crypto-key" for f in findings)


def test_sensitive_object_url_blob_detected(tmp_path: Path) -> None:
    """Blob object URLs should not carry runtime credential material."""
    path = tmp_path / "widget.js"
    path.write_text(
        "const href = URL.createObjectURL(new Blob([`access_token=${response.token}`], { type: 'text/plain' }));\n",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-sensitive-object-url" and f.sink == "URL.createObjectURL" and f.severity == "medium"
        for f in findings
    )


def test_sensitive_object_url_concatenation_detected(tmp_path: Path) -> None:
    """Concatenated credential blobs should be flagged before generating object URLs."""
    path = tmp_path / "widget.js"
    path.write_text(
        "const download = URL.createObjectURL(new Blob(['session=' + payload.session], { type: 'text/csv' }));\n",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-sensitive-object-url" for f in findings)


def test_static_object_url_blob_ignored(tmp_path: Path) -> None:
    """Static non-sensitive export blobs should not create object URL noise."""
    path = tmp_path / "widget.js"
    path.write_text(
        "const href = URL.createObjectURL(new Blob(['name,amount\\n'], { type: 'text/csv' }));\n",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-sensitive-object-url" for f in findings)


def test_postmessage_wildcard_origin_detected(tmp_path: Path) -> None:
    """postMessage should use explicit target origins for sensitive business UIs."""
    path = tmp_path / "widget.js"
    path.write_text("window.parent.postMessage({invoiceId, token}, '*');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-postmessage-wildcard-origin" and f.severity == "medium" for f in findings)


def test_postmessage_dynamic_origin_detected(tmp_path: Path) -> None:
    """postMessage target origins should not be chosen from runtime data."""
    path = tmp_path / "widget.js"
    path.write_text("window.parent.postMessage({invoiceId, token}, event.origin);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-postmessage-dynamic-origin"
        and f.sink == "postMessage"
        and f.severity == "medium"
        for f in findings
    )


def test_postmessage_literal_origin_ignored(tmp_path: Path) -> None:
    """Explicit literal target origins are reviewable allowlist entries."""
    path = tmp_path / "widget.js"
    path.write_text("window.parent.postMessage({invoiceId}, 'https://portal.example.com');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-postmessage-dynamic-origin" for f in findings)


def test_postmessage_same_origin_ignored(tmp_path: Path) -> None:
    """Same-origin postMessage targets are not cross-origin dynamic allowlists."""
    path = tmp_path / "widget.js"
    path.write_text("window.parent.postMessage({ready: true}, window.location.origin);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-postmessage-dynamic-origin" for f in findings)


def test_postmessage_sensitive_payload_detected(tmp_path: Path) -> None:
    """postMessage should not carry credentials across frame/window boundaries."""
    path = tmp_path / "widget.js"
    path.write_text("window.parent.postMessage({access_token: response.token}, 'https://portal.example.com');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-sensitive-postmessage-payload"
        and f.sink == "postMessage"
        and f.severity == "medium"
        for f in findings
    )


def test_postmessage_non_sensitive_payload_ignored(tmp_path: Path) -> None:
    """Routine frame messages without credential-shaped data should stay quiet."""
    path = tmp_path / "widget.js"
    path.write_text("window.parent.postMessage({event: 'invoice-ready'}, 'https://portal.example.com');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-sensitive-postmessage-payload" for f in findings)


def test_prototype_pollution_object_merge_detected(tmp_path: Path) -> None:
    """Frontend object merges should not consume request/RPC data without key filtering."""
    path = tmp_path / "widget.js"
    path.write_text(
        """Object.assign(this.state, response.data);
const options = {...payload};
$.extend(true, {}, event.data);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    matches = [f for f in findings if f.rule_id == "odoo-web-prototype-pollution-merge"]
    assert {f.sink for f in matches} >= {"Object.assign", "object-spread", "extend"}
    assert all(f.severity == "high" for f in matches)


def test_static_object_merge_ignored(tmp_path: Path) -> None:
    """Static object merges are common setup code and should not be noisy."""
    path = tmp_path / "widget.js"
    path.write_text("Object.assign(this.state, {ready: true});\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-prototype-pollution-merge" for f in findings)


def test_prototype_mutation_detected(tmp_path: Path) -> None:
    """Direct prototype-sensitive writes should be review leads."""
    path = tmp_path / "widget.js"
    path.write_text("target['__proto__'][key] = value;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-prototype-pollution-merge" and f.sink == "prototype" for f in findings)


def test_owl_markup_from_rpc_data_detected(tmp_path: Path) -> None:
    """OWL markup() should not safe-mark request/RPC HTML directly."""
    path = tmp_path / "widget.js"
    path.write_text("this.body = markup(response.html);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-owl-unsafe-markup" and f.sink == "markup" for f in findings)


def test_owl_markup_from_tainted_html_variable_detected(tmp_path: Path) -> None:
    """OWL markup() should catch request-derived HTML stored before safe-marking."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const html = response.html;
this.body = markup(html);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-owl-unsafe-markup" and f.line == 2 for f in findings)


def test_owl_markup_from_tainted_fragment_property_detected(tmp_path: Path) -> None:
    """OWL markup() should catch request-derived HTML held on component state."""
    path = tmp_path / "widget.js"
    path.write_text(
        """this.fragment = payload.fragment;
this.body = markup(this.fragment);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-owl-unsafe-markup" and f.line == 2 for f in findings)


def test_owl_markup_from_fetch_text_detected(tmp_path: Path) -> None:
    """OWL markup() should catch raw HTML loaded from fetch response text."""
    path = tmp_path / "widget.js"
    path.write_text("this.body = markup(await fetch('/portal/card').then((res) => res.text()));\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-owl-unsafe-markup" and f.sink == "markup" for f in findings)


def test_owl_markup_from_xhr_response_text_variable_detected(tmp_path: Path) -> None:
    """XHR responseText stored in an HTML-like variable should stay tainted before markup()."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const content = xhr.responseText;
this.body = markup(content);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-owl-unsafe-markup" and f.line == 2 for f in findings)


def test_owl_markup_from_sanitized_html_variable_ignored(tmp_path: Path) -> None:
    """Sanitized HTML variables should not be treated as unsafe safe-marking."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const html = DOMPurify.sanitize(response.html);
this.body = markup(html);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-owl-unsafe-markup" for f in findings)


def test_static_owl_markup_ignored(tmp_path: Path) -> None:
    """Static markup literals are not request-derived XSS leads."""
    path = tmp_path / "widget.js"
    path.write_text("this.body = markup('<strong>Ready</strong>');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-owl-unsafe-markup" for f in findings)


def test_owl_inline_template_t_raw_detected(tmp_path: Path) -> None:
    """OWL xml template literals can carry QWeb raw-output directives."""
    path = tmp_path / "widget.js"
    path.write_text(
        """import { xml } from '@odoo/owl';
export const template = xml`<div><span t-raw="props.html"/></div>`;
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-owl-qweb-t-raw"
        and f.sink == "owl-template"
        and f.severity == "medium"
        for f in findings
    )


def test_owl_inline_template_raw_output_mode_detected(tmp_path: Path) -> None:
    """OWL inline templates should not disable QWeb escaping."""
    path = tmp_path / "widget.js"
    path.write_text(
        """import { xml } from '@odoo/owl';
export const template = xml`
    <div>
        <t t-out="props.html" t-out-mode="raw"/>
    </div>
`;
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-owl-raw-output-mode"
        and f.sink == "owl-template"
        and f.severity == "high"
        for f in findings
    )


def test_owl_inline_template_dangerous_tag_detected(tmp_path: Path) -> None:
    """OWL inline templates should surface embedded active or submission tags."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<div><form action=\"/portal/pay\"><input name=\"amount\"/></form></div>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-owl-qweb-dangerous-tag"
        and f.sink == "owl-template"
        and f.severity == "medium"
        for f in findings
    )


def test_owl_inline_template_dangerous_tag_does_not_hide_raw_output(tmp_path: Path) -> None:
    """Dangerous OWL template tags should not suppress sibling raw-output leads."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<div><iframe src=\"https://player.example.com\"></iframe><span t-raw=\"props.html\"/></div>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-web-owl-qweb-dangerous-tag" in rule_ids
    assert "odoo-web-owl-qweb-t-raw" in rule_ids


def test_owl_inline_template_post_form_missing_csrf_detected(tmp_path: Path) -> None:
    """OWL inline POST forms should show a visible CSRF token."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<form action=\"/portal/pay\" method=\"post\"><input name=\"amount\"/></form>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-owl-qweb-post-form-missing-csrf"
        and f.sink == "owl-template"
        and f.severity == "medium"
        for f in findings
    )


def test_owl_inline_template_post_form_with_csrf_ignored(tmp_path: Path) -> None:
    """Visible csrf_token fields suppress OWL POST form CSRF leads."""
    path = tmp_path / "widget.js"
    path.write_text(
        "export const template = xml`<form method=\"post\"><input type=\"hidden\" name=\"csrf_token\" t-att-value=\"request.csrf_token()\"/></form>`;\n",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-owl-qweb-post-form-missing-csrf" for f in findings)


def test_owl_inline_template_get_form_missing_csrf_ignored(tmp_path: Path) -> None:
    """OWL GET/search forms do not need CSRF tokens."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<form action=\"/shop\" method=\"get\"><input name=\"search\"/></form>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-owl-qweb-post-form-missing-csrf" for f in findings)


def test_owl_inline_template_target_blank_without_noopener_detected(tmp_path: Path) -> None:
    """OWL inline links opening a new tab should isolate window.opener."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<a href=\"https://example.com\" target=\"_blank\">Open</a>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-owl-qweb-target-blank-no-noopener"
        and f.sink == "owl-template"
        and f.severity == "medium"
        for f in findings
    )


def test_owl_inline_template_target_blank_with_noopener_ignored(tmp_path: Path) -> None:
    """rel=noopener/noreferrer suppresses OWL target blank opener leads."""
    path = tmp_path / "widget.js"
    path.write_text(
        "export const template = xml`<a href=\"https://example.com\" target=\"_blank\" rel=\"noopener noreferrer\">Open</a>`;\n",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-owl-qweb-target-blank-no-noopener" for f in findings)


def test_owl_inline_template_iframe_missing_sandbox_detected(tmp_path: Path) -> None:
    """OWL inline iframes should declare sandbox restrictions."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<iframe src=\"https://player.example.com/embed/1\"></iframe>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-owl-qweb-iframe-missing-sandbox"
        and f.sink == "owl-template"
        and f.severity == "medium"
        for f in findings
    )


def test_owl_inline_template_iframe_with_sandbox_ignored(tmp_path: Path) -> None:
    """A visible OWL iframe sandbox suppresses the missing-sandbox lead."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<iframe src=\"https://player.example.com/embed/1\" sandbox=\"allow-scripts\"></iframe>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-owl-qweb-iframe-missing-sandbox" for f in findings)


def test_owl_inline_template_iframe_sandbox_escape_detected(tmp_path: Path) -> None:
    """OWL iframe sandbox should not combine scripts with same-origin."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<iframe src=\"/my/widget\" sandbox=\"allow-forms allow-scripts allow-same-origin\"></iframe>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-owl-qweb-iframe-sandbox-escape"
        and f.sink == "owl-template"
        and f.severity == "high"
        for f in findings
    )


def test_owl_inline_template_iframe_safe_sandbox_tokens_ignored(tmp_path: Path) -> None:
    """OWL iframe sandbox tokens without the escape combination stay quiet."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<iframe src=\"/my/widget\" sandbox=\"allow-forms allow-popups\"></iframe>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-owl-qweb-iframe-sandbox-escape" for f in findings)


def test_owl_inline_template_external_script_missing_sri_detected(tmp_path: Path) -> None:
    """OWL inline third-party scripts should be pinned with SRI."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<script src=\"https://cdn.example.com/widget.js\"></script>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-owl-qweb-external-script-missing-sri"
        and f.sink == "owl-template"
        and f.severity == "medium"
        for f in findings
    )


def test_owl_inline_template_external_script_with_sri_ignored(tmp_path: Path) -> None:
    """External OWL scripts with integrity are already pinned for review."""
    path = tmp_path / "widget.js"
    path.write_text(
        "export const template = xml`<script src=\"https://cdn.example.com/widget.js\" integrity=\"sha384-test\"></script>`;\n",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-owl-qweb-external-script-missing-sri" for f in findings)


def test_owl_inline_template_external_stylesheet_missing_sri_detected(tmp_path: Path) -> None:
    """OWL inline third-party stylesheets should be pinned with SRI."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<link rel=\"stylesheet\" href=\"https://cdn.example.com/theme.css\"/>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-owl-qweb-external-stylesheet-missing-sri"
        and f.sink == "owl-template"
        and f.severity == "low"
        for f in findings
    )


def test_owl_inline_template_external_stylesheet_with_sri_ignored(tmp_path: Path) -> None:
    """External OWL stylesheets with integrity are already pinned for review."""
    path = tmp_path / "widget.js"
    path.write_text(
        "export const template = xml`<link rel=\"stylesheet\" href=\"https://cdn.example.com/theme.css\" integrity=\"sha384-test\"/>`;\n",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-owl-qweb-external-stylesheet-missing-sri" for f in findings)


def test_owl_inline_template_escaped_output_ignored(tmp_path: Path) -> None:
    """Escaped OWL inline template output should not create raw-output leads."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<span t-out=\"props.name\"/>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id in {"odoo-web-owl-qweb-t-raw", "odoo-web-owl-raw-output-mode"} for f in findings)


def test_owl_inline_template_dynamic_event_handler_detected(tmp_path: Path) -> None:
    """OWL inline templates should not build JavaScript event handlers dynamically."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<button t-att-onclick=\"props.handler\">Pay</button>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-owl-qweb-dynamic-event-handler"
        and f.sink == "owl-template"
        and f.severity == "high"
        for f in findings
    )


def test_owl_inline_template_srcdoc_detected(tmp_path: Path) -> None:
    """OWL inline iframe srcdoc attributes should stay out of request-derived HTML."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<iframe sandbox=\"\" t-att-srcdoc=\"props.preview_html\"/>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-owl-qweb-srcdoc-html"
        and f.sink == "owl-template"
        and f.severity == "high"
        for f in findings
    )


def test_owl_inline_template_srcdoc_mapping_detected(tmp_path: Path) -> None:
    """OWL t-att mappings can also feed dynamic HTML into iframe srcdoc."""
    path = tmp_path / "widget.js"
    path.write_text(
        "export const template = xml`<iframe sandbox=\"\" t-att=\"{'srcdoc': props.preview_html}\"/>`;\n",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-owl-qweb-srcdoc-html"
        and f.sink == "owl-template"
        and f.severity == "high"
        for f in findings
    )


def test_owl_inline_template_dynamic_script_src_detected(tmp_path: Path) -> None:
    """OWL inline script src attributes should not import runtime-selected code."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<script t-att-src=\"props.script_url\"></script>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-owl-qweb-dynamic-script-src"
        and f.sink == "owl-template"
        and f.severity == "high"
        for f in findings
    )


def test_owl_inline_template_owl_event_binding_ignored(tmp_path: Path) -> None:
    """OWL t-on handlers reference component methods and are not string event attributes."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<button t-on-click=\"onPay\">Pay</button>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-owl-qweb-dynamic-event-handler" for f in findings)


def test_owl_inline_template_dynamic_stylesheet_href_detected(tmp_path: Path) -> None:
    """OWL inline stylesheet links should not load runtime-selected CSS."""
    path = tmp_path / "widget.js"
    path.write_text(
        "export const template = xml`<link rel=\"stylesheet\" t-att-href=\"props.theme_url\"/>`;\n",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-owl-qweb-dynamic-stylesheet-href"
        and f.sink == "owl-template"
        and f.severity == "medium"
        for f in findings
    )


def test_owl_inline_template_dynamic_style_attribute_detected(tmp_path: Path) -> None:
    """OWL inline style attributes should not render runtime-selected CSS."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<div t-att-style=\"props.css_text\">Panel</div>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-owl-qweb-dynamic-style-attribute"
        and f.sink == "owl-template"
        and f.severity == "medium"
        for f in findings
    )


def test_owl_inline_template_dynamic_style_mapping_detected(tmp_path: Path) -> None:
    """OWL t-att mappings can also bind dynamic inline style attributes."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<div t-att=\"{'style': props.css_text}\"/>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-owl-qweb-dynamic-style-attribute" for f in findings)


def test_owl_inline_template_dynamic_class_attribute_detected(tmp_path: Path) -> None:
    """OWL inline class attributes should not render runtime-selected UI state."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<button t-att-class=\"props.buttonClass\">Pay</button>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-owl-qweb-dynamic-class-attribute"
        and f.sink == "owl-template"
        and f.severity == "medium"
        for f in findings
    )


def test_owl_inline_template_dynamic_class_mapping_detected(tmp_path: Path) -> None:
    """OWL t-att mappings can also bind dynamic classes."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<button t-att=\"{'class': props.buttonClass}\"/>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-owl-qweb-dynamic-class-attribute" for f in findings)


def test_owl_inline_template_dynamic_url_attribute_detected(tmp_path: Path) -> None:
    """OWL inline URL-bearing attributes should not use runtime-selected targets."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<a t-att-href=\"props.next_url\">Continue</a>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-owl-qweb-dynamic-url-attribute"
        and f.sink == "owl-template"
        and f.severity == "medium"
        for f in findings
    )


def test_owl_inline_template_dynamic_url_mapping_detected(tmp_path: Path) -> None:
    """OWL t-att mappings can also bind URL-bearing attributes dynamically."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<form t-att=\"{'action': props.post_url}\"/>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-owl-qweb-dynamic-url-attribute" for f in findings)


def test_owl_inline_template_dangerous_static_url_detected(tmp_path: Path) -> None:
    """OWL inline templates should not hard-code executable URL schemes."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<a href=\"javascript:alert(document.cookie)\">Open</a>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-owl-qweb-dangerous-url-scheme"
        and f.sink == "owl-template"
        and f.severity == "high"
        for f in findings
    )


def test_owl_inline_template_safe_static_url_ignored(tmp_path: Path) -> None:
    """Normal local OWL URLs should not create dangerous-scheme noise."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<a href=\"/web#action=12\">Open</a>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-owl-qweb-dangerous-url-scheme" for f in findings)


def test_owl_inline_template_sensitive_field_render_detected(tmp_path: Path) -> None:
    """OWL inline templates should not expose credential-shaped values."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<span t-out=\"props.accessToken\"/>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-owl-qweb-sensitive-field-render"
        and f.sink == "owl-template"
        and f.severity == "high"
        for f in findings
    )


def test_owl_inline_template_sensitive_data_attribute_detected(tmp_path: Path) -> None:
    """Credential-shaped dynamic data attributes are still exposed to browser scripts."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<input t-att-data-token=\"props.csrf_token\"/>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-owl-qweb-sensitive-field-render" for f in findings)


def test_owl_inline_template_non_sensitive_field_render_ignored(tmp_path: Path) -> None:
    """Routine escaped field output should not create credential exposure leads."""
    path = tmp_path / "widget.js"
    path.write_text("export const template = xml`<span t-out=\"props.display_name\"/>`;\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-owl-qweb-sensitive-field-render" for f in findings)


def test_message_handler_missing_origin_check_detected(tmp_path: Path) -> None:
    """Inbound postMessage handlers should validate event.origin before using data."""
    path = tmp_path / "widget.js"
    path.write_text(
        """window.addEventListener('message', (event) => {
    this.rpc('/portal/pay', event.data);
});
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-message-handler-missing-origin-check" and f.severity == "high" for f in findings)


def test_message_handler_with_origin_check_ignored(tmp_path: Path) -> None:
    """A visible origin comparison is enough to avoid this review lead."""
    path = tmp_path / "widget.js"
    path.write_text(
        """window.addEventListener('message', (event) => {
    if (event.origin !== window.location.origin) {
        return;
    }
    this.rpc('/portal/pay', event.data);
});
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-message-handler-missing-origin-check" for f in findings)


def test_client_side_redirect_from_url_param_detected(tmp_path: Path) -> None:
    """Dynamic client-side navigation targets should be reviewed as redirect leads."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const target = new URLSearchParams(window.location.search).get('next');
window.location.href = target;
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-client-side-redirect" and f.sink == "location.href" for f in findings)


def test_window_open_dynamic_target_detected(tmp_path: Path) -> None:
    """window.open with a response-controlled target should be reported."""
    path = tmp_path / "widget.js"
    path.write_text("window.open(response.redirect_url);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-client-side-redirect" and f.sink == "window.open" for f in findings)


def test_dangerous_static_location_scheme_detected(tmp_path: Path) -> None:
    """Static javascript: navigation targets should be reviewed as executable URL sinks."""
    path = tmp_path / "widget.js"
    path.write_text("window.location.href = 'javascript:alert(document.cookie)';\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-dangerous-url-scheme" and f.sink == "location.href" and f.severity == "high"
        for f in findings
    )


def test_dangerous_window_open_data_scheme_detected(tmp_path: Path) -> None:
    """window.open should not target literal active data documents."""
    path = tmp_path / "widget.js"
    path.write_text("window.open('data:text/html,<script>alert(1)</script>');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dangerous-url-scheme" and f.sink == "window.open" for f in findings)


def test_dangerous_dom_url_attribute_scheme_detected(tmp_path: Path) -> None:
    """DOM URL-bearing attributes should not receive executable URL schemes."""
    path = tmp_path / "widget.js"
    path.write_text("link.setAttribute('href', 'javascript:alert(1)');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dangerous-url-scheme" and f.sink == "setAttribute-url" for f in findings)


def test_dangerous_jquery_url_attribute_scheme_detected(tmp_path: Path) -> None:
    """jQuery URL-bearing attributes should not receive executable URL schemes."""
    path = tmp_path / "widget.js"
    path.write_text(
        """this.$link.attr('href', 'javascript:alert(1)');
this.$frame.prop('src', 'data:text/html,<script>alert(1)</script>');
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert sum(1 for f in findings if f.rule_id == "odoo-web-dangerous-url-scheme" and f.sink == "jquery.attr-url") == 2


def test_static_local_navigation_scheme_ignored(tmp_path: Path) -> None:
    """Normal static Odoo route navigation should stay quiet."""
    path = tmp_path / "widget.js"
    path.write_text("window.location.href = '/web#action=12';\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-dangerous-url-scheme" for f in findings)


def test_window_open_blank_without_noopener_detected(tmp_path: Path) -> None:
    """window.open to a new browsing context should isolate window.opener."""
    path = tmp_path / "widget.js"
    path.write_text("window.open('https://partner.example.com/pay', '_blank');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-window-open-no-noopener" and f.severity == "medium" for f in findings)


def test_window_open_without_target_detected(tmp_path: Path) -> None:
    """window.open defaults to a new browsing context."""
    path = tmp_path / "widget.js"
    path.write_text("window.open('/portal/receipt');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-window-open-no-noopener" for f in findings)


def test_window_open_with_noopener_ignored(tmp_path: Path) -> None:
    """Explicit noopener/noreferrer features suppress opener-isolation leads."""
    path = tmp_path / "widget.js"
    path.write_text(
        "window.open('https://partner.example.com/pay', '_blank', 'popup,noopener,noreferrer');\n", encoding="utf-8"
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-window-open-no-noopener" for f in findings)


def test_window_open_named_target_ignored(tmp_path: Path) -> None:
    """Named same-application popup reuse should not be treated as _blank."""
    path = tmp_path / "widget.js"
    path.write_text("window.open('/web#action=12', 'odoo_backend');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-window-open-no-noopener" for f in findings)


def test_dom_target_blank_without_noopener_detected(tmp_path: Path) -> None:
    """DOM-generated new-tab links should set rel opener isolation."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const link = document.createElement('a');
link.href = response.url;
link.target = '_blank';
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-target-blank-no-noopener" and f.sink == "target" for f in findings)


def test_dom_target_blank_setattribute_without_noopener_detected(tmp_path: Path) -> None:
    """setAttribute('target', '_blank') needs the same opener isolation."""
    path = tmp_path / "widget.js"
    path.write_text("link.setAttribute('target', '_blank');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-target-blank-no-noopener" for f in findings)


def test_dom_target_blank_with_noopener_ignored(tmp_path: Path) -> None:
    """A nearby rel assignment with noopener/noreferrer suppresses the lead."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const link = document.createElement('a');
link.target = '_blank';
link.rel = 'noopener noreferrer';
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-target-blank-no-noopener" for f in findings)


def test_dom_iframe_sandbox_escape_property_detected(tmp_path: Path) -> None:
    """DOM iframe sandbox assignments should not combine scripts with same-origin."""
    path = tmp_path / "widget.js"
    path.write_text("iframe.sandbox = 'allow-forms allow-scripts allow-same-origin';\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-iframe-sandbox-escape" and f.severity == "high" for f in findings)


def test_dom_iframe_sandbox_escape_setattribute_detected(tmp_path: Path) -> None:
    """setAttribute('sandbox', ...) should get the same weak-sandbox coverage."""
    path = tmp_path / "widget.js"
    path.write_text(
        "iframe.setAttribute('sandbox', 'allow-same-origin allow-popups allow-scripts');\n", encoding="utf-8"
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-iframe-sandbox-escape" and f.sink == "iframe.sandbox" for f in findings)


def test_dom_iframe_safe_sandbox_tokens_ignored(tmp_path: Path) -> None:
    """Sandbox tokens without the escape combination should stay quiet."""
    path = tmp_path / "widget.js"
    path.write_text("iframe.sandbox = 'allow-forms allow-popups';\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-iframe-sandbox-escape" for f in findings)


def test_dom_iframe_missing_sandbox_detected(tmp_path: Path) -> None:
    """DOM-created iframes should show a visible sandbox before use."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const frame = document.createElement('iframe');
frame.src = response.checkout_url;
this.el.appendChild(frame);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-iframe-missing-sandbox" and f.severity == "medium" for f in findings)


def test_dom_iframe_missing_sandbox_setattribute_detected(tmp_path: Path) -> None:
    """setAttribute('src', ...) and append() count as visible iframe use."""
    path = tmp_path / "widget.js"
    path.write_text(
        """let paymentFrame = document.createElement("iframe");
paymentFrame.setAttribute("src", response.url);
container.append(paymentFrame);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-iframe-missing-sandbox" and f.sink == "iframe" for f in findings)


def test_dom_iframe_with_sandbox_ignored(tmp_path: Path) -> None:
    """A nearby sandbox assignment suppresses missing-sandbox leads."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const frame = document.createElement('iframe');
frame.sandbox = 'allow-forms';
frame.src = response.checkout_url;
this.el.appendChild(frame);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-iframe-missing-sandbox" for f in findings)


def test_unused_dom_iframe_ignored(tmp_path: Path) -> None:
    """Creating an iframe variable alone is not enough signal."""
    path = tmp_path / "widget.js"
    path.write_text("const frame = document.createElement('iframe');\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-iframe-missing-sandbox" for f in findings)


def test_dom_external_script_missing_sri_detected(tmp_path: Path) -> None:
    """DOM-created external scripts should show visible SRI pinning."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const script = document.createElement('script');
script.src = 'https://cdn.example.com/widget.js';
document.head.appendChild(script);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-external-script-missing-sri" and f.severity == "medium" for f in findings)


def test_dom_external_script_missing_sri_setattribute_detected(tmp_path: Path) -> None:
    """setAttribute('src', external URL) gets the same SRI coverage."""
    path = tmp_path / "widget.js"
    path.write_text(
        """let loader = document.createElement("script");
loader.setAttribute("src", "//cdn.example.com/widget.js");
document.body.append(loader);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-external-script-missing-sri" and f.sink == "script" for f in findings)


def test_dom_external_script_with_integrity_ignored(tmp_path: Path) -> None:
    """A nearby integrity assignment suppresses generated-script SRI leads."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const script = document.createElement('script');
script.src = 'https://cdn.example.com/widget.js';
script.integrity = 'sha384-test';
document.head.appendChild(script);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-external-script-missing-sri" for f in findings)


def test_dom_local_script_sri_ignored(tmp_path: Path) -> None:
    """Local generated scripts should not require SRI."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const script = document.createElement('script');
script.src = '/web/static/src/js/widget.js';
document.head.appendChild(script);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-external-script-missing-sri" for f in findings)


def test_dom_external_stylesheet_missing_sri_detected(tmp_path: Path) -> None:
    """DOM-created external stylesheets should show visible SRI pinning."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const style = document.createElement('link');
style.rel = 'stylesheet';
style.href = 'https://cdn.example.com/theme.css';
document.head.appendChild(style);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-external-stylesheet-missing-sri" and f.severity == "low" for f in findings)


def test_dom_external_stylesheet_missing_sri_setattribute_detected(tmp_path: Path) -> None:
    """setAttribute for rel/href gets the same stylesheet SRI coverage."""
    path = tmp_path / "widget.js"
    path.write_text(
        """let style = document.createElement("link");
style.setAttribute("rel", "stylesheet");
style.setAttribute("href", "//cdn.example.com/theme.css");
document.head.append(style);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-external-stylesheet-missing-sri" and f.sink == "stylesheet" for f in findings)


def test_dom_external_stylesheet_with_integrity_ignored(tmp_path: Path) -> None:
    """A nearby integrity assignment suppresses generated-stylesheet SRI leads."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const style = document.createElement('link');
style.rel = 'stylesheet';
style.href = 'https://cdn.example.com/theme.css';
style.integrity = 'sha384-test';
document.head.appendChild(style);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-external-stylesheet-missing-sri" for f in findings)


def test_dom_local_stylesheet_sri_ignored(tmp_path: Path) -> None:
    """Local generated stylesheets should not require SRI."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const style = document.createElement('link');
style.rel = 'stylesheet';
style.href = '/web/static/src/css/widget.css';
document.head.appendChild(style);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-external-stylesheet-missing-sri" for f in findings)


def test_static_local_navigation_ignored(tmp_path: Path) -> None:
    """Static local redirects are common Odoo UI flow and should not be noisy."""
    path = tmp_path / "widget.js"
    path.write_text("window.location.href = '/web';\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-client-side-redirect" for f in findings)


def test_dynamic_odoo_action_url_detected(tmp_path: Path) -> None:
    """Odoo act_url frontend actions should be reviewed when the URL is dynamic."""
    path = tmp_path / "widget.js"
    path.write_text(
        """this.actionService.doAction({
    type: 'ir.actions.act_url',
    url: response.redirect_url,
    target: 'self',
});
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-client-side-redirect" and f.sink == "ir.actions.act_url" for f in findings)


def test_static_odoo_action_url_ignored(tmp_path: Path) -> None:
    """Static local act_url actions should not create redirect noise."""
    path = tmp_path / "widget.js"
    path.write_text(
        """this.actionService.doAction({
    type: 'ir.actions.act_url',
    url: '/web#action=12',
    target: 'self',
});
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-client-side-redirect" for f in findings)


def test_dangerous_static_odoo_action_url_detected(tmp_path: Path) -> None:
    """Odoo act_url actions should not use executable URL schemes."""
    path = tmp_path / "widget.js"
    path.write_text(
        """this.actionService.doAction({
    type: 'ir.actions.act_url',
    url: 'javascript:alert(document.domain)',
    target: 'self',
});
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-dangerous-url-scheme" and f.sink == "ir.actions.act_url" and f.severity == "high"
        for f in findings
    )


def test_dynamic_odoo_action_window_detected(tmp_path: Path) -> None:
    """Frontend act_window actions should not let request data choose model/domain/context."""
    path = tmp_path / "widget.js"
    path.write_text(
        """this.actionService.doAction({
    type: 'ir.actions.act_window',
    res_model: params.model,
    domain: response.domain,
    context: payload.context,
});
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-web-dynamic-action-window"
        and f.sink == "ir.actions.act_window"
        and f.severity == "medium"
        for f in findings
    )


def test_request_derived_action_descriptor_detected(tmp_path: Path) -> None:
    """Action descriptors returned from request/RPC data should be reviewed."""
    path = tmp_path / "widget.js"
    path.write_text("await this.action.doAction(response.action);\n", encoding="utf-8")

    findings = WebAssetScanner(path).scan_file()

    assert any(f.rule_id == "odoo-web-dynamic-action-window" and f.sink == "doAction" for f in findings)


def test_static_odoo_action_window_ignored(tmp_path: Path) -> None:
    """Static act_window payloads are expected in reviewed Odoo widgets."""
    path = tmp_path / "widget.js"
    path.write_text(
        """this.actionService.doAction({
    type: 'ir.actions.act_window',
    res_model: 'res.partner',
    domain: [['customer_rank', '>', 0]],
    context: {active_test: false},
});
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-dynamic-action-window" for f in findings)


def test_dynamic_dom_url_attribute_detected(tmp_path: Path) -> None:
    """Dynamic DOM URL attribute assignments should be reviewed in portal widgets."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const checkout = response.redirect_url;
this.el.querySelector('iframe').src = checkout;
this.el.querySelector('button').formAction = checkout;
this.el.querySelector('form').setAttribute('action', checkout);
this.el.querySelector('img').setAttribute('srcset', checkout);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert sum(1 for f in findings if f.rule_id == "odoo-web-client-side-redirect" and f.sink == "element.href") == 2
    assert sum(1 for f in findings if f.rule_id == "odoo-web-client-side-redirect" and f.sink == "setAttribute-url") == 2


def test_dynamic_jquery_url_attribute_detected(tmp_path: Path) -> None:
    """Dynamic jQuery URL-bearing attributes should be reviewed in portal widgets."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const target = response.redirect_url;
this.$link.attr('href', target);
this.$form.prop('action', target);
this.$preview.attr('poster', target);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert sum(1 for f in findings if f.rule_id == "odoo-web-client-side-redirect" and f.sink == "jquery.attr-url") == 3


def test_dynamic_anchor_ping_url_attribute_detected(tmp_path: Path) -> None:
    """Anchor ping URLs can leak click and token data through browser beacons."""
    path = tmp_path / "widget.js"
    path.write_text(
        """const beacon = response.tracking_url;
this.el.querySelector('a').ping = beacon;
this.el.querySelector('a').setAttribute('ping', beacon);
this.$link.attr('ping', beacon);
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert sum(1 for f in findings if f.rule_id == "odoo-web-client-side-redirect" and f.sink == "element.href") == 1
    assert sum(1 for f in findings if f.rule_id == "odoo-web-client-side-redirect" and f.sink == "setAttribute-url") == 1
    assert sum(1 for f in findings if f.rule_id == "odoo-web-client-side-redirect" and f.sink == "jquery.attr-url") == 1


def test_static_dom_url_attribute_ignored(tmp_path: Path) -> None:
    """Static DOM URL attributes should not be reported as dynamic redirects."""
    path = tmp_path / "widget.js"
    path.write_text(
        """this.el.querySelector('a').href = 'https://www.odoo.com';
this.el.querySelector('iframe').src = '/web/static/blank.html';
""",
        encoding="utf-8",
    )

    findings = WebAssetScanner(path).scan_file()

    assert not any(f.rule_id == "odoo-web-client-side-redirect" for f in findings)


def test_repository_scan_only_static_assets(tmp_path: Path) -> None:
    """The repository scan should target Odoo static assets and skip node_modules."""
    asset = tmp_path / "addon" / "static" / "src" / "js" / "widget.js"
    asset.parent.mkdir(parents=True)
    asset.write_text("this.el.outerHTML = html;\n", encoding="utf-8")
    ignored = tmp_path / "addon" / "models" / "not_static.js"
    ignored.parent.mkdir(parents=True)
    ignored.write_text("this.el.outerHTML = html;\n", encoding="utf-8")
    node_module = tmp_path / "addon" / "static" / "node_modules" / "lib.js"
    node_module.parent.mkdir(parents=True)
    node_module.write_text("this.el.outerHTML = html;\n", encoding="utf-8")

    findings = scan_web_assets(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == str(asset)
