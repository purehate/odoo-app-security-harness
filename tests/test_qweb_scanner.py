"""Tests for QWeb template security scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.qweb_scanner import QWebScanner, scan_qweb_templates


def test_detects_t_raw(tmp_path: Path) -> None:
    """t-raw should be reported because it bypasses escaping."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><span t-raw="record.body"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-t-raw" for f in findings)


def test_detects_markup_escape_bypass(tmp_path: Path) -> None:
    """Markup() passed to t-out should be visible as an escape bypass."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><span t-out="Markup(record.body)"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-markup-escape-bypass" for f in findings)


def test_plain_t_out_is_not_markup_escape_bypass(tmp_path: Path) -> None:
    """Normal escaped t-out rendering should not trigger the Markup rule."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><span t-out="record.name"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert not any(f.rule_id == "odoo-qweb-markup-escape-bypass" for f in findings)


def test_detects_t_set_markup_escape_bypass(tmp_path: Path) -> None:
    """Markup() stored in t-set should be reported when rendered later."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><t t-set="safe_body" t-value="Markup(record.body)"/><span t-out="safe_body"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(
        f.rule_id == "odoo-qweb-markup-escape-bypass"
        and f.attribute == "t-out"
        and "t-set variable" in f.message
        for f in findings
    )


def test_plain_t_set_render_is_not_markup_escape_bypass(tmp_path: Path) -> None:
    """Normal t-set values should not be treated as Markup escape bypasses."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><t t-set="body" t-value="record.body"/><span t-out="body"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert not any(f.rule_id == "odoo-qweb-markup-escape-bypass" for f in findings)


def test_regex_fallback_detects_t_set_markup_escape_bypass(tmp_path: Path) -> None:
    """Malformed XML should still expose t-set Markup renders."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><t t-set="safe_body" t-value="Markup(record.body)"><span t-out="safe_body"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(
        f.rule_id == "odoo-qweb-markup-escape-bypass"
        and f.attribute == "t-out"
        and "t-set variable" in f.message
        for f in findings
    )


def test_detects_raw_output_mode(tmp_path: Path) -> None:
    """Raw t-out mode should be visible as an escaping bypass."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><span t-out="record.body" t-out-mode="raw"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-raw-output-mode" and f.severity == "high" for f in findings)


def test_plain_t_out_mode_is_ignored(tmp_path: Path) -> None:
    """Non-raw t-out modes should not trigger the raw-output rule."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><span t-out="record.body" t-out-mode="escaped"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert not any(f.rule_id == "odoo-qweb-raw-output-mode" for f in findings)


def test_dangerous_tag_does_not_abort_scan(tmp_path: Path) -> None:
    """Dangerous tags should be reported without hiding sibling QWeb sinks."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo>
  <template id="mixed">
    <form><input name="q"/></form>
    <span t-raw="record.body"/>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-qweb-dangerous-tag" in rule_ids
    assert "odoo-qweb-t-raw" in rule_ids


def test_detects_post_form_missing_csrf(tmp_path: Path) -> None:
    """Plain QWeb POST forms should show a CSRF review lead."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><form action="/portal/pay" method="post"><input name="amount"/></form></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-post-form-missing-csrf" and f.severity == "medium" for f in findings)


def test_post_form_with_csrf_token_ignored(tmp_path: Path) -> None:
    """Visible csrf_token fields suppress QWeb POST form CSRF leads."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><form action="/portal/pay" method="post"><input type="hidden" name="csrf_token" t-att-value="request.csrf_token()"/></form></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert not any(f.rule_id == "odoo-qweb-post-form-missing-csrf" for f in findings)


def test_get_form_missing_csrf_ignored(tmp_path: Path) -> None:
    """GET/search forms do not need CSRF tokens."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><form action="/shop" method="get"><input name="search"/></form></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert not any(f.rule_id == "odoo-qweb-post-form-missing-csrf" for f in findings)


def test_detects_target_blank_without_noopener(tmp_path: Path) -> None:
    """Links that open a new tab should isolate window.opener."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><a href="https://example.com" target="_blank">Open</a></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-target-blank-no-noopener" and f.severity == "medium" for f in findings)


def test_target_blank_with_noopener_ignored(tmp_path: Path) -> None:
    """rel=noopener/noreferrer is enough opener isolation."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><a href="https://example.com" target="_blank" rel="noopener noreferrer">Open</a></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert not any(f.rule_id == "odoo-qweb-target-blank-no-noopener" for f in findings)


def test_detects_iframe_missing_sandbox(tmp_path: Path) -> None:
    """Embedded frames should be sandboxed unless fully trusted."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><iframe src="https://player.example.com/embed/1"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-iframe-missing-sandbox" and f.severity == "medium" for f in findings)


def test_external_script_missing_sri_detected(tmp_path: Path) -> None:
    """Third-party scripts should be pinned with Subresource Integrity."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><script src="https://cdn.example.com/widget.js"></script></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-external-script-missing-sri" and f.severity == "medium" for f in findings)


def test_external_script_with_sri_ignored(tmp_path: Path) -> None:
    """External scripts with integrity are already pinned for review."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><script src="https://cdn.example.com/widget.js" integrity="sha384-test"></script></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert not any(f.rule_id == "odoo-qweb-external-script-missing-sri" for f in findings)


def test_detects_qweb_expression_inside_script_context(tmp_path: Path) -> None:
    """QWeb output inside <script> needs JavaScript-context serialization review."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><script>const name = "<t t-out='record.name'/>";</script></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(
        f.rule_id == "odoo-qweb-script-expression-context"
        and f.attribute == "t-out"
        and f.severity == "high"
        for f in findings
    )


def test_regex_fallback_detects_qweb_expression_inside_script_context(tmp_path: Path) -> None:
    """Malformed XML should still expose QWeb output inside JavaScript blocks."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><script>if (name < 1) { const v = "<t t-esc='record.name'/>"; }</script></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(
        f.rule_id == "odoo-qweb-script-expression-context"
        and f.attribute == "t-esc"
        and f.severity == "high"
        for f in findings
    )


def test_local_script_sri_ignored(tmp_path: Path) -> None:
    """Local bundle scripts should not require SRI."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><script src="/web/assets/debug/web.assets_frontend.js"></script></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert not any(f.rule_id == "odoo-qweb-external-script-missing-sri" for f in findings)


def test_external_stylesheet_missing_sri_detected(tmp_path: Path) -> None:
    """Third-party stylesheets should be pinned with Subresource Integrity."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><link rel="stylesheet" href="https://cdn.example.com/theme.css"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-external-stylesheet-missing-sri" and f.severity == "low" for f in findings)


def test_external_stylesheet_with_sri_ignored(tmp_path: Path) -> None:
    """External stylesheets with integrity are already pinned for review."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><link rel="stylesheet" href="https://cdn.example.com/theme.css" integrity="sha384-test"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert not any(f.rule_id == "odoo-qweb-external-stylesheet-missing-sri" for f in findings)


def test_local_stylesheet_sri_ignored(tmp_path: Path) -> None:
    """Local bundle stylesheets should not require SRI."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><link rel="stylesheet" href="/web/assets/debug/web.assets_frontend.css"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert not any(f.rule_id == "odoo-qweb-external-stylesheet-missing-sri" for f in findings)


def test_iframe_with_sandbox_ignored(tmp_path: Path) -> None:
    """A visible sandbox attribute suppresses the iframe sandbox lead."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><iframe src="https://player.example.com/embed/1" sandbox="allow-scripts"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert not any(f.rule_id == "odoo-qweb-iframe-missing-sandbox" for f in findings)


def test_iframe_empty_sandbox_ignored(tmp_path: Path) -> None:
    """An empty sandbox attribute is the most restrictive sandbox."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><iframe src="https://player.example.com/embed/1" sandbox=""/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert not any(f.rule_id == "odoo-qweb-iframe-missing-sandbox" for f in findings)


def test_detects_iframe_sandbox_escape_combo(tmp_path: Path) -> None:
    """allow-scripts plus allow-same-origin lets same-origin frames escape the sandbox."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><iframe src="/my/widget" sandbox="allow-forms allow-scripts allow-same-origin"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-iframe-sandbox-escape" and f.severity == "high" for f in findings)


def test_iframe_safe_sandbox_tokens_ignored(tmp_path: Path) -> None:
    """Other sandbox tokens should not trigger the escape-combination rule."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><iframe src="/my/widget" sandbox="allow-forms allow-popups"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert not any(f.rule_id == "odoo-qweb-iframe-sandbox-escape" for f in findings)


def test_detects_formatted_dynamic_url(tmp_path: Path) -> None:
    """t-attf URL attributes should be treated as dynamic URL sinks."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><a t-attf-href="/my/#{slug}">Open</a></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-t-attf-url" and f.severity == "medium" for f in findings)


def test_detects_javascript_formatted_url(tmp_path: Path) -> None:
    """t-attf URL attributes containing javascript: should be high severity."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><a t-attf-href="javascript:#{payload}">Open</a></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-t-attf-url" and f.severity == "high" for f in findings)


def test_detects_vbscript_formatted_url(tmp_path: Path) -> None:
    """t-attf URL attributes should treat legacy executable schemes like javascript:."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><a t-attf-href="vbscript:#{payload}">Open</a></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-t-attf-url" and f.severity == "high" for f in findings)


def test_detects_sensitive_formatted_url_token(tmp_path: Path) -> None:
    """QWeb URL attributes should not put secret-like values into links."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><a t-attf-href="/portal/pay?access_token=#{record.access_token}">Pay</a></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-sensitive-url-token" and f.attribute == "t-attf-href" for f in findings)


def test_detects_sensitive_t_att_url_token(tmp_path: Path) -> None:
    """Dynamic t-att URL expressions should report token-bearing links."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><a t-att-href="'/reset?password=%s' % record.reset_token">Reset</a></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-sensitive-url-token" and f.attribute == "t-att-href" for f in findings)


def test_static_sensitive_url_example_ignored(tmp_path: Path) -> None:
    """Literal examples without QWeb interpolation should not create URL-token noise."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><a href="/docs?access_token=example">Docs</a></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert not any(f.rule_id == "odoo-qweb-sensitive-url-token" for f in findings)


def test_detects_dynamic_event_handler_attribute(tmp_path: Path) -> None:
    """QWeb event-handler attributes place dynamic values in JavaScript context."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><button t-attf-onclick="openRecord('#{record.name}')">Open</button></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-dynamic-event-handler" and f.severity == "high" for f in findings)


def test_detects_dynamic_style_attribute(tmp_path: Path) -> None:
    """Dynamic style attributes can hide, overlay, or restyle privileged UI."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><div t-att-style="record.css_text">Panel</div></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(
        f.rule_id == "odoo-qweb-dynamic-style-attribute"
        and f.attribute == "t-att-style"
        and f.severity == "medium"
        for f in findings
    )


def test_detects_formatted_dynamic_style_attribute(tmp_path: Path) -> None:
    """Formatted style attributes should report interpolated CSS."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><div t-attf-style="display: #{record.display}; left: #{params.x}px">Panel</div></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-dynamic-style-attribute" and f.attribute == "t-attf-style" for f in findings)


def test_static_style_attribute_ignored(tmp_path: Path) -> None:
    """Static reviewed style literals should stay quiet."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><div t-attf-style="display: block; color: #333">Panel</div></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert not any(f.rule_id == "odoo-qweb-dynamic-style-attribute" for f in findings)


def test_detects_dynamic_class_attribute(tmp_path: Path) -> None:
    """Dynamic classes can hide controls or spoof visual state."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><button t-att-class="record.state_class">Approve</button></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(
        f.rule_id == "odoo-qweb-dynamic-class-attribute"
        and f.attribute == "t-att-class"
        and f.severity == "low"
        for f in findings
    )


def test_detects_formatted_dynamic_class_attribute(tmp_path: Path) -> None:
    """Formatted dynamic classes should be reported when they use record data."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><span t-attf-class="badge badge-#{record.status}">Status</span></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-dynamic-class-attribute" and f.attribute == "t-attf-class" for f in findings)


def test_static_class_attribute_ignored(tmp_path: Path) -> None:
    """Static reviewed class literals should stay quiet."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><span t-attf-class="badge badge-success">Status</span></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert not any(f.rule_id == "odoo-qweb-dynamic-class-attribute" for f in findings)


def test_regex_fallback_detects_dynamic_style_attribute(tmp_path: Path) -> None:
    """Malformed XML should still expose dynamic style attributes."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><div t-attf-style="background-image: url(#{payload.url})">Panel</div></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-dynamic-style-attribute" for f in findings)


def test_regex_fallback_detects_dynamic_class_attribute(tmp_path: Path) -> None:
    """Malformed XML should still expose dynamic class attributes."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><div t-attf-class="portal-card #{payload.class_name}">Panel</div></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-dynamic-class-attribute" for f in findings)


def test_detects_dynamic_attribute_mapping_url(tmp_path: Path) -> None:
    """Generic t-att mappings can dynamically set URL-bearing attributes."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><a t-att="{'href': record.callback_url}">Open</a></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-t-att-mapping-url" and f.severity == "medium" for f in findings)


def test_detects_javascript_dynamic_attribute_mapping_url(tmp_path: Path) -> None:
    """Generic t-att mappings with javascript URLs should be high severity."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><a t-att="{'href': 'javascript:%s' % payload}">Open</a></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-t-att-mapping-url" and f.severity == "high" for f in findings)


def test_detects_data_html_dynamic_attribute_mapping_url(tmp_path: Path) -> None:
    """Generic t-att mappings should catch executable data-document URLs."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><a t-att="{'href': 'data:text/html,%s' % payload}">Open</a></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-t-att-mapping-url" and f.severity == "high" for f in findings)


def test_detects_dynamic_attribute_mapping_style(tmp_path: Path) -> None:
    """Generic t-att mappings can dynamically set inline style attributes."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><div t-att="{'style': 'display: %s' % record.display}">Panel</div></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(
        f.rule_id == "odoo-qweb-dynamic-style-attribute"
        and f.attribute == "t-att"
        and f.severity == "medium"
        for f in findings
    )


def test_detects_dynamic_attribute_mapping_class(tmp_path: Path) -> None:
    """Generic t-att mappings can dynamically set CSS class attributes."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><button t-att="{'class': record.state_class}">Approve</button></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(
        f.rule_id == "odoo-qweb-dynamic-class-attribute"
        and f.attribute == "t-att"
        and f.severity == "low"
        for f in findings
    )


def test_static_attribute_mapping_class_ignored(tmp_path: Path) -> None:
    """Static class mapping literals should not trigger the dynamic class rule."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><button t-att="{'class': 'btn btn-primary'}">Approve</button></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert not any(f.rule_id == "odoo-qweb-dynamic-class-attribute" for f in findings)


def test_regex_fallback_detects_dynamic_attribute_mapping_style(tmp_path: Path) -> None:
    """Malformed XML should still expose t-att mapping style attributes."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><div t-att="{'style': 'left: %spx' % payload.x}">Panel</template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-dynamic-style-attribute" and f.attribute == "t-att" for f in findings)


def test_regex_fallback_detects_dynamic_attribute_mapping_class(tmp_path: Path) -> None:
    """Malformed XML should still expose t-att mapping class attributes."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><div t-att="{'class': payload.class_name}">Panel</template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-dynamic-class-attribute" and f.attribute == "t-att" for f in findings)


def test_detects_html_widget(tmp_path: Path) -> None:
    """HTML widget rendering should be visible in review output."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><span t-field="record.body" t-options="{'widget': 'html'}"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-html-widget" for f in findings)


def test_detects_dynamic_t_call_template_name(tmp_path: Path) -> None:
    """Dynamic t-call template selection should be review-visible."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><t t-call="record.template_name"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-dynamic-t-call" for f in findings)


def test_detects_t_js_inline_script(tmp_path: Path) -> None:
    """Inline t-js script blocks should be review-visible."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><t t-js="ctx">console.log(ctx.record_name)</t></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-t-js-inline-script" and f.severity == "medium" for f in findings)


def test_regex_fallback_detects_t_js_inline_script(tmp_path: Path) -> None:
    """Malformed XML should still expose t-js inline script leads."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><t t-js="ctx">if (name < 1) { alert(ctx.name); }</t></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-t-js-inline-script" for f in findings)


def test_literal_t_call_template_name_is_ignored(tmp_path: Path) -> None:
    """Static XML-ID t-call values are normal QWeb composition."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><t t-call="website.layout"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert not any(f.rule_id == "odoo-qweb-dynamic-t-call" for f in findings)


def test_detects_sensitive_field_rendering(tmp_path: Path) -> None:
    """Templates should not directly render credential-like fields."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><span t-field="record.access_token"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-sensitive-field-render" for f in findings)


def test_qweb_xml_entities_are_not_expanded(tmp_path: Path) -> None:
    """QWeb XML parsing should reject entities instead of expanding them into findings."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<!DOCTYPE odoo [
<!ENTITY sensitive_field "record.access_token">
]>
<odoo>
  <template id="entity_template">
    <span t-field="&sensitive_field;"/>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert not any(f.rule_id == "odoo-qweb-sensitive-field-render" for f in findings)


def test_directory_scan_finds_qweb_files(tmp_path: Path) -> None:
    """Directory scanner should include Odoo XML templates."""
    module = tmp_path / "module" / "views"
    module.mkdir(parents=True)
    (module / "templates.xml").write_text(
        """<odoo><template id="x"><a href="javascript:alert(1)">Open</a></template></odoo>""",
        encoding="utf-8",
    )

    findings = scan_qweb_templates(tmp_path)

    assert any(f.rule_id == "odoo-qweb-js-url" for f in findings)


def test_detects_data_html_url_attribute(tmp_path: Path) -> None:
    """Literal template URL attributes should catch executable data documents."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><iframe src="data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;"/></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-js-url" and f.attribute == "src" and f.severity == "high" for f in findings)


def test_detects_file_url_attribute(tmp_path: Path) -> None:
    """Literal template URL attributes should not point at local files."""
    template = tmp_path / "template.xml"
    template.write_text(
        """<odoo><template id="x"><a href="file:///etc/passwd">Open</a></template></odoo>""",
        encoding="utf-8",
    )

    findings = QWebScanner(str(template)).scan_file()

    assert any(f.rule_id == "odoo-qweb-js-url" and f.attribute == "href" and f.severity == "high" for f in findings)
