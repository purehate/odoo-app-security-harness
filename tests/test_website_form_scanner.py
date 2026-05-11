"""Tests for Odoo website form scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.website_form_scanner import scan_website_forms


def test_flags_website_form_model_create_and_sensitive_field(tmp_path: Path) -> None:
    """Website forms that post to model creation should be review leads."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "forms.xml").write_text(
        """<odoo>
  <template id="contact">
    <form action="/website/form/crm.lead" method="post">
      <input name="partner_id"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-website-form-public-model-create" in rule_ids
    assert "odoo-website-form-sensitive-field" in rule_ids


def test_security_model_website_forms_are_high_severity(tmp_path: Path) -> None:
    """Website forms targeting security/payment models should be treated as sensitive."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "forms.xml").write_text(
        """<odoo>
  <template id="params">
    <form action="/website/form/ir.config_parameter" method="post">
      <input name="key"/>
    </form>
  </template>
  <template id="payment_provider">
    <form data-model_name="payment.provider" method="post">
      <input name="name"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)
    high_model_creates = {
        finding.model
        for finding in findings
        if finding.rule_id == "odoo-website-form-public-model-create" and finding.severity == "high"
    }

    assert {"ir.config_parameter", "payment.provider"} <= high_model_creates


def test_xml_entities_are_not_expanded_into_website_form_findings(tmp_path: Path) -> None:
    """XML entities must not synthesize website form field exposure."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "forms.xml").write_text(
        """<!DOCTYPE odoo [
<!ENTITY sensitive_field "partner_id">
]>
<odoo>
  <template id="contact">
    <form action="/website/form/crm.lead" method="post">
      <input name="&sensitive_field;"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_website_forms(tmp_path) == []


def test_flags_website_form_file_upload(tmp_path: Path) -> None:
    """Public website file upload forms need attachment handling review."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "upload.xml").write_text(
        """<odoo>
  <template id="upload">
    <form action="/website/form/helpdesk.ticket" enctype="multipart/form-data">
      <input type="file" name="attachment"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-file-upload" for f in findings)


def test_flags_active_file_accept_on_website_form_upload(tmp_path: Path) -> None:
    """Website file inputs accepting SVG/HTML-like content deserve stronger review."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "upload.xml").write_text(
        """<odoo>
  <template id="upload">
    <form action="/website/form/helpdesk.ticket" enctype="multipart/form-data">
      <input type="hidden" name="csrf_token" t-att-value="request.csrf_token()"/>
      <input type="file" name="attachment" accept="image/svg+xml,.html,image/*"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(
        f.rule_id == "odoo-website-form-active-file-upload"
        and f.severity == "high"
        and "image/svg+xml" in f.message
        and ".html" in f.message
        for f in findings
    )


def test_flags_missing_csrf_token_on_post_form(tmp_path: Path) -> None:
    """Public website model-create forms should carry a CSRF token."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "forms.xml").write_text(
        """<odoo>
  <template id="contact">
    <form action="/website/form/crm.lead" method="post">
      <input name="name"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-missing-csrf-token" and f.severity == "high" for f in findings)


def test_flags_external_success_redirect(tmp_path: Path) -> None:
    """Website form success pages should not redirect to arbitrary external origins."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "forms.xml").write_text(
        """<odoo>
  <template id="contact">
    <form action="/website/form/crm.lead" method="post" data-success-page="https://evil.example/thanks">
      <input type="hidden" name="csrf_token" t-att-value="request.csrf_token()"/>
      <input name="name"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-external-success-redirect" for f in findings)


def test_flags_dangerous_success_redirect_scheme(tmp_path: Path) -> None:
    """Website form success pages should not use executable URL schemes."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "forms.xml").write_text(
        """<odoo>
  <template id="contact">
    <form action="/website/form/crm.lead" method="post" data-success-page="javascript:alert(document.domain)">
      <input type="hidden" name="csrf_token" t-att-value="request.csrf_token()"/>
      <input name="name"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(
        f.rule_id == "odoo-website-form-dangerous-success-redirect"
        and f.field == "success_page"
        and f.severity == "high"
        for f in findings
    )


def test_flags_hidden_model_selector(tmp_path: Path) -> None:
    """Legacy hidden model selectors should be surfaced for tamper review."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "legacy.xml").write_text(
        """<odoo>
  <template id="legacy">
    <form method="post">
      <input type="hidden" name="model_name" value="res.partner"/>
      <input name="name"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-hidden-model-selector" for f in findings)


def test_flags_website_form_sanitize_form_disabled_input(tmp_path: Path) -> None:
    """Forms should not let clients turn off website_form sanitization."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "forms.xml").write_text(
        """<odoo>
  <template id="contact">
    <form action="/website/form/crm.lead" method="post">
      <input type="hidden" name="sanitize_form" value="false"/>
      <textarea name="description"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-sanitize-disabled" and f.severity == "high" for f in findings)


def test_flags_website_form_sanitize_form_disabled_call(tmp_path: Path) -> None:
    """Custom website_form call sites should not disable sanitization."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http

class Form(http.Controller):
    @http.route('/x/form', auth='public', type='http')
    def form(self, **post):
        return self.extract_data('crm.lead', post, sanitize_form=False)
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-sanitize-disabled" and f.field == "sanitize_form" for f in findings)


def test_flags_website_form_sanitize_form_disabled_constant_call(tmp_path: Path) -> None:
    """sanitize_form constants should not hide disabled website_form sanitization."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http

SANITIZE_FORM = False

class Form(http.Controller):
    @http.route('/x/form', auth='public', type='http')
    def form(self, **post):
        return self.extract_data('crm.lead', post, sanitize_form=SANITIZE_FORM)
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-sanitize-disabled" and f.field == "sanitize_form" for f in findings)


def test_flags_website_form_sanitize_form_disabled_local_constant_call(tmp_path: Path) -> None:
    """Function-local sanitize_form constants should not hide disabled website_form sanitization."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http

class Form(http.Controller):
    @http.route('/x/form', auth='public', type='http')
    def form(self, **post):
        sanitize = False
        return self.extract_data('crm.lead', post, sanitize_form=sanitize)
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-sanitize-disabled" and f.field == "sanitize_form" for f in findings)


def test_flags_website_form_sanitize_form_disabled_dict_union_call(tmp_path: Path) -> None:
    """Dict-union call kwargs should not hide disabled website_form sanitization."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http

BASE_OPTIONS = {'sanitize_form': True}
EXTRACT_OPTIONS = BASE_OPTIONS | {'sanitize_form': False}

class Form(http.Controller):
    @http.route('/x/form', auth='public', type='http')
    def form(self, **post):
        return self.extract_data('crm.lead', post, **EXTRACT_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-sanitize-disabled" and f.field == "sanitize_form" for f in findings)


def test_flags_data_model_alias_and_qweb_sensitive_field(tmp_path: Path) -> None:
    """Common model/field attribute variants should not hide website form risk."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "forms.xml").write_text(
        """<odoo>
  <template id="signup">
    <form data-model="res.users" method="post">
      <input type="hidden" name="csrf_token" t-att-value="request.csrf_token()"/>
      <input t-att-name="'groups_id'"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-website-form-public-model-create" in rule_ids
    assert "odoo-website-form-sensitive-field" in rule_ids
    assert any(f.model == "res.users" and f.severity == "high" for f in findings)


def test_flags_token_visibility_and_relational_website_form_fields(tmp_path: Path) -> None:
    """Public website forms should not expose token, visibility, or chatter controls."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "forms.xml").write_text(
        """<odoo>
  <template id="lead">
    <form action="/website/form/crm.lead" method="post">
      <input type="hidden" name="csrf_token" t-att-value="request.csrf_token()"/>
      <input name="signup_token"/>
      <input name="access_url"/>
      <input name="attachment_ids"/>
      <input name="message_follower_ids"/>
      <input name="website_published"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)
    sensitive_fields = {
        finding.field for finding in findings if finding.rule_id == "odoo-website-form-sensitive-field"
    }

    assert {
        "signup_token",
        "access_url",
        "attachment_ids",
        "message_follower_ids",
        "website_published",
    } <= sensitive_fields


def test_flags_broad_sensitive_website_form_fields(tmp_path: Path) -> None:
    """Public website forms should catch key-shaped fields beyond exact names."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "forms.xml").write_text(
        """<odoo>
  <template id="lead">
    <form action="/website/form/crm.lead" method="post">
      <input type="hidden" name="csrf_token" t-att-value="request.csrf_token()"/>
      <input name="license_key"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(
        finding.rule_id == "odoo-website-form-sensitive-field" and finding.field == "license_key"
        for finding in findings
    )


def test_flags_data_model_name_dash_variant(tmp_path: Path) -> None:
    """data-model-name should be treated like Odoo's data-model_name."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "forms.xml").write_text(
        """<odoo>
  <template id="lead">
    <form data-model-name="crm.lead" method="post">
      <input type="hidden" name="csrf_token" t-att-value="request.csrf_token()"/>
      <input name="name"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-public-model-create" and f.model == "crm.lead" for f in findings)


def test_flags_qweb_formatted_data_model_attribute(tmp_path: Path) -> None:
    """Formatted QWeb model attributes should still expose website form model creation."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "forms.xml").write_text(
        """<odoo>
  <template id="lead">
    <form t-attf-data-model_name="res.users" method="post">
      <input name="groups_id"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-website-form-public-model-create" in rule_ids
    assert "odoo-website-form-sensitive-field" in rule_ids
    assert any(f.model == "res.users" and f.severity == "high" for f in findings)


def test_flags_qweb_external_success_redirect(tmp_path: Path) -> None:
    """QWeb success-page attributes should still be checked for external URLs."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "forms.xml").write_text(
        """<odoo>
  <template id="lead">
    <form action="/website/form/crm.lead" method="post" t-att-data-success-page="'https://evil.example/thanks'">
      <input type="hidden" name="csrf_token" t-att-value="request.csrf_token()"/>
      <input name="name"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-external-success-redirect" for f in findings)


def test_flags_request_derived_qweb_success_redirect(tmp_path: Path) -> None:
    """Request-derived success pages can become open redirects after form submission."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "forms.xml").write_text(
        """<odoo>
  <template id="lead">
    <form action="/website/form/crm.lead" method="post" t-att-data-success-page="request.params.get('next')">
      <input type="hidden" name="csrf_token" t-att-value="request.csrf_token()"/>
      <input name="name"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(
        f.rule_id == "odoo-website-form-dynamic-success-redirect"
        and f.field == "success_page"
        and f.severity == "medium"
        for f in findings
    )


def test_flags_request_derived_formatted_success_redirect(tmp_path: Path) -> None:
    """Formatted success page attributes should still catch request-controlled targets."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "forms.xml").write_text(
        """<odoo>
  <template id="lead">
    <form action="/website/form/crm.lead" method="post" t-attf-data-success_page="/thanks?next=#{post.get('return_url')}">
      <input type="hidden" name="csrf_token" t-att-value="request.csrf_token()"/>
      <input name="name"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-dynamic-success-redirect" for f in findings)


def test_flags_qweb_dangerous_success_redirect_scheme(tmp_path: Path) -> None:
    """QWeb success-page attributes should catch executable data-document redirects."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "forms.xml").write_text(
        """<odoo>
  <template id="lead">
    <form action="/website/form/crm.lead" method="post" t-att-data-success-page="'data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;'">
      <input type="hidden" name="csrf_token" t-att-value="request.csrf_token()"/>
      <input name="name"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-dangerous-success-redirect" for f in findings)


def test_flags_qweb_dangerous_svg_success_redirect_scheme(tmp_path: Path) -> None:
    """QWeb success-page attributes should catch active SVG data-document redirects."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "forms.xml").write_text(
        """<odoo>
  <template id="lead">
    <form action="/website/form/crm.lead" method="post" t-att-data-success-page="'data:image/svg+xml,&lt;svg onload=&quot;alert(1)&quot;/&gt;'">
      <input type="hidden" name="csrf_token" t-att-value="request.csrf_token()"/>
      <input name="name"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-dangerous-success-redirect" for f in findings)


def test_flags_qweb_dynamic_website_form_action(tmp_path: Path) -> None:
    """QWeb action attributes can still post directly to website_form model creation."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "forms.xml").write_text(
        """<odoo>
  <template id="contact">
    <form t-att-action="'/website/form/crm.lead'" method="post">
      <input name="partner_id"/>
    </form>
  </template>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-website-form-public-model-create" in rule_ids
    assert "odoo-website-form-sensitive-field" in rule_ids
    assert "odoo-website-form-missing-csrf-token" in rule_ids
    assert {finding.model for finding in findings} == {"crm.lead"}


def test_flags_sensitive_model_field_allowlisted_for_website_form(tmp_path: Path) -> None:
    """Python field declarations can expose sensitive fields to website forms."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "lead.py").write_text(
        """
from odoo import fields, models

class Lead(models.Model):
    _inherit = 'crm.lead'

    partner_id = fields.Many2one('res.partner', website_form_blacklisted=False)
    x_public_note = fields.Char(website_form_blacklisted=False)
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(
        f.rule_id == "odoo-website-form-field-allowlisted-sensitive"
        and f.model == "crm.lead"
        and f.field == "partner_id"
        and f.severity == "high"
        for f in findings
    )


def test_flags_broad_sensitive_field_allowlisted_for_website_form(tmp_path: Path) -> None:
    """website_form_blacklisted=False should catch key-shaped custom fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "lead.py").write_text(
        """
from odoo import fields, models

class Lead(models.Model):
    _inherit = 'crm.lead'

    license_key = fields.Char(website_form_blacklisted=False)
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(
        f.rule_id == "odoo-website-form-field-allowlisted-sensitive"
        and f.field == "license_key"
        and f.severity == "high"
        for f in findings
    )


def test_flags_direct_field_constructor_allowlisted_for_website_form(tmp_path: Path) -> None:
    """Directly imported field constructors should not hide website form allowlists."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "lead.py").write_text(
        """
from odoo import models
from odoo.fields import Many2one

class Lead(models.Model):
    _inherit = 'crm.lead'

    partner_id = Many2one('res.partner', website_form_blacklisted=False)
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(
        f.rule_id == "odoo-website-form-field-allowlisted-sensitive"
        and f.model == "crm.lead"
        and f.field == "partner_id"
        and f.severity == "high"
        for f in findings
    )


def test_flags_aliased_odoo_fields_module_allowlisted_for_website_form(tmp_path: Path) -> None:
    """Aliased Odoo fields modules should not hide website form allowlists."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "lead.py").write_text(
        """
from odoo import fields as odoo_fields, models

class Lead(models.Model):
    _inherit = 'crm.lead'

    partner_id = odoo_fields.Many2one('res.partner', website_form_blacklisted=False)
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(
        f.rule_id == "odoo-website-form-field-allowlisted-sensitive"
        and f.model == "crm.lead"
        and f.field == "partner_id"
        for f in findings
    )


def test_flags_imported_odoo_fields_module_allowlisted_for_website_form(tmp_path: Path) -> None:
    """Direct odoo.fields imports should not hide website form allowlists."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "lead.py").write_text(
        """
from odoo import models
import odoo.fields as odoo_fields

class Lead(models.Model):
    _inherit = 'crm.lead'

    partner_id = odoo_fields.Many2one('res.partner', website_form_blacklisted=False)
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(
        f.rule_id == "odoo-website-form-field-allowlisted-sensitive"
        and f.model == "crm.lead"
        and f.field == "partner_id"
        for f in findings
    )


def test_flags_imported_odoo_module_fields_allowlisted_for_website_form(tmp_path: Path) -> None:
    """Direct odoo module imports should still expose website form allowlists."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "lead.py").write_text(
        """
import odoo as od

class Lead(od.models.Model):
    _inherit = 'crm.lead'

    partner_id = od.fields.Many2one('res.partner', website_form_blacklisted=False)
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(
        f.rule_id == "odoo-website-form-field-allowlisted-sensitive"
        and f.model == "crm.lead"
        and f.field == "partner_id"
        for f in findings
    )


def test_flags_constant_backed_sensitive_field_allowlisted_for_website_form(tmp_path: Path) -> None:
    """website_form_blacklisted constants should not hide sensitive field allowlists."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "lead.py").write_text(
        """
from odoo import fields, models

ALLOW_WEBSITE_FORM = False

class Lead(models.Model):
    _inherit = 'crm.lead'

    partner_id = fields.Many2one('res.partner', website_form_blacklisted=ALLOW_WEBSITE_FORM)
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(
        f.rule_id == "odoo-website-form-field-allowlisted-sensitive"
        and f.model == "crm.lead"
        and f.field == "partner_id"
        for f in findings
    )


def test_flags_dict_union_sensitive_field_allowlisted_for_website_form(tmp_path: Path) -> None:
    """Dict-union field kwargs should not hide sensitive website form allowlists."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "lead.py").write_text(
        """
from odoo import fields, models

BASE_OPTIONS = {'website_form_blacklisted': True}
FIELD_OPTIONS = BASE_OPTIONS | {'website_form_blacklisted': False}

class Lead(models.Model):
    _inherit = 'crm.lead'

    partner_id = fields.Many2one('res.partner', **FIELD_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(
        f.rule_id == "odoo-website-form-field-allowlisted-sensitive"
        and f.model == "crm.lead"
        and f.field == "partner_id"
        for f in findings
    )


def test_flags_class_constant_backed_sensitive_field_allowlisted_for_website_form(tmp_path: Path) -> None:
    """Class-body website_form_blacklisted constants should not hide sensitive field allowlists."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "lead.py").write_text(
        """
from odoo import fields, models

class Lead(models.Model):
    _inherit = 'crm.lead'
    ALLOW_WEBSITE_FORM = False

    partner_id = fields.Many2one('res.partner', website_form_blacklisted=ALLOW_WEBSITE_FORM)
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(
        f.rule_id == "odoo-website-form-field-allowlisted-sensitive"
        and f.model == "crm.lead"
        and f.field == "partner_id"
        for f in findings
    )


def test_flags_sensitive_model_custom_field_allowlisted_for_website_form(tmp_path: Path) -> None:
    """Allowlisting any field on a sensitive model should still be reviewable."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import fields, models

class Partner(models.Model):
    _name = 'res.partner'

    x_signup_source = fields.Char(website_form_blacklisted=False)
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(
        f.rule_id == "odoo-website-form-field-allowlisted-sensitive"
        and f.model == "res.partner"
        and f.field == "x_signup_source"
        and f.severity == "medium"
        for f in findings
    )


def test_flags_website_form_route_with_csrf_disabled(tmp_path: Path) -> None:
    """Custom website form routes should not disable CSRF protection."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http

class WebsiteForm(http.Controller):
    @http.route('/website/form/crm.lead', type='http', auth='public', methods=['POST'], csrf=False)
    def website_form(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-route-csrf-disabled" and f.severity == "high" for f in findings)


def test_flags_website_form_route_list_with_csrf_disabled(tmp_path: Path) -> None:
    """Route lists can hide website_form paths behind another alias."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http

class WebsiteForm(http.Controller):
    @http.route(['/contactus', '/website/form/helpdesk.ticket'], auth='public', csrf=False)
    def submit(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-route-csrf-disabled" for f in findings)


def test_flags_imported_route_website_form_csrf_disabled(tmp_path: Path) -> None:
    """Imported route decorators should not hide website form CSRF disablement."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import route

class WebsiteForm(http.Controller):
    @route('/website/form/crm.lead', type='http', auth='public', methods=['POST'], csrf=False)
    def website_form(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-route-csrf-disabled" for f in findings)


def test_flags_aliased_http_module_website_form_csrf_disabled(tmp_path: Path) -> None:
    """Aliased odoo.http module route decorators should remain recognized."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http as odoo_http

class WebsiteForm(odoo_http.Controller):
    @odoo_http.route('/website/form/crm.lead', type='http', auth='public', methods=['POST'], csrf=False)
    def website_form(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-route-csrf-disabled" for f in findings)


def test_flags_imported_odoo_http_module_website_form_csrf_disabled(tmp_path: Path) -> None:
    """Direct odoo.http imports should not hide website form CSRF disablement."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
import odoo.http as odoo_http

class WebsiteForm(odoo_http.Controller):
    @odoo_http.route('/website/form/crm.lead', type='http', auth='public', methods=['POST'], csrf=False)
    def website_form(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-route-csrf-disabled" for f in findings)


def test_flags_imported_odoo_module_website_form_csrf_disabled(tmp_path: Path) -> None:
    """Direct odoo imports should not hide website form CSRF disablement."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
import odoo as od

class WebsiteForm(od.http.Controller):
    @od.http.route('/website/form/crm.lead', type='http', auth='public', methods=['POST'], csrf=False)
    def website_form(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-route-csrf-disabled" for f in findings)


def test_non_odoo_route_website_form_csrf_disabled_is_ignored(tmp_path: Path) -> None:
    """Local route decorators should not be treated as Odoo website form routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http

class Router:
    def route(self, *args, **kwargs):
        def decorate(func):
            return func
        return decorate

router = Router()

class WebsiteForm(http.Controller):
    @router.route('/website/form/crm.lead', type='http', auth='public', methods=['POST'], csrf=False)
    def website_form(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    assert scan_website_forms(tmp_path) == []


def test_flags_constant_backed_website_form_route_with_csrf_disabled(tmp_path: Path) -> None:
    """Route and csrf constants should not hide website_form CSRF disablement."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http

FORM_ROUTES = ['/contactus', '/website/form/helpdesk.ticket']
CSRF_ENABLED = False

class WebsiteForm(http.Controller):
    @http.route(FORM_ROUTES, auth='public', csrf=CSRF_ENABLED)
    def submit(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-route-csrf-disabled" for f in findings)


def test_flags_dict_union_website_form_route_with_csrf_disabled(tmp_path: Path) -> None:
    """Dict-union route kwargs should not hide website_form CSRF disablement."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http

BASE_OPTIONS = {
    'route': ['/contactus', '/website/form/helpdesk.ticket'],
    'csrf': True,
}
ROUTE_OPTIONS = BASE_OPTIONS | {'auth': 'public', 'csrf': False}

class WebsiteForm(http.Controller):
    @http.route(**ROUTE_OPTIONS)
    def submit(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-route-csrf-disabled" for f in findings)


def test_flags_class_constant_backed_website_form_route_with_csrf_disabled(tmp_path: Path) -> None:
    """Class-body route and csrf constants should not hide website_form CSRF disablement."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http

class WebsiteForm(http.Controller):
    FORM_ROUTES = ['/contactus', '/website/form/helpdesk.ticket']
    CSRF_ENABLED = False

    @http.route(FORM_ROUTES, auth='public', csrf=CSRF_ENABLED)
    def submit(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_website_forms(tmp_path)

    assert any(f.rule_id == "odoo-website-form-route-csrf-disabled" for f in findings)


def test_non_website_form_csrf_disabled_route_is_ignored(tmp_path: Path) -> None:
    """The website form route rule should stay scoped to website_form endpoints."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http

class Api(http.Controller):
    @http.route('/api/ping', auth='public', csrf=False)
    def ping(self):
        return 'pong'
""",
        encoding="utf-8",
    )

    assert scan_website_forms(tmp_path) == []


def test_safe_regular_form_is_ignored(tmp_path: Path) -> None:
    """Normal non-website-form XML forms should not be flagged."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "regular.xml").write_text(
        """<odoo>
  <record id="view_form" model="ir.ui.view">
    <field name="arch" type="xml">
      <form><field name="name"/></form>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_website_forms(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """XML fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "form.xml").write_text(
        """<odoo><template id="x"><form action="/website/form/crm.lead"/></template></odoo>""",
        encoding="utf-8",
    )

    assert scan_website_forms(tmp_path) == []
