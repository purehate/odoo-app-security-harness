"""Tests for Odoo property/company-dependent field scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.property_field_scanner import scan_property_fields


def test_xml_entities_are_not_expanded_into_property_findings(tmp_path: Path) -> None:
    """XML entities must not synthesize global sensitive property findings."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "entity.xml").write_text(
        """<!DOCTYPE odoo [
<!ENTITY sensitive_field "account.field_res_partner__property_account_receivable_id">
]>
<odoo>
  <record id="property_entity" model="ir.property">
    <field name="fields_id" ref="&sensitive_field;"/>
    <field name="value_reference">account.account,1</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_property_fields(tmp_path) == []


def test_flags_company_dependent_field_without_company_id(tmp_path: Path) -> None:
    """Company-dependent fields on company-less models rely on property fallback behavior."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import fields, models

class Product(models.Model):
    _name = 'x.product'

    property_account_income_id = fields.Many2one('account.account', company_dependent=True)
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(f.rule_id == "odoo-property-field-no-company-field" for f in findings)


def test_flags_direct_field_constructor_company_dependent_field(tmp_path: Path) -> None:
    """Directly imported field constructors should still be scanned."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import models
from odoo.fields import Many2one

class Product(models.Model):
    _name = 'x.product'

    property_account_income_id = Many2one('account.account', company_dependent=True)
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(f.rule_id == "odoo-property-field-no-company-field" for f in findings)


def test_flags_aliased_odoo_fields_module_company_dependent_field(tmp_path: Path) -> None:
    """Aliased Odoo fields modules should still be scanned."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import fields as odoo_fields, models

class Product(models.Model):
    _name = 'x.product'

    property_account_income_id = odoo_fields.Many2one('account.account', company_dependent=True)
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(f.rule_id == "odoo-property-field-no-company-field" for f in findings)


def test_flags_imported_odoo_fields_module_company_dependent_field(tmp_path: Path) -> None:
    """Direct odoo.fields imports should still be scanned."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import models
import odoo.fields as odoo_fields

class Product(models.Model):
    _name = 'x.product'

    property_account_income_id = odoo_fields.Many2one('account.account', company_dependent=True)
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(f.rule_id == "odoo-property-field-no-company-field" for f in findings)


def test_flags_imported_odoo_module_fields_company_dependent_field(tmp_path: Path) -> None:
    """Direct odoo module imports should still expose company-dependent fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
import odoo as od

class Product(od.models.Model):
    _name = 'x.product'

    property_account_income_id = od.fields.Many2one('account.account', company_dependent=True)
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(f.rule_id == "odoo-property-field-no-company-field" for f in findings)


def test_flags_direct_model_base_company_dependent_field(tmp_path: Path) -> None:
    """Direct Model bases should not hide company-dependent property fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import fields
from odoo.models import Model

class Product(Model):
    _name = 'x.product'

    property_account_income_id = fields.Many2one('account.account', company_dependent=True)
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(f.rule_id == "odoo-property-field-no-company-field" for f in findings)


def test_flags_annotated_company_dependent_field(tmp_path: Path) -> None:
    """Annotated property field declarations should be scanned."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import fields, models

class Product(models.Model):
    _name = 'x.product'

    property_account_income_id: fields.Many2one = fields.Many2one('account.account', company_dependent=True)
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(f.rule_id == "odoo-property-field-no-company-field" for f in findings)


def test_flags_sensitive_company_dependent_field_without_groups_and_default(tmp_path: Path) -> None:
    """Sensitive property fields should be restricted and defaulted carefully."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "account.py").write_text(
        """
from odoo import fields, models

class AccountConfig(models.Model):
    _name = 'x.account.config'
    company_id = fields.Many2one('res.company')
    property_journal_id = fields.Many2one('account.journal', company_dependent=True, default=lambda self: self.env.company.id)
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-sensitive-field-no-groups" in rule_ids
    assert "odoo-property-field-default" in rule_ids


def test_recursive_constant_company_dependent_field_options_are_reported(tmp_path: Path) -> None:
    """Recursive constant field options should not hide company-dependent property fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "account.py").write_text(
        """
from odoo import fields, models

MODEL_NAME = 'x.account.config'
MODEL_ALIAS = MODEL_NAME
PROPERTY_FIELD = True
PROPERTY_ALIAS = PROPERTY_FIELD

class AccountConfig(models.Model):
    _name = MODEL_ALIAS
    property_journal_id = fields.Many2one('account.journal', company_dependent=PROPERTY_ALIAS)
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    field_findings = [finding for finding in findings if finding.field == "property_journal_id"]
    rule_ids = {finding.rule_id for finding in field_findings}

    assert "odoo-property-field-no-company-field" in rule_ids
    assert "odoo-property-sensitive-field-no-groups" in rule_ids
    assert any(finding.model == "x.account.config" for finding in field_findings)


def test_class_constant_company_dependent_field_options_are_reported(tmp_path: Path) -> None:
    """Class-scoped field options should not hide company-dependent property fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "account.py").write_text(
        """
from odoo import fields, models

class AccountConfig(models.Model):
    MODEL_NAME = 'x.account.config'
    MODEL_ALIAS = MODEL_NAME
    PROPERTY_FIELD = True
    PROPERTY_ALIAS = PROPERTY_FIELD
    _name = MODEL_ALIAS
    property_journal_id = fields.Many2one('account.journal', company_dependent=PROPERTY_ALIAS)
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    field_findings = [finding for finding in findings if finding.field == "property_journal_id"]
    rule_ids = {finding.rule_id for finding in field_findings}

    assert "odoo-property-field-no-company-field" in rule_ids
    assert "odoo-property-sensitive-field-no-groups" in rule_ids
    assert any(finding.model == "x.account.config" for finding in field_findings)


def test_nested_static_unpack_company_dependent_field_options_are_reported(tmp_path: Path) -> None:
    """Nested static field options should not hide company-dependent property fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "account.py").write_text(
        """
from odoo import fields, models

BASE_OPTIONS = {'company_dependent': True}
FIELD_OPTIONS = {**BASE_OPTIONS}

class AccountConfig(models.Model):
    _name = 'x.account.config'
    property_journal_id = fields.Many2one('account.journal', **FIELD_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    field_findings = [finding for finding in findings if finding.field == "property_journal_id"]
    rule_ids = {finding.rule_id for finding in field_findings}

    assert "odoo-property-field-no-company-field" in rule_ids
    assert "odoo-property-sensitive-field-no-groups" in rule_ids


def test_flags_global_ir_property_record(tmp_path: Path) -> None:
    """Global property records can leak defaults across companies."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "properties.xml").write_text(
        """<odoo>
  <record id="property_receivable_global" model="ir.property">
    <field name="fields_id" ref="account.field_res_partner__property_account_receivable_id"/>
    <field name="value_reference">account.account,1</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-global-default" in rule_ids
    assert "odoo-property-no-resource-scope" in rule_ids
    assert "odoo-property-sensitive-value" in rule_ids


def test_flags_global_ir_property_csv_record(tmp_path: Path) -> None:
    """CSV ir.property rows should use the same global-default checks as XML."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.property.csv").write_text(
        "id,fields_id/id,value_reference\n"
        'property_receivable_global,account.field_res_partner__property_account_receivable_id,"account.account,1"\n',
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-global-default" in rule_ids
    assert "odoo-property-no-resource-scope" in rule_ids
    assert "odoo-property-sensitive-value" in rule_ids


def test_flags_global_ir_property_csv_colon_field_record(tmp_path: Path) -> None:
    """CSV ir.property rows exported with colon headers should resolve field refs."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.property.csv").write_text(
        "id,fields_id:id,value_reference\n"
        'property_receivable_global,account.field_res_partner__property_account_receivable_id,"account.account,1"\n',
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-global-default" in rule_ids
    assert "odoo-property-no-resource-scope" in rule_ids
    assert "odoo-property-sensitive-value" in rule_ids


def test_safe_company_scoped_property_csv_is_ignored(tmp_path: Path) -> None:
    """Company-scoped non-sensitive CSV properties should avoid noise."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir_property.csv").write_text(
        "id,fields_id/id,company_id/id,res_id,value_text\n"
        'property_label_company,x_module.field_x_model__property_label,base.main_company,"x.model,1",Label\n',
        encoding="utf-8",
    )

    assert scan_property_fields(tmp_path) == []


def test_flags_credential_and_provider_property_values(tmp_path: Path) -> None:
    """Credential and payment-provider properties should be sensitive defaults."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "properties.xml").write_text(
        """<odoo>
  <record id="property_gateway_key" model="ir.property">
    <field name="fields_id" ref="payment.field_payment_provider__api_key"/>
    <field name="value_text">test-secret</field>
  </record>
  <record id="property_provider_default" model="ir.property">
    <field name="fields_id" ref="payment.field_res_company__property_payment_provider_id"/>
    <field name="value_reference">payment.provider,1</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    sensitive_fields = {finding.field for finding in findings if finding.rule_id == "odoo-property-sensitive-value"}

    assert {
        "payment.field_payment_provider__api_key",
        "payment.field_res_company__property_payment_provider_id",
    } <= sensitive_fields


def test_flags_integration_key_property_values(tmp_path: Path) -> None:
    """Integration-key shaped ir.property fields should be sensitive defaults."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "properties.xml").write_text(
        """<odoo>
  <record id="property_connector_access_key" model="ir.property">
    <field name="fields_id" ref="x_connector.field_x_connector__access_key"/>
    <field name="value_text">ak_live_abcdef1234567890</field>
  </record>
  <record id="property_connector_license_key" model="ir.property">
    <field name="fields_id" ref="x_connector.field_x_connector__license_key"/>
    <field name="value_text">lic_live_abcdef1234567890</field>
  </record>
  <record id="property_connector_access_url" model="ir.property">
    <field name="fields_id" ref="x_connector.field_x_connector__access_url"/>
    <field name="value_text">https://example.test/private</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    sensitive_fields = {finding.field for finding in findings if finding.rule_id == "odoo-property-sensitive-value"}

    assert {
        "x_connector.field_x_connector__access_key",
        "x_connector.field_x_connector__license_key",
        "x_connector.field_x_connector__access_url",
    } <= sensitive_fields


def test_flags_public_sudo_runtime_property_create(tmp_path: Path) -> None:
    """Public routes must not create request-controlled property defaults."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request

class Properties(http.Controller):
    @http.route('/properties/account', auth='public', csrf=False)
    def set_property(self, **kwargs):
        return request.env['ir.property'].sudo().create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': kwargs.get('account'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-public-route-mutation" in rule_ids
    assert "odoo-property-sudo-mutation" in rule_ids
    assert "odoo-property-request-derived-mutation" in rule_ids
    assert "odoo-property-runtime-global-default" in rule_ids
    assert "odoo-property-runtime-no-resource-scope" in rule_ids
    assert "odoo-property-runtime-sensitive-value" in rule_ids


def test_constant_backed_public_sudo_runtime_property_create(tmp_path: Path) -> None:
    """Constant-backed public route auth should not hide public property mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request

PROPERTY_ROUTE = '/properties/account'
PROPERTY_AUTH = 'public'

class Properties(http.Controller):
    @http.route(PROPERTY_ROUTE, auth=PROPERTY_AUTH, csrf=False)
    def set_property(self, **kwargs):
        return request.env['ir.property'].sudo().create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': kwargs.get('account'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-public-route-mutation" in rule_ids
    assert "odoo-property-sudo-mutation" in rule_ids
    assert any(
        finding.rule_id == "odoo-property-request-derived-mutation" and finding.severity == "critical"
        for finding in findings
    )


def test_keyword_constant_backed_none_runtime_property_create_is_critical(tmp_path: Path) -> None:
    """Keyword route constants with auth='none' should keep property mutations critical."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request

PROPERTY_ROUTE = '/properties/account'
PROPERTY_AUTH = 'none'

class Properties(http.Controller):
    @http.route(route=PROPERTY_ROUTE, auth=PROPERTY_AUTH, csrf=False)
    def set_property(self, **kwargs):
        return request.env['ir.property'].create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': kwargs.get('account'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(
        finding.rule_id == "odoo-property-public-route-mutation" and finding.severity == "critical"
        for finding in findings
    )
    assert any(
        finding.rule_id == "odoo-property-request-derived-mutation" and finding.severity == "critical"
        for finding in findings
    )


def test_recursive_constant_backed_public_runtime_property_create(tmp_path: Path) -> None:
    """Recursive route and mutation constants should keep public ir.property writes visible."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request

PROPERTY_ROUTE = '/properties/account'
ROUTE_ALIAS = PROPERTY_ROUTE
PUBLIC_AUTH = 'public'
AUTH_ALIAS = PUBLIC_AUTH
PROPERTY_MODEL = 'ir.property'
MODEL_ALIAS = PROPERTY_MODEL
FIELD_KEY = 'fields_id'
FIELD_ALIAS = FIELD_KEY
VALUE_KEY = 'value_reference'
VALUE_ALIAS = VALUE_KEY
FIELD_REF = 'account.field_res_partner__property_account_receivable_id'
FIELD_REF_ALIAS = FIELD_REF

class Properties(http.Controller):
    @http.route(ROUTE_ALIAS, auth=AUTH_ALIAS, csrf=False)
    def set_property(self, **kwargs):
        return request.env[MODEL_ALIAS].sudo().create({
            FIELD_ALIAS: FIELD_REF_ALIAS,
            VALUE_ALIAS: kwargs.get('account'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-public-route-mutation" in rule_ids
    assert "odoo-property-sudo-mutation" in rule_ids
    assert "odoo-property-request-derived-mutation" in rule_ids
    assert "odoo-property-runtime-sensitive-value" in rule_ids


def test_imported_route_decorator_public_sudo_runtime_property_create(tmp_path: Path) -> None:
    """Imported route decorators should not hide public property mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request, route

class Properties(http.Controller):
    @route('/properties/account', auth='public', csrf=False)
    def set_property(self, **kwargs):
        return request.env['ir.property'].sudo().create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': kwargs.get('account'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-public-route-mutation" in rule_ids
    assert "odoo-property-sudo-mutation" in rule_ids
    assert "odoo-property-request-derived-mutation" in rule_ids
    assert "odoo-property-runtime-global-default" in rule_ids
    assert "odoo-property-runtime-no-resource-scope" in rule_ids
    assert "odoo-property-runtime-sensitive-value" in rule_ids


def test_aliased_imported_route_decorator_public_sudo_runtime_property_create(tmp_path: Path) -> None:
    """Aliased imported route decorators should not hide public property mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request, route as public_route

class Properties(http.Controller):
    @public_route('/properties/account', auth='public', csrf=False)
    def set_property(self, **kwargs):
        return request.env['ir.property'].sudo().create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': kwargs.get('account'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-public-route-mutation" in rule_ids
    assert "odoo-property-sudo-mutation" in rule_ids
    assert "odoo-property-request-derived-mutation" in rule_ids
    assert "odoo-property-runtime-sensitive-value" in rule_ids


def test_aliased_http_module_route_public_sudo_runtime_property_create(tmp_path: Path) -> None:
    """Aliased odoo.http module route decorators should remain recognized."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http as odoo_http
from odoo.http import request

class Properties(odoo_http.Controller):
    @odoo_http.route('/properties/account', auth='public', csrf=False)
    def set_property(self, **kwargs):
        return request.env['ir.property'].sudo().create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': kwargs.get('account'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-public-route-mutation" in rule_ids
    assert "odoo-property-sudo-mutation" in rule_ids
    assert "odoo-property-request-derived-mutation" in rule_ids
    assert "odoo-property-runtime-sensitive-value" in rule_ids


def test_imported_odoo_http_module_public_sudo_runtime_property_create(tmp_path: Path) -> None:
    """Direct odoo.http imports should not hide public property mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
import odoo.http as odoo_http

class Properties(odoo_http.Controller):
    @odoo_http.route('/properties/account', auth='public', csrf=False)
    def set_property(self, **kwargs):
        return odoo_http.request.env['ir.property'].sudo().create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': kwargs.get('account'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-public-route-mutation" in rule_ids
    assert "odoo-property-sudo-mutation" in rule_ids
    assert "odoo-property-request-derived-mutation" in rule_ids
    assert "odoo-property-runtime-sensitive-value" in rule_ids


def test_imported_odoo_module_public_sudo_runtime_property_create(tmp_path: Path) -> None:
    """Direct odoo module imports should not hide public property mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
import odoo as od

class Properties(od.http.Controller):
    @od.http.route('/properties/account', auth='public', csrf=False)
    def set_property(self, **kwargs):
        return od.http.request.env['ir.property'].sudo().create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': kwargs.get('account'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-public-route-mutation" in rule_ids
    assert "odoo-property-sudo-mutation" in rule_ids
    assert "odoo-property-request-derived-mutation" in rule_ids
    assert "odoo-property-runtime-sensitive-value" in rule_ids


def test_non_odoo_route_decorator_runtime_property_create_is_not_public(tmp_path: Path) -> None:
    """Local route decorators should not make property mutations public routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request

class Router:
    def route(self, *args, **kwargs):
        def decorate(func):
            return func
        return decorate

router = Router()

class Properties(http.Controller):
    @router.route('/properties/account', auth='public', csrf=False)
    def set_property(self, **kwargs):
        return request.env['ir.property'].sudo().create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': kwargs.get('account'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-public-route-mutation" not in rule_ids
    assert "odoo-property-sudo-mutation" in rule_ids
    assert "odoo-property-request-derived-mutation" in rule_ids
    assert "odoo-property-runtime-sensitive-value" in rule_ids


def test_static_unpack_public_route_options_property_create(tmp_path: Path) -> None:
    """Static route option unpacking should preserve public property-mutation context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request

ROUTE_OPTIONS = {'auth': 'public', 'csrf': False}

class Properties(http.Controller):
    @http.route('/properties/account', **ROUTE_OPTIONS)
    def set_property(self, **kwargs):
        return request.env['ir.property'].sudo().create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': kwargs.get('account'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-public-route-mutation" in rule_ids
    assert "odoo-property-sudo-mutation" in rule_ids
    assert "odoo-property-request-derived-mutation" in rule_ids
    assert "odoo-property-runtime-sensitive-value" in rule_ids


def test_nested_static_unpack_public_route_options_property_create(tmp_path: Path) -> None:
    """Nested route option unpacking should preserve public property-mutation context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request

BASE_OPTIONS = {'auth': 'public'}
ROUTE_OPTIONS = {**BASE_OPTIONS, 'csrf': False}

class Properties(http.Controller):
    @http.route('/properties/account', **ROUTE_OPTIONS)
    def set_property(self, **kwargs):
        return request.env['ir.property'].sudo().create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': kwargs.get('account'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-public-route-mutation" in rule_ids
    assert "odoo-property-sudo-mutation" in rule_ids
    assert "odoo-property-request-derived-mutation" in rule_ids
    assert "odoo-property-runtime-sensitive-value" in rule_ids


def test_class_constant_public_sudo_runtime_property_create(tmp_path: Path) -> None:
    """Class-scoped route and mutation constants should keep public ir.property writes visible."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request

class Properties(http.Controller):
    PROPERTY_ROUTE = '/properties/account'
    ROUTE_ALIAS = PROPERTY_ROUTE
    PUBLIC_AUTH = 'public'
    AUTH_ALIAS = PUBLIC_AUTH
    PROPERTY_MODEL = 'ir.property'
    MODEL_ALIAS = PROPERTY_MODEL
    FIELD_KEY = 'fields_id'
    FIELD_ALIAS = FIELD_KEY
    VALUE_KEY = 'value_reference'
    VALUE_ALIAS = VALUE_KEY
    FIELD_REF = 'account.field_res_partner__property_account_receivable_id'
    FIELD_REF_ALIAS = FIELD_REF

    @http.route(ROUTE_ALIAS, auth=AUTH_ALIAS, csrf=False)
    def set_property(self, **kwargs):
        return request.env[MODEL_ALIAS].sudo().create({
            FIELD_ALIAS: FIELD_REF_ALIAS,
            VALUE_ALIAS: kwargs.get('account'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-public-route-mutation" in rule_ids
    assert "odoo-property-sudo-mutation" in rule_ids
    assert "odoo-property-request-derived-mutation" in rule_ids
    assert "odoo-property-runtime-sensitive-value" in rule_ids


def test_local_constant_public_sudo_runtime_property_create(tmp_path: Path) -> None:
    """Function-local mutation constants should keep public ir.property writes visible."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request

class Properties(http.Controller):
    @http.route('/properties/account', auth='public', csrf=False)
    def set_property(self, **kwargs):
        property_model = 'ir.property'
        field_key = 'fields_id'
        value_key = 'value_reference'
        field_ref = 'account.field_res_partner__property_account_receivable_id'
        return request.env[property_model].sudo().create({
            field_key: field_ref,
            value_key: kwargs.get('account'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-public-route-mutation" in rule_ids
    assert "odoo-property-sudo-mutation" in rule_ids
    assert "odoo-property-request-derived-mutation" in rule_ids
    assert "odoo-property-runtime-sensitive-value" in rule_ids


def test_class_constant_static_unpack_public_route_options_property_create(tmp_path: Path) -> None:
    """Class-scoped static route option unpacking should preserve public mutation context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request

class Properties(http.Controller):
    AUTH_BASE = 'public'
    ROUTE_OPTIONS = {'auth': AUTH_BASE, 'csrf': False}

    @http.route('/properties/account', **ROUTE_OPTIONS)
    def set_property(self, **kwargs):
        return request.env['ir.property'].sudo().create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': kwargs.get('account'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-public-route-mutation" in rule_ids
    assert "odoo-property-sudo-mutation" in rule_ids
    assert "odoo-property-request-derived-mutation" in rule_ids
    assert "odoo-property-runtime-sensitive-value" in rule_ids


def test_superuser_with_user_property_mutation_is_elevated(tmp_path: Path) -> None:
    """Admin-root with_user should be treated like sudo for ir.property mutation."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "properties.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class Properties(models.Model):
    _name = 'x.properties'

    def set_property(self):
        return self.env['ir.property'].with_user(user=SUPERUSER_ID).create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': 'account.account,1',
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(finding.rule_id == "odoo-property-sudo-mutation" for finding in findings)


def test_import_aliased_superuser_with_user_property_mutation_is_elevated(tmp_path: Path) -> None:
    """Imported SUPERUSER_ID aliases should be treated like sudo for ir.property mutation."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "properties.py").write_text(
        """
from odoo import SUPERUSER_ID as ROOT_UID, models

class Properties(models.Model):
    _name = 'x.properties'

    def set_property(self):
        return self.env['ir.property'].with_user(user=ROOT_UID).create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': 'account.account,1',
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(finding.rule_id == "odoo-property-sudo-mutation" for finding in findings)


def test_recursive_constant_superuser_property_mutation_is_elevated(tmp_path: Path) -> None:
    """Recursive superuser aliases should be treated like sudo for ir.property mutation."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "properties.py").write_text(
        """
from odoo import models

ROOT_UID = 1
ADMIN_UID = ROOT_UID
PROPERTY_MODEL = 'ir.property'
MODEL_ALIAS = PROPERTY_MODEL

class Properties(models.Model):
    _name = 'x.properties'

    def set_property(self):
        return self.env[MODEL_ALIAS].with_user(user=ADMIN_UID).create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': 'account.account,1',
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(finding.rule_id == "odoo-property-sudo-mutation" for finding in findings)


def test_class_constant_superuser_property_mutation_is_elevated(tmp_path: Path) -> None:
    """Class-scoped superuser aliases should be treated like sudo for ir.property mutation."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "properties.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class Properties(models.Model):
    _name = 'x.properties'
    ROOT_UID = SUPERUSER_ID
    ADMIN_UID = ROOT_UID
    PROPERTY_MODEL = 'ir.property'
    MODEL_ALIAS = PROPERTY_MODEL

    def set_property(self):
        return self.env[MODEL_ALIAS].with_user(user=ADMIN_UID).create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': 'account.account,1',
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(finding.rule_id == "odoo-property-sudo-mutation" for finding in findings)


def test_local_constant_superuser_property_mutation_is_elevated(tmp_path: Path) -> None:
    """Function-local superuser aliases should be treated like sudo for ir.property mutation."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "properties.py").write_text(
        """
from odoo import models

class Properties(models.Model):
    _name = 'x.properties'

    def set_property(self):
        root_uid = 1
        property_model = 'ir.property'
        return self.env[property_model].with_user(user=root_uid).create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': 'account.account,1',
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(finding.rule_id == "odoo-property-sudo-mutation" for finding in findings)


def test_regular_with_user_property_mutation_is_not_elevated(tmp_path: Path) -> None:
    """Regular user context switches should not be reported as sudo/property elevation."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "properties.py").write_text(
        """
from odoo import models

class Properties(models.Model):
    _name = 'x.properties'

    def set_property(self, user):
        return self.env['ir.property'].with_user(user).create({
            'fields_id': 'x.field_note',
            'value_text': 'ok',
            'res_id': 'res.partner,1',
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert not any(finding.rule_id == "odoo-property-sudo-mutation" for finding in findings)


def test_request_alias_public_runtime_property_create(tmp_path: Path) -> None:
    """Aliased request imports should still taint public ir.property mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Properties(http.Controller):
    @http.route('/properties/account', auth='public', csrf=False)
    def set_property(self):
        payload = req.get_http_params()
        return req.env['ir.property'].sudo().create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': payload.get('account'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-public-route-mutation" in rule_ids
    assert "odoo-property-sudo-mutation" in rule_ids
    assert "odoo-property-request-derived-mutation" in rule_ids


def test_request_alias_direct_property_value_is_reported(tmp_path: Path) -> None:
    """Direct values read from an aliased request should taint property writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Properties(http.Controller):
    @http.route('/properties/account', auth='user', csrf=False)
    def set_property(self):
        props = req.env['ir.property']
        return props.create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'company_id': req.env.company.id,
            'res_id': 'res.partner,%s' % req.env.user.partner_id.id,
            'value_reference': req.params.get('account'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(f.rule_id == "odoo-property-request-derived-mutation" for f in findings)


def test_imported_odoo_http_module_direct_property_value_is_reported(tmp_path: Path) -> None:
    """Direct odoo.http request values should taint property writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
import odoo.http as odoo_http

class Properties(odoo_http.Controller):
    @odoo_http.route('/properties/account', auth='user', csrf=False)
    def set_property(self):
        props = odoo_http.request.env['ir.property']
        return props.create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'company_id': odoo_http.request.env.company.id,
            'res_id': 'res.partner,%s' % odoo_http.request.env.user.partner_id.id,
            'value_reference': odoo_http.request.params.get('account'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(f.rule_id == "odoo-property-request-derived-mutation" for f in findings)


def test_imported_odoo_module_direct_property_value_is_reported(tmp_path: Path) -> None:
    """Direct odoo module request values should taint property writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
import odoo as od

class Properties(od.http.Controller):
    @od.http.route('/properties/account', auth='user', csrf=False)
    def set_property(self):
        props = od.http.request.env['ir.property']
        return props.create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'company_id': od.http.request.env.company.id,
            'res_id': 'res.partner,%s' % od.http.request.env.user.partner_id.id,
            'value_reference': od.http.request.params.get('account'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(f.rule_id == "odoo-property-request-derived-mutation" for f in findings)


def test_flags_route_path_id_runtime_property_create(tmp_path: Path) -> None:
    """Path-selected IDs are request-controlled property values."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request

class Properties(http.Controller):
    @http.route('/properties/account/<int:account_id>', auth='public', csrf=False)
    def set_property_path(self, account_id):
        return request.env['ir.property'].sudo().create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': f'account.account,{account_id}',
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-public-route-mutation" in rule_ids
    assert "odoo-property-sudo-mutation" in rule_ids
    assert "odoo-property-request-derived-mutation" in rule_ids
    assert "odoo-property-runtime-global-default" in rule_ids
    assert "odoo-property-runtime-no-resource-scope" in rule_ids
    assert "odoo-property-runtime-sensitive-value" in rule_ids


def test_flags_alias_runtime_property_write(tmp_path: Path) -> None:
    """ir.property aliases should still be recognized when writing values."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "properties.py").write_text(
        """
from odoo import models

class Properties(models.Model):
    _name = 'x.properties'

    def set_price_property(self):
        props = self.env['ir.property'].sudo()
        property_record = props.search([('name', '=', 'property_price')], limit=1)
        return property_record.write({
            'fields_id': 'product.field_product_template__property_price',
            'company_id': self.env.company.id,
            'value_float': 10.0,
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-sudo-mutation" in rule_ids
    assert "odoo-property-runtime-no-resource-scope" in rule_ids
    assert "odoo-property-runtime-sensitive-value" in rule_ids
    assert "odoo-property-runtime-global-default" not in rule_ids


def test_flags_starred_rest_alias_runtime_property_write(tmp_path: Path) -> None:
    """Starred-rest ir.property aliases should still be recognized when writing values."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "properties.py").write_text(
        """
from odoo import models

class Properties(models.Model):
    _name = 'x.properties'

    def set_price_property(self):
        marker, *items, tail = 'x', self.env['ir.property'].sudo(), self.env.company.id, 'end'
        props = items[0]
        company_id = items[1]
        property_record = props.search([('name', '=', 'property_price')], limit=1)
        return property_record.write({
            'fields_id': 'product.field_product_template__property_price',
            'company_id': company_id,
            'value_float': 10.0,
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-sudo-mutation" in rule_ids
    assert "odoo-property-runtime-no-resource-scope" in rule_ids
    assert "odoo-property-runtime-sensitive-value" in rule_ids
    assert "odoo-property-runtime-global-default" not in rule_ids


def test_flags_walrus_elevated_property_alias(tmp_path: Path) -> None:
    """Walrus-bound ir.property aliases should preserve elevated model state."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "properties.py").write_text(
        """
from odoo import models

class Properties(models.Model):
    _name = 'x.properties'

    def set_price_property(self):
        if props := self.env['ir.property'].sudo():
            property_record = props.search([('name', '=', 'property_price')], limit=1)
            return property_record.write({
                'fields_id': 'product.field_product_template__property_price',
                'company_id': self.env.company.id,
                'value_float': 10.0,
            })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-property-sudo-mutation" in rule_ids
    assert "odoo-property-runtime-no-resource-scope" in rule_ids
    assert "odoo-property-runtime-sensitive-value" in rule_ids
    assert "odoo-property-runtime-global-default" not in rule_ids


def test_walrus_reassigned_property_alias_is_not_stale(tmp_path: Path) -> None:
    """Walrus-reassigned aliases should clear stale property-model state."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "properties.py").write_text(
        """
from odoo import models

class Properties(models.Model):
    _name = 'x.properties'

    def set_partner_name(self):
        props = self.env['ir.property'].sudo()
        if props := self.env['res.partner']:
            return props.create({'name': 'ok'})
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert not any(f.rule_id == "odoo-property-sudo-mutation" for f in findings)


def test_flags_runtime_provider_property_value(tmp_path: Path) -> None:
    """Runtime payment-provider property changes should be sensitive writes."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "properties.py").write_text(
        """
from odoo import models

class Properties(models.Model):
    _name = 'x.properties'

    def set_provider_property(self):
        return self.env['ir.property'].create({
            'fields_id': 'payment.field_res_company__property_payment_provider_id',
            'company_id': self.env.company.id,
            'value_reference': 'payment.provider,1',
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(f.rule_id == "odoo-property-runtime-sensitive-value" for f in findings)


def test_reassigned_property_alias_is_not_stale(tmp_path: Path) -> None:
    """Reassigned ir.property aliases should not keep property-model state."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "properties.py").write_text(
        """
from odoo import models

class Properties(models.Model):
    _name = 'x.properties'

    def set_partner_name(self):
        props = self.env['ir.property'].sudo()
        props = self.env['res.partner']
        return props.create({'name': 'ok'})
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert not any(f.rule_id == "odoo-property-sudo-mutation" for f in findings)


def test_reassigned_property_value_name_is_not_permanently_tainted(tmp_path: Path) -> None:
    """Property value-like names should not stay tainted after safe reassignment."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request

class Properties(http.Controller):
    @http.route('/properties/account', auth='user', csrf=False)
    def set_property(self, **kwargs):
        value = kwargs.get('account')
        value = 'account.account,1'
        return request.env['ir.property'].create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'company_id': request.env.company.id,
            'res_id': 'res.partner,%s' % request.env.user.partner_id.id,
            'value_reference': value,
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert not any(f.rule_id == "odoo-property-request-derived-mutation" for f in findings)


def test_comprehension_derived_property_value_is_reported(tmp_path: Path) -> None:
    """Request-derived comprehensions should stay tainted for ir.property writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request

class Properties(http.Controller):
    @http.route('/properties/account', auth='user', csrf=False)
    def set_property(self, **kwargs):
        accounts = [str(account) for account in kwargs.get('accounts')]
        return request.env['ir.property'].create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'company_id': request.env.company.id,
            'res_id': 'res.partner,%s' % request.env.user.partner_id.id,
            'value_reference': accounts[0],
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(f.rule_id == "odoo-property-request-derived-mutation" for f in findings)


def test_comprehension_filter_derived_property_value_is_reported(tmp_path: Path) -> None:
    """Request-only comprehension filters should taint generated property values."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request

class Properties(http.Controller):
    @http.route('/properties/account', auth='user', csrf=False)
    def set_property(self, **kwargs):
        accounts = ['account.account,1' for _ in range(1) if kwargs.get('account')]
        return request.env['ir.property'].create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'company_id': request.env.company.id,
            'res_id': 'res.partner,%s' % request.env.user.partner_id.id,
            'value_reference': accounts[0],
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(f.rule_id == "odoo-property-request-derived-mutation" for f in findings)


def test_named_expression_derived_property_value_is_reported(tmp_path: Path) -> None:
    """Walrus-bound property values should remain tainted after the condition."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request

class Properties(http.Controller):
    @http.route('/properties/account', auth='user', csrf=False)
    def set_property(self, **kwargs):
        if account := kwargs.get('account'):
            return request.env['ir.property'].create({
                'fields_id': 'account.field_res_partner__property_account_receivable_id',
                'company_id': request.env.company.id,
                'res_id': 'res.partner,%s' % request.env.user.partner_id.id,
                'value_reference': account,
            })
        return None
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(f.rule_id == "odoo-property-request-derived-mutation" for f in findings)


def test_starred_rest_derived_property_value_is_reported(tmp_path: Path) -> None:
    """Starred-rest property values should remain tainted after unpacking."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request

class Properties(http.Controller):
    @http.route('/properties/account', auth='user', csrf=False)
    def set_property(self, **kwargs):
        marker, *items, tail = 'x', kwargs.get('account'), request.env.company.id, 'end'
        account = items[0]
        company_id = items[1]
        return request.env['ir.property'].create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'company_id': company_id,
            'res_id': 'res.partner,%s' % request.env.user.partner_id.id,
            'value_reference': account,
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(f.rule_id == "odoo-property-request-derived-mutation" for f in findings)


def test_boolop_derived_property_value_is_reported(tmp_path: Path) -> None:
    """Boolean fallback expressions should keep property values tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "properties.py").write_text(
        """
from odoo import http
from odoo.http import request

class Properties(http.Controller):
    @http.route('/properties/account', auth='user', csrf=False)
    def set_property(self, **kwargs):
        account = kwargs.get('account') or 'account.account,1'
        return request.env['ir.property'].create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'company_id': request.env.company.id,
            'res_id': 'res.partner,%s' % request.env.user.partner_id.id,
            'value_reference': account,
        })
""",
        encoding="utf-8",
    )

    findings = scan_property_fields(tmp_path)

    assert any(f.rule_id == "odoo-property-request-derived-mutation" for f in findings)


def test_safe_company_scoped_property_is_ignored(tmp_path: Path) -> None:
    """Company-scoped non-sensitive properties should avoid noise."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "safe.xml").write_text(
        """<odoo>
  <record id="property_label_company" model="ir.property">
    <field name="fields_id" ref="x_module.field_x_model__property_label"/>
    <field name="company_id" ref="base.main_company"/>
    <field name="res_id">x.model,1</field>
    <field name="value_text">Label</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_property_fields(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Property fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "properties.xml").write_text(
        """<odoo>
  <record id="property_receivable_global" model="ir.property">
    <field name="fields_id" ref="account.field_res_partner__property_account_receivable_id"/>
    <field name="value_reference">account.account,1</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_property_fields(tmp_path) == []
