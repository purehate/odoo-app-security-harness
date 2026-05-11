"""Tests for public data/attachment publication scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.publication_scanner import PublicationScanner, scan_publication


def test_public_attachment_is_reported(tmp_path: Path) -> None:
    """ir.attachment public=True should be a data-exposure finding."""
    xml = tmp_path / "attachments.xml"
    xml.write_text(
        """<odoo>
  <record id="attachment_terms" model="ir.attachment">
    <field name="name">terms.pdf</field>
    <field name="public">True</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = PublicationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-publication-public-attachment" for f in findings)


def test_sensitive_public_attachment_is_critical(tmp_path: Path) -> None:
    """Public attachments with sensitive names deserve critical review."""
    xml = tmp_path / "attachments.xml"
    xml.write_text(
        """<odoo>
  <record id="attachment_contract" model="ir.attachment">
    <field name="name">employee_contract.pdf</field>
    <field name="datas_fname">employee_contract.pdf</field>
    <field name="public">1</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = PublicationScanner(xml).scan_file()

    assert any(
        f.rule_id == "odoo-publication-sensitive-public-attachment" and f.severity == "critical" for f in findings
    )


def test_sensitive_website_published_record_is_reported(tmp_path: Path) -> None:
    """Sensitive records should not be silently marked website-published."""
    xml = tmp_path / "website.xml"
    xml.write_text(
        """<odoo>
  <record id="public_partner" model="res.partner">
    <field name="name">VIP Customer</field>
    <field name="website_published">True</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = PublicationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-publication-sensitive-website-published" for f in findings)


def test_security_model_website_published_records_are_reported(tmp_path: Path) -> None:
    """Security/payment records should be treated as sensitive publication targets."""
    xml = tmp_path / "website.xml"
    xml.write_text(
        """<odoo>
  <record id="public_params" model="ir.config_parameter">
    <field name="key">web.base.url</field>
    <field name="is_published">True</field>
  </record>
  <record id="public_payment_provider" model="payment.provider">
    <field name="name">Provider</field>
    <field name="website_published">True</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = PublicationScanner(xml).scan_file()
    published_models = {
        finding.model for finding in findings if finding.rule_id == "odoo-publication-sensitive-website-published"
    }

    assert {"ir.config_parameter", "payment.provider"} <= published_models


def test_portal_share_sensitive_target_is_reported(tmp_path: Path) -> None:
    """Portal/share data records can create exposed links to sensitive models."""
    xml = tmp_path / "share.xml"
    xml.write_text(
        """<odoo>
  <record id="share_invoice" model="portal.share">
    <field name="res_model">account.move</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = PublicationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-publication-portal-share-sensitive" for f in findings)


def test_portal_share_sensitive_model_external_id_is_normalized(tmp_path: Path) -> None:
    """Portal/share model refs should be normalized before sensitivity checks."""
    xml = tmp_path / "share.xml"
    xml.write_text(
        """<odoo>
  <record id="share_provider" model="portal.share">
    <field name="res_model" ref="payment.model_payment_provider"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = PublicationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-publication-portal-share-sensitive" for f in findings)


def test_public_attachment_sensitive_res_model_external_id_is_reported(tmp_path: Path) -> None:
    """Public attachments bound to sensitive model refs deserve sensitive exposure review."""
    xml = tmp_path / "attachments.xml"
    xml.write_text(
        """<odoo>
  <record id="attachment_config" model="ir.attachment">
    <field name="name">export.bin</field>
    <field name="res_model" ref="base.model_ir_config_parameter"/>
    <field name="public">True</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = PublicationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-publication-sensitive-public-attachment" for f in findings)


def test_repository_scan_finds_publication_records(tmp_path: Path) -> None:
    """Repository scanner should include XML data files."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "attachment.xml").write_text(
        """<odoo><record id="attachment_invoice" model="ir.attachment">
<field name="name">invoice.pdf</field><field name="public">True</field>
</record></odoo>""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)

    assert any(f.rule_id == "odoo-publication-sensitive-public-attachment" for f in findings)


def test_public_attachment_csv_is_reported(tmp_path: Path) -> None:
    """CSV ir.attachment records should get the same public exposure checks as XML."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.attachment.csv").write_text(
        "id,name,res_model,public\n"
        "attachment_invoice,invoice.pdf,account.move,1\n",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-publication-public-attachment" in rule_ids
    assert "odoo-publication-sensitive-public-attachment" in rule_ids


def test_sensitive_website_published_csv_is_reported(tmp_path: Path) -> None:
    """CSV data can also publish sensitive records directly."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "res_partner.csv").write_text(
        "id,name,website_published\n"
        "vip_customer,VIP Customer,True\n",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)

    assert any(
        f.rule_id == "odoo-publication-sensitive-website-published"
        and f.model == "res.partner"
        and f.record_id == "vip_customer"
        for f in findings
    )


def test_portal_share_csv_sensitive_target_is_reported(tmp_path: Path) -> None:
    """CSV portal share records can expose sensitive target records."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "portal_share.csv").write_text(
        "id,res_model/id,access_warning\n"
        "share_provider,payment.model_payment_provider,\n",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)

    assert any(f.rule_id == "odoo-publication-portal-share-sensitive" for f in findings)


def test_sensitive_model_default_website_published_is_reported(tmp_path: Path) -> None:
    """Sensitive models should not default records into website publication."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import fields, models

class Partner(models.Model):
    _inherit = 'res.partner'

    website_published = fields.Boolean(default=True)
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)

    assert any(
        f.rule_id == "odoo-publication-sensitive-default-published"
        and f.model == "res.partner"
        and f.record_id == "website_published"
        for f in findings
    )


def test_direct_boolean_constructor_default_website_published_is_reported(tmp_path: Path) -> None:
    """Directly imported Boolean constructors should not hide publication defaults."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import models
from odoo.fields import Boolean

class Partner(models.Model):
    _inherit = 'res.partner'

    website_published = Boolean(default=True)
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)

    assert any(
        f.rule_id == "odoo-publication-sensitive-default-published"
        and f.model == "res.partner"
        and f.record_id == "website_published"
        for f in findings
    )


def test_sensitive_model_default_is_published_constant_is_reported(tmp_path: Path) -> None:
    """Constant publication defaults should be caught too."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "employee.py").write_text(
        """
from odoo import models

class Employee(models.Model):
    _name = 'hr.employee'

    is_published = True
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)

    assert any(
        f.rule_id == "odoo-publication-sensitive-default-published"
        and f.model == "hr.employee"
        and f.record_id == "is_published"
        for f in findings
    )


def test_constant_alias_sensitive_model_default_publication_is_reported(tmp_path: Path) -> None:
    """Recursive constants should not hide sensitive model publication defaults."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "employee.py").write_text(
        """
from odoo import fields, models

EMPLOYEE_MODEL = 'hr.employee'
MODEL_NAME = EMPLOYEE_MODEL
PUBLISHED = True
DEFAULT_PUBLISHED = PUBLISHED

class Employee(models.Model):
    _name = MODEL_NAME

    website_published = fields.Boolean(default=DEFAULT_PUBLISHED)
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)

    assert any(
        f.rule_id == "odoo-publication-sensitive-default-published"
        and f.model == "hr.employee"
        and f.record_id == "website_published"
        for f in findings
    )


def test_class_constant_alias_sensitive_model_default_publication_is_reported(tmp_path: Path) -> None:
    """Class-scoped constants should not hide sensitive publication defaults."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "employee.py").write_text(
        """
from odoo import fields, models

class Employee(models.Model):
    EMPLOYEE_MODEL = 'hr.employee'
    MODEL_NAME = EMPLOYEE_MODEL
    PUBLISHED = True
    DEFAULT_PUBLISHED = PUBLISHED

    _name = MODEL_NAME

    website_published = fields.Boolean(default=DEFAULT_PUBLISHED)
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)

    assert any(
        f.rule_id == "odoo-publication-sensitive-default-published"
        and f.model == "hr.employee"
        and f.record_id == "website_published"
        for f in findings
    )


def test_public_route_runtime_publication_write_is_reported(tmp_path: Path) -> None:
    """Public routes should not publish sensitive records from path values."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request

class Publish(http.Controller):
    @http.route('/public/orders/<int:order_id>/publish/<int:is_published>', auth='public', csrf=False)
    def publish_order(self, order_id, is_published):
        return request.env['sale.order'].sudo().browse(order_id).write({
            'website_published': is_published,
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-publication-public-route-mutation" in rule_ids
    assert "odoo-publication-sensitive-runtime-published" in rule_ids
    assert "odoo-publication-tainted-runtime-published" in rule_ids


def test_imported_route_decorator_runtime_publication_write_is_reported(tmp_path: Path) -> None:
    """Imported route decorators should not hide runtime publication writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request, route

class Publish(http.Controller):
    @route('/public/orders/<int:order_id>/publish/<int:is_published>', auth='public', csrf=False)
    def publish_order(self, order_id, is_published):
        return request.env['sale.order'].sudo().browse(order_id).write({
            'website_published': is_published,
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-publication-public-route-mutation" in rule_ids
    assert "odoo-publication-sensitive-runtime-published" in rule_ids
    assert "odoo-publication-tainted-runtime-published" in rule_ids


def test_aliased_imported_route_decorator_runtime_publication_write_is_reported(tmp_path: Path) -> None:
    """Aliased imported route decorators should not hide public publication writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request, route as web_route

class Publish(http.Controller):
    @web_route('/public/orders/<int:order_id>/publish/<int:is_published>', auth='public', csrf=False)
    def publish_order(self, order_id, is_published):
        return request.env['sale.order'].sudo().browse(order_id).write({
            'website_published': is_published,
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-publication-public-route-mutation" in rule_ids
    assert "odoo-publication-sensitive-runtime-published" in rule_ids
    assert "odoo-publication-tainted-runtime-published" in rule_ids


def test_aliased_http_module_route_runtime_publication_write_is_reported(tmp_path: Path) -> None:
    """Aliased odoo.http module route decorators should remain recognized."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http as odoo_http
from odoo.http import request

class Publish(odoo_http.Controller):
    @odoo_http.route('/public/orders/<int:order_id>/publish/<int:is_published>', auth='public', csrf=False)
    def publish_order(self, order_id, is_published):
        return request.env['sale.order'].sudo().browse(order_id).write({
            'website_published': is_published,
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-publication-public-route-mutation" in rule_ids
    assert "odoo-publication-sensitive-runtime-published" in rule_ids
    assert "odoo-publication-tainted-runtime-published" in rule_ids


def test_non_odoo_route_decorator_runtime_publication_write_is_not_public(tmp_path: Path) -> None:
    """Local route decorators should not make publication writes public routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request

class Router:
    def route(self, *args, **kwargs):
        def decorate(func):
            return func
        return decorate

router = Router()

class Publish(http.Controller):
    @router.route('/public/orders/<int:order_id>/publish/<int:is_published>', auth='public', csrf=False)
    def publish_order(self, order_id, is_published):
        return request.env['sale.order'].sudo().browse(order_id).write({
            'website_published': is_published,
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-publication-public-route-mutation" not in rule_ids
    assert "odoo-publication-sensitive-runtime-published" in rule_ids


def test_constant_backed_public_route_runtime_publication_write_is_reported(tmp_path: Path) -> None:
    """Constant-backed public auth should still flag public publication writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request

PUBLISH_ROUTE = '/public/orders/<int:order_id>/publish/<int:is_published>'
PUBLISH_AUTH = 'public'
PUBLISH_CSRF = False

class Publish(http.Controller):
    @http.route(PUBLISH_ROUTE, auth=PUBLISH_AUTH, csrf=PUBLISH_CSRF)
    def publish_order(self, order_id, is_published):
        return request.env['sale.order'].sudo().browse(order_id).write({
            'website_published': is_published,
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-publication-public-route-mutation" in rule_ids
    assert "odoo-publication-sensitive-runtime-published" in rule_ids
    assert "odoo-publication-tainted-runtime-published" in rule_ids
    assert any(
        f.rule_id == "odoo-publication-tainted-runtime-published" and f.severity == "critical" for f in findings
    )


def test_class_constant_backed_public_route_runtime_publication_write_is_reported(tmp_path: Path) -> None:
    """Class-scoped public auth should still flag public publication writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request

class Publish(http.Controller):
    PUBLISH_AUTH_BASE = 'public'
    PUBLISH_AUTH = PUBLISH_AUTH_BASE

    @http.route('/public/orders/<int:order_id>/publish/<int:is_published>', auth=PUBLISH_AUTH)
    def publish_order(self, order_id, is_published):
        return request.env['sale.order'].sudo().browse(order_id).write({
            'website_published': is_published,
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-publication-public-route-mutation" in rule_ids
    assert "odoo-publication-sensitive-runtime-published" in rule_ids
    assert "odoo-publication-tainted-runtime-published" in rule_ids
    assert any(
        f.rule_id == "odoo-publication-tainted-runtime-published" and f.severity == "critical" for f in findings
    )


def test_static_unpack_public_route_runtime_publication_write_is_reported(tmp_path: Path) -> None:
    """Static **route options should keep publication writes public/critical."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request

PUBLISH_OPTIONS = {
    'route': '/public/orders/<int:order_id>/publish',
    'auth': 'public',
    'csrf': False,
}

class Publish(http.Controller):
    @http.route(**PUBLISH_OPTIONS)
    def publish_order(self, order_id, **kwargs):
        return request.env['sale.order'].sudo().browse(order_id).write({
            'website_published': kwargs.get('published'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)

    assert any(
        f.rule_id == "odoo-publication-public-route-mutation" and f.severity == "critical" for f in findings
    )
    assert any(
        f.rule_id == "odoo-publication-tainted-runtime-published" and f.severity == "critical" for f in findings
    )


def test_class_constant_static_unpack_public_route_runtime_publication_write_is_reported(tmp_path: Path) -> None:
    """Class-scoped static **route options should keep publication writes public/critical."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request

class Publish(http.Controller):
    PUBLISH_OPTIONS = {
        'route': '/public/orders/<int:order_id>/publish',
        'auth': 'public',
        'csrf': False,
    }

    @http.route(**PUBLISH_OPTIONS)
    def publish_order(self, order_id, **kwargs):
        return request.env['sale.order'].sudo().browse(order_id).write({
            'website_published': kwargs.get('published'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)

    assert any(
        f.rule_id == "odoo-publication-public-route-mutation" and f.severity == "critical" for f in findings
    )
    assert any(
        f.rule_id == "odoo-publication-tainted-runtime-published" and f.severity == "critical" for f in findings
    )


def test_keyword_constant_backed_none_route_publication_write_is_critical(tmp_path: Path) -> None:
    """Keyword route constants with auth='none' should keep publication writes critical."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request

PUBLISH_ROUTE = '/public/orders/<int:order_id>/publish'
PUBLISH_AUTH = 'none'

class Publish(http.Controller):
    @http.route(route=PUBLISH_ROUTE, auth=PUBLISH_AUTH)
    def publish_order(self, order_id, **kwargs):
        return request.env['sale.order'].sudo().browse(order_id).write({
            'is_published': kwargs.get('published'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)

    assert any(
        f.rule_id == "odoo-publication-public-route-mutation" and f.severity == "critical" for f in findings
    )
    assert any(
        f.rule_id == "odoo-publication-tainted-runtime-published" and f.severity == "critical" for f in findings
    )


def test_constant_alias_runtime_publication_write_is_reported(tmp_path: Path) -> None:
    """Recursive constants should not hide runtime publication writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request

SALE_MODEL = 'sale.order'
TARGET_MODEL = SALE_MODEL
PUBLISHED_FIELD = 'website_published'
PUBLISHED_VALUE = True
PUBLIC_AUTH = 'public'
ROUTE_AUTH = PUBLIC_AUTH

class Publish(http.Controller):
    @http.route('/public/orders/<int:order_id>/publish', auth=ROUTE_AUTH)
    def publish_order(self, order_id):
        return request.env[TARGET_MODEL].sudo().browse(order_id).write({
            PUBLISHED_FIELD: PUBLISHED_VALUE,
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-publication-public-route-mutation" in rule_ids
    assert "odoo-publication-sensitive-runtime-published" in rule_ids


def test_local_constant_alias_runtime_publication_write_is_reported(tmp_path: Path) -> None:
    """Function-local constants should not hide runtime publication writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request

class Publish(http.Controller):
    @http.route('/public/orders/<int:order_id>/publish', auth='public', csrf=False)
    def publish_order(self, order_id):
        target_model = 'sale.order'
        field_name = 'website_published'
        published = True
        return request.env[target_model].sudo().browse(order_id).write({
            field_name: published,
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-publication-public-route-mutation" in rule_ids
    assert "odoo-publication-sensitive-runtime-published" in rule_ids


def test_local_values_alias_runtime_publication_write_is_reported(tmp_path: Path) -> None:
    """Local vals dictionaries should not hide publication writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request

class Publish(http.Controller):
    @http.route('/public/orders/<int:order_id>/publish', auth='public', csrf=False)
    def publish_order(self, order_id):
        values = {'website_published': True}
        return request.env['sale.order'].sudo().browse(order_id).write(values)
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-publication-public-route-mutation" in rule_ids
    assert "odoo-publication-sensitive-runtime-published" in rule_ids


def test_tainted_local_values_alias_runtime_publication_write_is_reported(tmp_path: Path) -> None:
    """Request-derived local vals dictionaries should remain tainted at write sinks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request

class Publish(http.Controller):
    @http.route('/public/orders/<int:order_id>/publish', auth='public', csrf=False)
    def publish_order(self, order_id, **kwargs):
        values = {'website_published': kwargs.get('published')}
        return request.env['sale.order'].sudo().browse(order_id).write(values)
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-publication-public-route-mutation" in rule_ids
    assert "odoo-publication-sensitive-runtime-published" in rule_ids
    assert "odoo-publication-tainted-runtime-published" in rule_ids


def test_reassigned_values_alias_does_not_keep_stale_publication_dict(tmp_path: Path) -> None:
    """Reassigned vals dictionaries should clear stale publication keys."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request

class Publish(http.Controller):
    @http.route('/public/orders/<int:order_id>/publish', auth='public', csrf=False)
    def publish_order(self, order_id, **kwargs):
        values = {'website_published': kwargs.get('published')}
        values = {'name': 'Renamed'}
        return request.env['sale.order'].sudo().browse(order_id).write(values)
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-publication-public-route-mutation" not in rule_ids
    assert "odoo-publication-sensitive-runtime-published" not in rule_ids
    assert "odoo-publication-tainted-runtime-published" not in rule_ids


def test_request_alias_runtime_publication_write_is_reported(tmp_path: Path) -> None:
    """Aliased request imports should still taint runtime publication writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Publish(http.Controller):
    @http.route('/public/orders/<int:order_id>/publish', auth='public', csrf=False)
    def publish_order(self, order_id):
        payload = req.get_http_params()
        return req.env['sale.order'].sudo().browse(order_id).write({
            'website_published': payload.get('published'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-publication-public-route-mutation" in rule_ids
    assert "odoo-publication-sensitive-runtime-published" in rule_ids
    assert "odoo-publication-tainted-runtime-published" in rule_ids


def test_request_alias_direct_publication_value_is_reported(tmp_path: Path) -> None:
    """Direct aliased request params should taint publication flag writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Publish(http.Controller):
    @http.route('/orders/<int:order_id>/publish', auth='user')
    def publish_order(self, order_id):
        return req.env['sale.order'].sudo().browse(order_id).write({
            'website_published': req.params.get('published'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)

    assert any(f.rule_id == "odoo-publication-tainted-runtime-published" for f in findings)


def test_reassigned_publication_value_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing a request publication flag alias for static data should clear taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request

class Publish(http.Controller):
    @http.route('/public/orders/<int:order_id>/publish', auth='public', csrf=False)
    def publish_order(self, order_id, **kwargs):
        value = kwargs.get('published')
        value = True
        return request.env['sale.order'].sudo().browse(order_id).write({
            'website_published': value,
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-publication-tainted-runtime-published" not in rule_ids


def test_comprehension_derived_publication_value_is_reported(tmp_path: Path) -> None:
    """Request-derived comprehensions should remain tainted for publication writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request

class Publish(http.Controller):
    @http.route('/orders/<int:order_id>/publish', auth='user')
    def publish_order(self, order_id, **kwargs):
        flags = [bool(flag) for flag in kwargs.get('flags')]
        return request.env['sale.order'].sudo().browse(order_id).write({
            'website_published': flags[0],
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)

    assert any(f.rule_id == "odoo-publication-tainted-runtime-published" for f in findings)


def test_starred_unpacked_publication_value_is_reported(tmp_path: Path) -> None:
    """Starred request publication aliases should remain tainted for publication writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request

class Publish(http.Controller):
    @http.route('/public/orders/<int:order_id>/publish', auth='public', csrf=False)
    def publish_order(self, order_id, **kwargs):
        _, *flags = ('fixed', kwargs.get('published'))
        published = flags[0]
        return request.env['sale.order'].sudo().browse(order_id).write({
            'website_published': published,
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-publication-public-route-mutation" in rule_ids
    assert "odoo-publication-sensitive-runtime-published" in rule_ids
    assert "odoo-publication-tainted-runtime-published" in rule_ids


def test_comprehension_filter_derived_publication_value_is_reported(tmp_path: Path) -> None:
    """Request-only comprehension filters should taint publication writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request

class Publish(http.Controller):
    @http.route('/orders/<int:order_id>/publish', auth='user')
    def publish_order(self, order_id, **kwargs):
        flags = [True for _ in range(1) if kwargs.get('published')]
        return request.env['sale.order'].sudo().browse(order_id).write({
            'website_published': flags[0],
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)

    assert any(f.rule_id == "odoo-publication-tainted-runtime-published" for f in findings)


def test_named_expression_derived_publication_value_is_reported(tmp_path: Path) -> None:
    """Walrus-bound publication values should remain tainted after the condition."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request

class Publish(http.Controller):
    @http.route('/orders/<int:order_id>/publish', auth='user')
    def publish_order(self, order_id, **kwargs):
        if published := kwargs.get('published'):
            return request.env['sale.order'].sudo().browse(order_id).write({
                'website_published': published,
            })
        return None
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)

    assert any(f.rule_id == "odoo-publication-tainted-runtime-published" for f in findings)


def test_boolop_derived_publication_value_is_reported(tmp_path: Path) -> None:
    """Boolean fallback expressions should keep publication writes tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request

class Publish(http.Controller):
    @http.route('/orders/<int:order_id>/publish', auth='user')
    def publish_order(self, order_id, **kwargs):
        published = kwargs.get('published') or False
        return request.env['sale.order'].sudo().browse(order_id).write({
            'website_published': published,
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)

    assert any(f.rule_id == "odoo-publication-tainted-runtime-published" for f in findings)


def test_publication_value_argument_is_reported(tmp_path: Path) -> None:
    """Publication-like arguments should still seed tainted runtime publish writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "publish.py").write_text(
        """
from odoo import http
from odoo.http import request

class Publish(http.Controller):
    @http.route('/orders/<int:order_id>/publish', auth='user')
    def publish_order(self, order_id, value):
        return request.env['sale.order'].sudo().browse(order_id).write({
            'website_published': value,
        })
""",
        encoding="utf-8",
    )

    findings = scan_publication(tmp_path)

    assert any(f.rule_id == "odoo-publication-tainted-runtime-published" for f in findings)
