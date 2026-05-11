"""Tests for Odoo report action scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.report_scanner import ReportPythonScanner, ReportScanner, scan_reports


def test_report_sudo_is_reported(tmp_path: Path) -> None:
    """report_sudo should be visible as a privilege-boundary finding."""
    xml = tmp_path / "reports.xml"
    xml.write_text(
        """<odoo>
  <record id="action_invoice_report" model="ir.actions.report">
    <field name="model">account.move</field>
    <field name="report_sudo">True</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = ReportScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-report-sudo-enabled" for f in findings)


def test_sensitive_report_without_groups_is_reported(tmp_path: Path) -> None:
    """Sensitive model reports should declare groups or get reviewed."""
    xml = tmp_path / "reports.xml"
    xml.write_text(
        """<odoo>
  <record id="action_users_report" model="ir.actions.report">
    <field name="model">res.users</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = ReportScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-report-sensitive-no-groups" for f in findings)


def test_sensitive_report_without_groups_in_csv_is_reported(tmp_path: Path) -> None:
    """CSV report actions should get the same exposure checks as XML records."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir_actions_report.csv").write_text(
        "id,name,model\naction_users_report,Users,res.users\n",
        encoding="utf-8",
    )

    findings = scan_reports(tmp_path)

    assert any(
        finding.rule_id == "odoo-report-sensitive-no-groups" and finding.report == "action_users_report"
        for finding in findings
    )


def test_sensitive_csv_report_with_groups_is_ignored(tmp_path: Path) -> None:
    """Grouped CSV report actions should not be broad-exposure findings."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.actions.report.csv").write_text(
        "id,name,model,groups_id/id\naction_users_report,Users,res.users,base.group_system\n",
        encoding="utf-8",
    )

    assert scan_reports(tmp_path) == []


def test_sensitive_csv_report_with_colon_groups_is_ignored(tmp_path: Path) -> None:
    """Grouped CSV report actions exported with colon headers should not look broad."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.actions.report.csv").write_text(
        "id,name,model,groups_id:id\naction_users_report,Users,res.users,base.group_system\n",
        encoding="utf-8",
    )

    assert scan_reports(tmp_path) == []


def test_csv_report_sudo_and_filename_risks_are_reported(tmp_path: Path) -> None:
    """CSV report action metadata should feed existing report-risk rules."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir_actions_report.csv").write_text(
        "id,name,model,report_sudo,attachment_use,attachment,print_report_name\n"
        "action_token_report,Token,sale.order,True,1,object.name,object.access_token\n",
        encoding="utf-8",
    )

    findings = scan_reports(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-sudo-enabled" in rule_ids
    assert "odoo-report-dynamic-attachment-cache" in rule_ids
    assert "odoo-report-sensitive-filename-expression" in rule_ids


def test_sensitive_report_model_external_ids_are_normalized(tmp_path: Path) -> None:
    """Report models supplied as model external IDs should normalize to Odoo model names."""
    xml = tmp_path / "reports.xml"
    xml.write_text(
        """<odoo>
  <record id="action_config_report" model="ir.actions.report">
    <field name="model" ref="base.model_ir_config_parameter"/>
  </record>
  <report id="payment_provider_report" model="payment.model_payment_provider"/>
</odoo>""",
        encoding="utf-8",
    )

    findings = ReportScanner(xml).scan_file()
    sensitive_findings = [finding for finding in findings if finding.rule_id == "odoo-report-sensitive-no-groups"]

    assert {finding.model for finding in sensitive_findings} == {
        "ir.config_parameter",
        "payment.provider",
    }


def test_sensitive_csv_report_colon_model_external_ids_are_normalized(tmp_path: Path) -> None:
    """CSV report model refs exported with colon headers should normalize to model names."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.actions.report.csv").write_text(
        "id,name,model:id\n"
        "action_config_report,Config,base.model_ir_config_parameter\n"
        "payment_provider_report,Provider,payment.model_payment_provider\n",
        encoding="utf-8",
    )

    findings = scan_reports(tmp_path)
    sensitive_models = {
        finding.model for finding in findings if finding.rule_id == "odoo-report-sensitive-no-groups"
    }

    assert {"ir.config_parameter", "payment.provider"} <= sensitive_models


def test_dynamic_attachment_cache_is_reported(tmp_path: Path) -> None:
    """Cached dynamic report attachments can leak stale private PDFs."""
    xml = tmp_path / "reports.xml"
    xml.write_text(
        """<odoo>
  <record id="action_sale_report" model="ir.actions.report">
    <field name="model">sale.order</field>
    <field name="attachment_use">1</field>
    <field name="attachment">'SO-%s' % (object.name)</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = ReportScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-report-dynamic-attachment-cache" for f in findings)


def test_sensitive_report_filename_expression_is_reported(tmp_path: Path) -> None:
    """Report filenames should not include token or credential-like values."""
    xml = tmp_path / "reports.xml"
    xml.write_text(
        """<odoo>
  <record id="action_token_report" model="ir.actions.report">
    <field name="model">sale.order</field>
    <field name="print_report_name">'SO-%s' % (object.access_token)</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = ReportScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-report-sensitive-filename-expression" for f in findings)


def test_broad_sensitive_report_filename_markers_are_reported(tmp_path: Path) -> None:
    """Report filename expressions should catch key and reset-token shaped fields."""
    xml = tmp_path / "reports.xml"
    xml.write_text(
        """<odoo>
  <record id="action_key_report" model="ir.actions.report">
    <field name="model">res.partner</field>
    <field name="attachment">object.private_key</field>
    <field name="print_report_name">object.reset_password_url</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = ReportScanner(xml).scan_file()

    assert any(
        f.rule_id == "odoo-report-sensitive-filename-expression" and f.report == "action_key_report" for f in findings
    )


def test_report_xml_entities_are_not_expanded(tmp_path: Path) -> None:
    """Report XML parsing should reject entities instead of expanding them into findings."""
    xml = tmp_path / "reports.xml"
    xml.write_text(
        """<!DOCTYPE odoo [
<!ENTITY sensitive_model "res.users">
]>
<odoo>
  <record id="action_entity_report" model="ir.actions.report">
    <field name="model">&sensitive_model;</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = ReportScanner(xml).scan_file()

    assert not findings


def test_legacy_report_tag_is_scanned(tmp_path: Path) -> None:
    """Legacy <report> tags should get the same checks."""
    xml = tmp_path / "reports.xml"
    xml.write_text(
        """<odoo>
  <report id="sale_report" model="sale.order" report_sudo="True" attachment_use="True" attachment="object.name"/>
</odoo>""",
        encoding="utf-8",
    )

    findings = ReportScanner(xml).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-sudo-enabled" in rule_ids
    assert "odoo-report-sensitive-no-groups" in rule_ids
    assert "odoo-report-dynamic-attachment-cache" in rule_ids


def test_repository_scan_finds_reports(tmp_path: Path) -> None:
    """Repository scan should include XML report files."""
    reports = tmp_path / "module" / "report"
    reports.mkdir(parents=True)
    (reports / "report.xml").write_text(
        """<odoo><record id="action_partner_report" model="ir.actions.report">
<field name="model">res.partner</field>
</record></odoo>""",
        encoding="utf-8",
    )

    findings = scan_reports(tmp_path)

    assert any(f.rule_id == "odoo-report-sensitive-no-groups" for f in findings)


def test_public_report_render_with_request_ids_is_reported(tmp_path: Path) -> None:
    """Public report routes should not render request-selected records unchecked."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/invoice', auth='public')
    def invoice(self, **kwargs):
        report = request.env.ref('account.account_invoices')
        return report._render_qweb_pdf([int(kwargs.get('id'))])
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-public-render-route" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_imported_route_decorator_public_report_render_is_reported(tmp_path: Path) -> None:
    """Imported route decorators should not hide public report rendering."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request, route

class Controller(http.Controller):
    @route('/public/invoice', auth='public')
    def invoice(self, **kwargs):
        report = request.env.ref('account.account_invoices')
        return report._render_qweb_pdf([int(kwargs.get('id'))])
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-public-render-route" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_aliased_imported_route_decorator_public_report_render_is_reported(tmp_path: Path) -> None:
    """Aliased imported route decorators should not hide public report rendering."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request, route as web_route

class Controller(http.Controller):
    @web_route('/public/invoice', auth='public')
    def invoice(self, **kwargs):
        report = request.env.ref('account.account_invoices')
        return report._render_qweb_pdf([int(kwargs.get('id'))])
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-public-render-route" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_aliased_http_module_route_public_report_render_is_reported(tmp_path: Path) -> None:
    """Aliased odoo.http module route decorators should preserve public report context."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http as odoo_http
from odoo.http import request

class Controller(odoo_http.Controller):
    @odoo_http.route('/public/invoice', auth='public')
    def invoice(self, **kwargs):
        report = request.env.ref('account.account_invoices')
        return report._render_qweb_pdf([int(kwargs.get('id'))])
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-public-render-route" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_imported_odoo_http_module_route_public_report_render_is_reported(tmp_path: Path) -> None:
    """Direct odoo.http imports should preserve public report context."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
import odoo.http as odoo_http

class Controller(odoo_http.Controller):
    @odoo_http.route('/public/invoice', auth='public')
    def invoice(self, **kwargs):
        report = odoo_http.request.env.ref('account.account_invoices')
        return report._render_qweb_pdf([int(kwargs.get('id'))])
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-public-render-route" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_imported_odoo_module_route_public_report_render_is_reported(tmp_path: Path) -> None:
    """Direct odoo imports should preserve public report context."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
import odoo as od

class Controller(od.http.Controller):
    @od.http.route('/public/invoice', auth='public')
    def invoice(self, **kwargs):
        report = od.http.request.env.ref('account.account_invoices')
        return report._render_qweb_pdf([int(kwargs.get('id'))])
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-public-render-route" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_non_odoo_route_decorator_report_render_is_not_public(tmp_path: Path) -> None:
    """Local route decorators should not create public report route context."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

class Router:
    def route(self, *args, **kwargs):
        def decorate(func):
            return func
        return decorate

router = Router()

class Controller(http.Controller):
    @router.route('/public/invoice', auth='public')
    def invoice(self, **kwargs):
        report = request.env.ref('account.account_invoices')
        return report._render_qweb_pdf([int(kwargs.get('id'))])
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-public-render-route" not in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_static_unpack_public_report_render_is_reported(tmp_path: Path) -> None:
    """Static **route options should not hide public report rendering."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

ROUTE_OPTIONS = {'auth': 'public', 'type': 'http'}

class Controller(http.Controller):
    @http.route('/public/invoice', **ROUTE_OPTIONS)
    def invoice(self, **kwargs):
        report = request.env.ref('account.account_invoices')
        return report._render_qweb_pdf([int(kwargs.get('id'))])
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-public-render-route" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_nested_static_unpack_public_report_render_is_reported(tmp_path: Path) -> None:
    """Nested static **route options should not hide public report rendering."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

BASE_OPTIONS = {'auth': 'public'}
ROUTE_OPTIONS = {**BASE_OPTIONS, 'type': 'http'}

class Controller(http.Controller):
    @http.route('/public/invoice', **ROUTE_OPTIONS)
    def invoice(self, **kwargs):
        report = request.env.ref('account.account_invoices')
        return report._render_qweb_pdf([int(kwargs.get('id'))])
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-public-render-route" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_dict_union_static_unpack_public_report_render_is_reported(tmp_path: Path) -> None:
    """Dict-union **route options should not hide public report rendering."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

BASE_OPTIONS = {'auth': 'public'}
ROUTE_OPTIONS = BASE_OPTIONS | {'type': 'http'}

class Controller(http.Controller):
    @http.route('/public/invoice', **ROUTE_OPTIONS)
    def invoice(self, **kwargs):
        report = request.env.ref('account.account_invoices')
        return report._render_qweb_pdf([int(kwargs.get('id'))])
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-public-render-route" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_constant_backed_public_report_render_is_reported(tmp_path: Path) -> None:
    """Constant-backed public route auth should still expose report rendering."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

REPORT_ROUTES = ['/public/invoice', '/public/invoice/alt']
REPORT_AUTH = 'public'

class Controller(http.Controller):
    @http.route(REPORT_ROUTES, auth=REPORT_AUTH)
    def invoice(self, **kwargs):
        report = request.env.ref('account.account_invoices')
        return report._render_qweb_pdf([int(kwargs.get('id'))])
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-public-render-route" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_recursive_constant_backed_public_report_render_is_reported(tmp_path: Path) -> None:
    """Chained public route auth constants should still expose report rendering."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

PUBLIC_AUTH = 'public'
REPORT_AUTH = PUBLIC_AUTH

class Controller(http.Controller):
    @http.route('/public/invoice', auth=REPORT_AUTH)
    def invoice(self, **kwargs):
        report = request.env.ref('account.account_invoices')
        return report._render_qweb_pdf([int(kwargs.get('id'))])
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-public-render-route" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_class_constant_backed_public_report_render_is_reported(tmp_path: Path) -> None:
    """Class-scoped public route constants should still expose report rendering."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    PUBLIC_AUTH = 'public'
    REPORT_AUTH = PUBLIC_AUTH

    @http.route('/public/invoice', auth=REPORT_AUTH)
    def invoice(self, **kwargs):
        report = request.env.ref('account.account_invoices')
        return report._render_qweb_pdf([int(kwargs.get('id'))])
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-public-render-route" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_class_constant_static_unpack_public_report_render_is_reported(tmp_path: Path) -> None:
    """Class-scoped static **route options should not hide public report rendering."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    ROUTE_OPTIONS = {'auth': 'public', 'type': 'http'}

    @http.route('/public/invoice', **ROUTE_OPTIONS)
    def invoice(self, **kwargs):
        report = request.env.ref('account.account_invoices')
        return report._render_qweb_pdf([int(kwargs.get('id'))])
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-public-render-route" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_keyword_constant_backed_none_report_render_is_reported(tmp_path: Path) -> None:
    """Keyword route constants with auth='none' should keep report exposure visible."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

REPORT_ROUTE = '/public/report'
REPORT_AUTH = 'none'

class Controller(http.Controller):
    @http.route(route=REPORT_ROUTE, auth=REPORT_AUTH)
    def report(self, **kwargs):
        report = request.env.ref(kwargs.get('report_xmlid'))
        return report._render_qweb_pdf([42])
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-public-render-route" in rule_ids
    assert "odoo-report-tainted-render-action" in rule_ids


def test_request_alias_public_report_render_is_reported(tmp_path: Path) -> None:
    """Request aliases should still taint report rendering inputs."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request as req

class Controller(http.Controller):
    @http.route('/public/invoice', auth='public')
    def invoice(self):
        params = req.get_http_params()
        report = req.env.ref('account.account_invoices')
        return report._render_qweb_pdf([int(params.get('id'))])
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-public-render-route" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_imported_odoo_http_request_public_report_render_is_reported(tmp_path: Path) -> None:
    """Direct odoo.http request access should still taint report rendering inputs."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
import odoo.http as odoo_http

class Controller(odoo_http.Controller):
    @odoo_http.route('/public/invoice', auth='public')
    def invoice(self):
        params = odoo_http.request.get_http_params()
        report = odoo_http.request.env.ref('account.account_invoices')
        return report._render_qweb_pdf([int(params.get('id'))])
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-public-render-route" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_route_path_id_report_records_are_reported(tmp_path: Path) -> None:
    """Odoo route path IDs should be treated as request-controlled report inputs."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/order/<int:order_id>', auth='public')
    def order_report(self, order_id):
        order = request.env['sale.order'].browse(order_id)
        return request.env.ref('sale.action_report_saleorder').report_action(order)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-public-render-route" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_tainted_report_action_selection_is_reported(tmp_path: Path) -> None:
    """Request-controlled report action selection can expose unintended reports."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/report', auth='public')
    def report(self, **kwargs):
        report = request.env.ref(kwargs.get('report_xmlid'))
        return report._render_qweb_pdf([42])
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-tainted-render-action" in rule_ids
    assert "odoo-report-public-render-route" in rule_ids
    assert "odoo-report-tainted-render-records" not in rule_ids


def test_tainted_report_data_is_reported(tmp_path: Path) -> None:
    """Report data payloads often drive report model domains and filters."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/report/orders', auth='user')
    def orders(self, **kwargs):
        options = {'domain': kwargs.get('domain'), 'include_costs': kwargs.get('costs')}
        report = request.env.ref('sale.action_report_saleorder')
        return report._render_qweb_pdf([request.env.user.partner_id.id], data=options)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-tainted-render-data" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_tainted_report_context_is_reported(tmp_path: Path) -> None:
    """Request-derived context can change language, company, active IDs, or report options."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/report/orders', auth='user')
    def orders(self, **kwargs):
        report = request.env.ref('sale.action_report_saleorder').with_context(active_model=kwargs.get('model'))
        return report._render_qweb_pdf([request.env.user.partner_id.id])
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()

    assert any(f.rule_id == "odoo-report-tainted-render-data" for f in findings)


def test_sudo_report_action_is_reported(tmp_path: Path) -> None:
    """report_action through sudo can bypass record rules in rendered templates."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/invoice/<int:order_id>', auth='user')
    def invoice(self, order_id):
        order = request.env['sale.order'].sudo().browse(order_id)
        return request.env.ref('sale.action_report_saleorder').sudo().report_action(order)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()

    assert any(f.rule_id == "odoo-report-sudo-render-call" for f in findings)


def test_superuser_report_action_is_reported(tmp_path: Path) -> None:
    """report_action through with_user(SUPERUSER_ID) can bypass record rules."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/invoice/<int:order_id>', auth='user')
    def invoice(self, order_id):
        order = request.env['sale.order'].with_user(SUPERUSER_ID).browse(order_id)
        return request.env.ref('sale.action_report_saleorder').with_user(SUPERUSER_ID).report_action(order)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()

    assert any(f.rule_id == "odoo-report-sudo-render-call" for f in findings)


def test_import_aliased_superuser_report_action_is_reported(tmp_path: Path) -> None:
    """Imported SUPERUSER_ID aliases should still flag elevated report rendering."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import SUPERUSER_ID as ROOT_UID, http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/invoice/<int:order_id>', auth='user')
    def invoice(self, order_id):
        order = request.env['sale.order'].with_user(ROOT_UID).browse(order_id)
        return request.env.ref('sale.action_report_saleorder').with_user(ROOT_UID).report_action(order)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()

    assert any(f.rule_id == "odoo-report-sudo-render-call" for f in findings)


def test_keyword_superuser_report_action_is_reported(tmp_path: Path) -> None:
    """Keyword with_user(user=SUPERUSER_ID) report calls remain privileged."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/invoice/<int:order_id>', auth='user')
    def invoice(self, order_id):
        order = request.env['sale.order'].with_user(user=SUPERUSER_ID).browse(order_id)
        return request.env.ref('sale.action_report_saleorder').with_user(user=SUPERUSER_ID).report_action(order)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()

    assert any(f.rule_id == "odoo-report-sudo-render-call" for f in findings)


def test_recursive_constant_backed_superuser_report_action_is_reported(tmp_path: Path) -> None:
    """Chained superuser aliases should still flag elevated report rendering."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

ROOT_UID = 1
ADMIN_UID = ROOT_UID

class Controller(http.Controller):
    @http.route('/invoice/<int:order_id>', auth='user')
    def invoice(self, order_id):
        order = request.env['sale.order'].with_user(ADMIN_UID).browse(order_id)
        return request.env.ref('sale.action_report_saleorder').with_user(ADMIN_UID).report_action(order)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()

    assert any(f.rule_id == "odoo-report-sudo-render-call" for f in findings)


def test_class_constant_backed_superuser_report_action_is_reported(tmp_path: Path) -> None:
    """Class-scoped superuser aliases should still flag elevated report rendering."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    ROOT_UID = 1
    ADMIN_UID = ROOT_UID

    @http.route('/invoice/<int:order_id>', auth='user')
    def invoice(self, order_id):
        order = request.env['sale.order'].with_user(ADMIN_UID).browse(order_id)
        return request.env.ref('sale.action_report_saleorder').with_user(ADMIN_UID).report_action(order)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()

    assert any(f.rule_id == "odoo-report-sudo-render-call" for f in findings)


def test_local_constant_superuser_report_action_is_reported(tmp_path: Path) -> None:
    """Function-local superuser aliases should still flag elevated report rendering."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class C(http.Controller):
    @http.route('/invoice/<int:order_id>', auth='user')
    def invoice(self, order_id):
        root_user = SUPERUSER_ID
        order = request.env['sale.order'].with_user(root_user).browse(order_id)
        return request.env.ref('sale.action_report_saleorder').with_user(root_user).report_action(order)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()

    assert any(f.rule_id == "odoo-report-sudo-render-call" for f in findings)


def test_unpacked_tainted_report_inputs_are_reported(tmp_path: Path) -> None:
    """Tuple-unpacked request data should stay tainted when rendering reports."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/report/invoice', auth='user')
    def invoice(self, **kwargs):
        report_xmlid, docids = kwargs.get('report_xmlid'), kwargs.get('ids')
        report = request.env.ref(report_xmlid)
        return report._render_qweb_pdf(docids)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-tainted-render-action" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_starred_rest_tainted_report_inputs_are_reported(tmp_path: Path) -> None:
    """Starred-rest request data should stay tainted when rendering reports."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/report/invoice', auth='user')
    def invoice(self, **kwargs):
        marker, *items, tail = 'x', kwargs.get('report_xmlid'), kwargs.get('ids'), 'end'
        report_xmlid = items[0]
        docids = items[1]
        report = request.env.ref(report_xmlid)
        return report._render_qweb_pdf(docids)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-report-tainted-render-action" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids


def test_comprehension_derived_report_ids_are_reported(tmp_path: Path) -> None:
    """Request-derived IDs laundered through comprehensions should be reported."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/report/orders', auth='user')
    def orders(self, **kwargs):
        ids = [int(part) for part in kwargs.get('ids', '').split(',') if part]
        return self.env.ref('sale.action_report_saleorder')._render_qweb_pdf(ids)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()

    assert any(f.rule_id == "odoo-report-tainted-render-records" for f in findings)


def test_comprehension_filter_derived_report_ids_are_reported(tmp_path: Path) -> None:
    """Request-only comprehension filters should taint generated report IDs."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/report/orders', auth='user')
    def orders(self, **kwargs):
        ids = [42 for _ in range(1) if kwargs.get('include')]
        return self.env.ref('sale.action_report_saleorder')._render_qweb_pdf(ids)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()

    assert any(f.rule_id == "odoo-report-tainted-render-records" for f in findings)


def test_named_expression_derived_report_ids_are_reported(tmp_path: Path) -> None:
    """Walrus-bound report IDs should remain tainted after the condition."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/report/orders', auth='user')
    def orders(self, **kwargs):
        if docids := kwargs.get('ids'):
            return self.env.ref('sale.action_report_saleorder')._render_qweb_pdf(docids)
        return None
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()

    assert any(f.rule_id == "odoo-report-tainted-render-records" for f in findings)


def test_loop_derived_report_ids_are_reported(tmp_path: Path) -> None:
    """Loop variables sourced from request values should stay tainted."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/report/batch', auth='user')
    def batch(self, **kwargs):
        selected = []
        for docid in kwargs.get('ids', []):
            selected.append(int(docid))
        return self.env.ref('sale.action_report_saleorder')._render_qweb_pdf(selected)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()

    assert any(f.rule_id == "odoo-report-tainted-render-records" for f in findings)


def test_unpacked_sudo_report_records_are_reported(tmp_path: Path) -> None:
    """Tuple-unpacked sudo records should still trigger sudo render findings."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/report/private', auth='user')
    def private(self, order_id):
        order, partner = request.env['sale.order'].sudo().browse(order_id), request.env.user.partner_id
        return request.env.ref('sale.action_report_saleorder').report_action(order)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()

    assert any(f.rule_id == "odoo-report-sudo-render-call" for f in findings)


def test_aliased_superuser_report_records_are_reported(tmp_path: Path) -> None:
    """with_user(1) record aliases should still trigger elevated render findings."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/report/private', auth='user')
    def private(self, order_id):
        order = request.env['sale.order'].with_user(1).browse(order_id)
        return request.env.ref('sale.action_report_saleorder').report_action(order)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()

    assert any(f.rule_id == "odoo-report-sudo-render-call" for f in findings)


def test_env_ref_admin_report_records_are_reported(tmp_path: Path) -> None:
    """with_user(base.user_admin) report records should trigger elevated findings."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/report/private', auth='user')
    def private(self, order_id):
        order = request.env['sale.order'].with_user(request.env.ref('base.user_admin')).browse(order_id)
        return request.env.ref('sale.action_report_saleorder').report_action(order)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()

    assert any(f.rule_id == "odoo-report-sudo-render-call" for f in findings)


def test_starred_rest_sudo_report_records_are_reported(tmp_path: Path) -> None:
    """Starred-rest sudo records should still trigger sudo render findings."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/report/private', auth='user')
    def private(self, order_id):
        marker, *items, tail = 'x', request.env['sale.order'].sudo().browse(order_id), request.env.user.partner_id, 'end'
        order = items[0]
        return request.env.ref('sale.action_report_saleorder').report_action(order)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()

    assert any(f.rule_id == "odoo-report-sudo-render-call" for f in findings)


def test_reassigned_sudo_report_record_alias_is_not_stale(tmp_path: Path) -> None:
    """Reused report record aliases should not keep stale sudo state."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/report/private', auth='user')
    def private(self, order_id):
        order = request.env['sale.order'].sudo().browse(order_id)
        order = request.env['sale.order'].browse(order_id)
        return request.env.ref('sale.action_report_saleorder').report_action(order)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()

    assert not any(f.rule_id == "odoo-report-sudo-render-call" for f in findings)


def test_reassigned_report_docids_name_is_not_permanently_tainted(tmp_path: Path) -> None:
    """Report id-like local names should not stay tainted after safe reassignment."""
    controller = tmp_path / "module" / "controllers" / "report.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/report/orders', auth='user')
    def orders(self, **kwargs):
        docids = kwargs.get('ids')
        docids = [self.env.user.partner_id.id]
        return self.env.ref('sale.action_report_saleorder')._render_qweb_pdf(docids)
""",
        encoding="utf-8",
    )

    findings = ReportPythonScanner(controller).scan_file()

    assert not any(f.rule_id == "odoo-report-tainted-render-records" for f in findings)
