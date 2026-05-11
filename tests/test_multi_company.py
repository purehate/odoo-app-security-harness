"""Tests for multi-company isolation checks."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.multi_company import MultiCompanyChecker, check_multi_company_isolation


def _write_model(tmp_path: Path, source: str) -> Path:
    model = tmp_path / "addons" / "test_module" / "models" / "test_model.py"
    model.parent.mkdir(parents=True)
    model.write_text(source, encoding="utf-8")
    return model


def test_company_id_requires_check_company_auto(tmp_path: Path) -> None:
    """Models with company_id should enable Odoo's automatic company checks."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class TestModel(models.Model):
    _name = 'test.model'
    company_id = fields.Many2one('res.company')
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-missing-check-company" for f in findings)


def test_constant_backed_company_id_requires_check_company_auto(tmp_path: Path) -> None:
    """Constants should not hide company_id relation detection."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

COMPANY_MODEL = 'res.company'

class TestModel(models.Model):
    _name = 'test.model'
    company_id = fields.Many2one(COMPANY_MODEL)
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-missing-check-company" for f in findings)


def test_class_constant_backed_company_id_requires_check_company_auto(tmp_path: Path) -> None:
    """Class-scoped constants should not hide company_id relation detection."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class TestModel(models.Model):
    MODEL_NAME = 'test.model'
    COMPANY_BASE = 'res.company'
    COMPANY_MODEL = COMPANY_BASE
    _name = MODEL_NAME
    company_id = fields.Many2one(COMPANY_MODEL)
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(
        f.rule_id == "odoo-mc-missing-check-company" and f.model == "test.model"
        for f in findings
    )


def test_class_constant_backed_check_company_auto_suppresses_missing_check(tmp_path: Path) -> None:
    """Class-scoped true constants should preserve _check_company_auto handling."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class TestModel(models.Model):
    COMPANY_MODEL = 'res.company'
    ENABLED_BASE = True
    ENABLED = ENABLED_BASE
    _name = 'test.model'
    _check_company_auto = ENABLED
    company_id = fields.Many2one(COMPANY_MODEL)
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert not any(f.rule_id == "odoo-mc-missing-check-company" for f in findings)


def test_direct_many2one_constructor_company_id_requires_check_company_auto(tmp_path: Path) -> None:
    """Directly imported Many2one should still be treated as a company field."""
    model = _write_model(
        tmp_path,
        """
from odoo import models
from odoo.fields import Many2one

class TestModel(models.Model):
    _name = 'test.model'
    company_id = Many2one('res.company')
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-missing-check-company" for f in findings)


def test_direct_model_base_company_id_requires_check_company_auto(tmp_path: Path) -> None:
    """Direct Model bases should not hide company isolation field checks."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields
from odoo.models import Model

class TestModel(Model):
    _name = 'test.model'
    company_id = fields.Many2one('res.company')
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-missing-check-company" for f in findings)


def test_relational_check_company_false_is_reported(tmp_path: Path) -> None:
    """Any Many2one with check_company=False can weaken company consistency."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class TestModel(models.Model):
    _name = 'test.model'
    warehouse_id = fields.Many2one('stock.warehouse', check_company=False)
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-check-company-disabled" for f in findings)


def test_constant_backed_check_company_false_is_reported(tmp_path: Path) -> None:
    """Constants should not hide disabled check_company settings."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

DISABLED = False

class TestModel(models.Model):
    _name = 'test.model'
    warehouse_id = fields.Many2one('stock.warehouse', check_company=DISABLED)
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-check-company-disabled" for f in findings)


def test_class_constant_backed_check_company_false_is_reported(tmp_path: Path) -> None:
    """Class-scoped constants should not hide disabled check_company settings."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class TestModel(models.Model):
    DISABLED_BASE = False
    DISABLED = DISABLED_BASE
    _name = 'test.model'
    warehouse_id = fields.Many2one('stock.warehouse', check_company=DISABLED)
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-check-company-disabled" for f in findings)


def test_sudo_search_read_without_company_filter(tmp_path: Path) -> None:
    """Privileged read APIs need explicit company scoping."""
    model = _write_model(
        tmp_path,
        """
class TestModel(models.Model):
    def leak_orders(self):
        return self.env['sale.order'].sudo().search_read([])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-sudo-search-no-company" for f in findings)


def test_sudo_search_count_without_company_filter(tmp_path: Path) -> None:
    """Privileged count APIs can expose cross-company existence and volume."""
    model = _write_model(
        tmp_path,
        """
class TestModel(models.Model):
    def count_orders(self):
        return self.env['sale.order'].sudo().search_count([])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mc-sudo-search-no-company" in rule_ids
    assert "odoo-mc-search-no-company" in rule_ids


def test_sudo_read_group_without_company_filter(tmp_path: Path) -> None:
    """Privileged grouped reads can aggregate data across company boundaries."""
    model = _write_model(
        tmp_path,
        """
class TestModel(models.Model):
    def group_orders(self):
        return self.env['sale.order'].sudo().read_group([], ['amount_total:sum'], ['state'])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mc-sudo-search-no-company" in rule_ids
    assert "odoo-mc-search-no-company" in rule_ids


def test_superuser_search_read_without_company_filter(tmp_path: Path) -> None:
    """with_user(SUPERUSER_ID) reads need the same company scoping as sudo()."""
    model = _write_model(
        tmp_path,
        """
from odoo import SUPERUSER_ID

class TestModel(models.Model):
    def leak_orders(self):
        return self.env['sale.order'].with_user(SUPERUSER_ID).search_read([])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-sudo-search-no-company" for f in findings)


def test_constant_backed_superuser_search_read_without_company_filter(tmp_path: Path) -> None:
    """with_user constants should keep elevated read posture."""
    model = _write_model(
        tmp_path,
        """
ROOT_UID = 1
ORDER_MODEL = 'sale.order'

class TestModel(models.Model):
    def leak_orders(self):
        return self.env[ORDER_MODEL].with_user(ROOT_UID).search_read([])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-sudo-search-no-company" for f in findings)


def test_class_constant_backed_superuser_search_read_without_company_filter(tmp_path: Path) -> None:
    """Class-scoped constants should not hide elevated reads on company models."""
    model = _write_model(
        tmp_path,
        """
class TestModel(models.Model):
    ROOT_BASE = 1
    ROOT_UID = ROOT_BASE
    ORDER_BASE = 'sale.order'
    ORDER_MODEL = ORDER_BASE

    def leak_orders(self):
        return self.env[ORDER_MODEL].with_user(ROOT_UID).search_read([])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mc-sudo-search-no-company" in rule_ids
    assert "odoo-mc-search-no-company" in rule_ids


def test_aliased_superuser_search_without_company_filter(tmp_path: Path) -> None:
    """Aliased with_user(1) recordsets should keep elevated read posture."""
    model = _write_model(
        tmp_path,
        """
class TestModel(models.Model):
    def leak_orders(self):
        Orders = self.env['sale.order'].with_user(1)
        return Orders.search([])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-sudo-search-no-company" for f in findings)


def test_annotated_aliased_superuser_search_without_company_filter(tmp_path: Path) -> None:
    """Annotated elevated record aliases should keep elevated read posture."""
    model = _write_model(
        tmp_path,
        """
class TestModel(models.Model):
    def leak_orders(self):
        Orders: object = self.env['sale.order'].with_user(1)
        return Orders.search([])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-sudo-search-no-company" for f in findings)


def test_env_ref_root_search_without_company_filter(tmp_path: Path) -> None:
    """with_user(base.user_root) reads need explicit company scoping."""
    model = _write_model(
        tmp_path,
        """
class TestModel(models.Model):
    def leak_orders(self):
        Orders = self.env['sale.order'].with_user(self.env.ref('base.user_root'))
        return Orders.search([])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-sudo-search-no-company" for f in findings)


def test_reassigned_elevated_search_alias_is_not_stale(tmp_path: Path) -> None:
    """Elevated aliases should clear after rebinding to a normal recordset."""
    model = _write_model(
        tmp_path,
        """
class TestModel(models.Model):
    def leak_orders(self):
        Orders = self.env['sale.order'].with_user(1)
        Orders = self.env['sale.order']
        return Orders.search([])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert not any(f.rule_id == "odoo-mc-sudo-search-no-company" for f in findings)


def test_annotated_reassigned_elevated_search_alias_is_not_stale(tmp_path: Path) -> None:
    """Annotated elevated aliases should clear after rebinding to a normal recordset."""
    model = _write_model(
        tmp_path,
        """
class TestModel(models.Model):
    def leak_orders(self):
        Orders: object = self.env['sale.order'].with_user(1)
        Orders: object = self.env['sale.order']
        return Orders.search([])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert not any(f.rule_id == "odoo-mc-sudo-search-no-company" for f in findings)


def test_sensitive_model_search_without_company_filter(tmp_path: Path) -> None:
    """Searches on obvious multi-company models should include company filters."""
    model = _write_model(
        tmp_path,
        """
class TestModel(models.Model):
    def orders(self):
        return self.env['sale.order'].search([('state', '=', 'sale')])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-search-no-company" for f in findings)


def test_constant_backed_sensitive_model_search_without_company_filter(tmp_path: Path) -> None:
    """Constants should not hide multi-company env model names."""
    model = _write_model(
        tmp_path,
        """
ORDER_MODEL = 'sale.order'

class TestModel(models.Model):
    def orders(self):
        return self.env[ORDER_MODEL].search([('state', '=', 'sale')])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-search-no-company" for f in findings)


def test_sensitive_model_search_with_company_filter_is_allowed(tmp_path: Path) -> None:
    """A literal company domain should suppress the missing-company warning."""
    model = _write_model(
        tmp_path,
        """
class TestModel(models.Model):
    def orders(self):
        return self.env['sale.order'].search([('company_id', 'in', self.env.companies.ids)])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert not any(f.rule_id == "odoo-mc-search-no-company" for f in findings)


def test_user_controlled_company_context(tmp_path: Path) -> None:
    """User-controlled company context switching should be flagged."""
    model = _write_model(
        tmp_path,
        """
from odoo.http import request

class TestModel(models.Model):
    def orders(self):
        company_ids = request.params['company_ids']
        return self.env['sale.order'].with_context(allowed_company_ids=company_ids).search([])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-company-context-user-input" for f in findings)


def test_request_alias_company_context(tmp_path: Path) -> None:
    """Aliased Odoo request imports should still taint company context values."""
    model = _write_model(
        tmp_path,
        """
from odoo.http import request as req

class TestModel(models.Model):
    def orders(self):
        company_ids = req.get_http_params().get('company_ids')
        return self.env['sale.order'].with_context(allowed_company_ids=company_ids).search([])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-company-context-user-input" for f in findings)


def test_imported_odoo_http_request_company_context(tmp_path: Path) -> None:
    """Direct odoo.http request access should still taint company context values."""
    model = _write_model(
        tmp_path,
        """
import odoo.http as odoo_http

class TestModel(models.Model):
    def orders(self):
        company_ids = odoo_http.request.get_http_params().get('company_ids')
        return self.env['sale.order'].with_context(allowed_company_ids=company_ids).search([])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-company-context-user-input" for f in findings)


def test_imported_odoo_request_company_context(tmp_path: Path) -> None:
    """Direct odoo module request access should still taint company context values."""
    model = _write_model(
        tmp_path,
        """
import odoo as od

class TestModel(models.Model):
    def orders(self):
        company_ids = od.http.request.get_http_params().get('company_ids')
        return self.env['sale.order'].with_context(allowed_company_ids=company_ids).search([])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-company-context-user-input" for f in findings)


def test_reassigned_company_context_value_is_not_stale(tmp_path: Path) -> None:
    """Request-controlled company aliases should clear when rebound to static values."""
    model = _write_model(
        tmp_path,
        """
from odoo.http import request

class TestModel(models.Model):
    def orders(self):
        company_ids = request.params['company_ids']
        company_ids = [self.env.company.id]
        return self.env['sale.order'].with_context(allowed_company_ids=company_ids).search([])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert not any(f.rule_id == "odoo-mc-company-context-user-input" for f in findings)


def test_annotated_user_controlled_company_context(tmp_path: Path) -> None:
    """Annotated aliases should not hide request-selected companies."""
    model = _write_model(
        tmp_path,
        """
from odoo.http import request

class TestModel(models.Model):
    def orders(self):
        company_ids: list[int] = request.params['company_ids']
        return self.env['sale.order'].with_context(allowed_company_ids=company_ids).search([])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-company-context-user-input" for f in findings)


def test_annotated_reassigned_company_context_value_is_not_stale(tmp_path: Path) -> None:
    """Annotated request-controlled company aliases should clear on safe rebinds."""
    model = _write_model(
        tmp_path,
        """
from odoo.http import request

class TestModel(models.Model):
    def orders(self):
        company_ids: list[int] = request.params['company_ids']
        company_ids: list[int] = [self.env.company.id]
        return self.env['sale.order'].with_context(allowed_company_ids=company_ids).search([])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert not any(f.rule_id == "odoo-mc-company-context-user-input" for f in findings)


def test_user_controlled_company_context_from_kwargs_and_dict(tmp_path: Path) -> None:
    """Dict-style with_context should not hide request-selected companies."""
    model = _write_model(
        tmp_path,
        """
class TestModel(models.Model):
    def orders(self, **kwargs):
        return self.env['sale.order'].with_context({
            'allowed_company_ids': kwargs.get('company_ids'),
            'force_company': kwargs.get('company_id'),
        }).search([])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-company-context-user-input" for f in findings)


def test_user_controlled_with_company_from_kwargs(tmp_path: Path) -> None:
    """with_company(kwargs.get(...)) should be reported as company switching."""
    model = _write_model(
        tmp_path,
        """
class TestModel(models.Model):
    def orders(self, **kwargs):
        return self.env['sale.order'].with_company(kwargs.get('company_id')).search([])
""",
    )

    findings = MultiCompanyChecker(str(model)).check_file()

    assert any(f.rule_id == "odoo-mc-with-company-user-input" for f in findings)


def test_repository_scan_includes_security_xml(tmp_path: Path) -> None:
    """Repository-level checker should include Python and security XML checks."""
    security = tmp_path / "addons" / "test_module" / "security"
    security.mkdir(parents=True)
    (security / "rules.xml").write_text(
        """<odoo>
  <record id="sale_order_all" model="ir.rule">
    <field name="model_id" ref="model_sale_order"/>
    <field name="domain_force">[('state', '=', 'sale')]</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = check_multi_company_isolation(tmp_path)

    assert any(f.rule_id == "odoo-mc-rule-missing-company" for f in findings)
