"""Tests for Odoo model access/search override scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.access_override_scanner import scan_access_overrides


def test_flags_allow_all_access_override(tmp_path: Path) -> None:
    """check_access_* overrides returning True without super are critical."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _inherit = 'sale.order'

    def check_access_rights(self, operation, raise_exception=True):
        return True
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-access-override-missing-super" in rule_ids
    assert "odoo-access-override-allow-all" in rule_ids


def test_flags_constant_backed_allow_all_access_override(tmp_path: Path) -> None:
    """Constant-backed model names and allow-all returns should still be caught."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

SALE_MODEL = 'sale.order'
ALLOW_ALL = True

class Sale(models.Model):
    _inherit = SALE_MODEL

    def check_access_rights(self, operation, raise_exception=True):
        return ALLOW_ALL
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-access-override-missing-super" in rule_ids
    assert "odoo-access-override-allow-all" in rule_ids
    assert any(f.model == "sale.order" for f in findings)


def test_flags_constant_alias_allow_all_access_override(tmp_path: Path) -> None:
    """Recursive constant aliases should not hide model names or allow-all returns."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

SALE_MODEL_BASE = 'sale.order'
SALE_MODEL = SALE_MODEL_BASE
ALLOW_BASE = True
ALLOW_ALL = ALLOW_BASE

class Sale(models.Model):
    _inherit = SALE_MODEL

    def check_access_rule(self, operation):
        return ALLOW_ALL
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-access-override-missing-super" in rule_ids
    assert "odoo-access-override-allow-all" in rule_ids
    assert any(f.model == "sale.order" for f in findings)


def test_flags_class_constant_alias_allow_all_access_override(tmp_path: Path) -> None:
    """Class-scoped constant aliases should not hide model names or allow-all returns."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    SALE_MODEL_BASE = 'sale.order'
    SALE_MODEL = SALE_MODEL_BASE
    ALLOW_BASE = True
    ALLOW_ALL = ALLOW_BASE
    _inherit = SALE_MODEL

    def check_access_rule(self, operation):
        return ALLOW_ALL
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-access-override-missing-super" in rule_ids
    assert "odoo-access-override-allow-all" in rule_ids
    assert any(f.model == "sale.order" for f in findings)


def test_flags_direct_model_base_access_override(tmp_path: Path) -> None:
    """Direct Model bases should not hide risky access overrides."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo.models import Model

class Sale(Model):
    _inherit = 'sale.order'

    def check_access_rights(self, operation, raise_exception=True):
        return True
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-access-override-missing-super" in rule_ids
    assert "odoo-access-override-allow-all" in rule_ids


def test_flags_aliased_direct_model_base_access_override(tmp_path: Path) -> None:
    """Aliased direct Model bases should not hide risky access overrides."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo.models import Model as OdooModel

class Sale(OdooModel):
    _inherit = 'sale.order'

    def check_access_rights(self, operation, raise_exception=True):
        return True
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-access-override-missing-super" in rule_ids
    assert "odoo-access-override-allow-all" in rule_ids
    assert any(f.model == "sale.order" for f in findings)


def test_flags_aliased_direct_abstract_model_base_access_override(tmp_path: Path) -> None:
    """Aliased direct AbstractModel bases should still be treated as Odoo models."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo.models import AbstractModel as OdooAbstractModel

class SalePolicy(OdooAbstractModel):
    _name = 'x.sale.policy'

    def check_access_rule(self, operation):
        return True
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-access-override-missing-super" in rule_ids
    assert "odoo-access-override-allow-all" in rule_ids
    assert any(f.model == "x.sale.policy" for f in findings)


def test_flags_filter_access_rules_returning_self(tmp_path: Path) -> None:
    """Returning self from record-rule filters disables filtering."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import models

class Partner(models.Model):
    _inherit = 'res.partner'

    def _filter_access_rules(self, operation):
        return self
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-access-override-missing-super" in rule_ids
    assert "odoo-access-override-filter-self" in rule_ids


def test_flags_sudo_search_override(tmp_path: Path) -> None:
    """Search overrides should not back results with sudo reads."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import models

class Product(models.Model):
    _inherit = 'product.template'

    def name_search(self, name='', args=None, operator='ilike', limit=100):
        return self.sudo().search([]).name_get()
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)

    assert any(f.rule_id == "odoo-access-override-sudo-search" for f in findings)


def test_flags_aliased_sudo_search_override(tmp_path: Path) -> None:
    """Search overrides should not hide sudo reads behind local aliases."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import models

class Product(models.Model):
    _inherit = 'product.template'

    def name_search(self, name='', args=None, operator='ilike', limit=100):
        Products = self.env['product.template'].sudo()
        return Products.search([]).name_get()
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)

    assert any(f.rule_id == "odoo-access-override-sudo-search" for f in findings)


def test_flags_sudo_search_count_override(tmp_path: Path) -> None:
    """Search overrides should not use sudo search_count() as an existence oracle."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import models

class Product(models.Model):
    _inherit = 'product.template'

    def name_search(self, name='', args=None, operator='ilike', limit=100):
        if self.env['product.template'].sudo().search_count([('default_code', '=', name)]):
            return super().name_search(name=name, args=args, operator=operator, limit=limit)
        return []
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)

    assert any(f.rule_id == "odoo-access-override-sudo-search" and f.method == "name_search" for f in findings)


def test_flags_with_user_superuser_search_override(tmp_path: Path) -> None:
    """Search overrides should treat with_user(SUPERUSER_ID) as elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class Product(models.Model):
    _inherit = 'product.template'

    def name_search(self, name='', args=None, operator='ilike', limit=100):
        return self.env['product.template'].with_user(SUPERUSER_ID).search([]).name_get()
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)

    assert any(f.rule_id == "odoo-access-override-sudo-search" for f in findings)


def test_flags_keyword_with_user_superuser_search_override(tmp_path: Path) -> None:
    """Keyword with_user(user=SUPERUSER_ID) search overrides are elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class Product(models.Model):
    _inherit = 'product.template'

    def name_search(self, name='', args=None, operator='ilike', limit=100):
        return self.env['product.template'].with_user(user=SUPERUSER_ID).search([]).name_get()
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)

    assert any(f.rule_id == "odoo-access-override-sudo-search" for f in findings)


def test_flags_aliased_with_user_one_search_override(tmp_path: Path) -> None:
    """Search overrides should not hide with_user(1) reads behind aliases."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import models

class Product(models.Model):
    _inherit = 'product.template'

    def name_search(self, name='', args=None, operator='ilike', limit=100):
        Products = self.env['product.template'].with_user(1)
        return Products.search([]).name_get()
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)

    assert any(f.rule_id == "odoo-access-override-sudo-search" for f in findings)


def test_flags_constant_backed_with_user_root_search_override(tmp_path: Path) -> None:
    """Constant-backed superuser values should not hide elevated search overrides."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import models

ROOT_UID = 1

class Product(models.Model):
    _inherit = 'product.template'

    def name_search(self, name='', args=None, operator='ilike', limit=100):
        Products = self.env['product.template'].with_user(ROOT_UID)
        return Products.search([]).name_get()
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)

    assert any(f.rule_id == "odoo-access-override-sudo-search" for f in findings)


def test_flags_constant_alias_with_user_superuser_search_override(tmp_path: Path) -> None:
    """Recursive SUPERUSER_ID aliases should still be treated as elevated reads."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import SUPERUSER_ID, models

ROOT_BASE = SUPERUSER_ID
ROOT_UID = ROOT_BASE

class Product(models.Model):
    _inherit = 'product.template'

    def search_read(self, domain=None, fields=None, offset=0, limit=None, order=None):
        Products = self.env['product.template'].with_user(ROOT_UID)
        return Products.search([]).read(fields)
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)

    assert any(f.rule_id == "odoo-access-override-sudo-search" for f in findings)


def test_flags_class_constant_alias_with_user_superuser_search_override(tmp_path: Path) -> None:
    """Class-scoped SUPERUSER_ID aliases should still be treated as elevated reads."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class Product(models.Model):
    ROOT_BASE = SUPERUSER_ID
    ROOT_UID = ROOT_BASE
    MODEL_NAME = 'product.template'
    _inherit = MODEL_NAME

    def search_read(self, domain=None, fields=None, offset=0, limit=None, order=None):
        Products = self.env['product.template'].with_user(ROOT_UID)
        return Products.search([]).read(fields)
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)

    assert any(
        f.rule_id == "odoo-access-override-sudo-search" and f.model == "product.template"
        for f in findings
    )


def test_flags_env_ref_admin_search_override(tmp_path: Path) -> None:
    """Search overrides should treat with_user(base.user_admin) as elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import models

class Product(models.Model):
    _inherit = 'product.template'

    def name_search(self, name='', args=None, operator='ilike', limit=100):
        Products = self.env['product.template'].with_user(self.env.ref('base.user_admin'))
        return Products.search([]).name_get()
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)

    assert any(f.rule_id == "odoo-access-override-sudo-search" for f in findings)


def test_flags_tuple_unpacked_sudo_search_override(tmp_path: Path) -> None:
    """Tuple-unpacked sudo aliases should still be visible in search overrides."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import models

class Product(models.Model):
    _inherit = 'product.template'

    def name_search(self, name='', args=None, operator='ilike', limit=100):
        Products, label = self.env['product.template'].sudo(), name
        return Products.search([]).name_get()
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)

    assert any(f.rule_id == "odoo-access-override-sudo-search" for f in findings)


def test_flags_named_expression_sudo_search_override(tmp_path: Path) -> None:
    """Walrus-assigned sudo aliases should still be visible in search overrides."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import models

class Product(models.Model):
    _inherit = 'product.template'

    def name_search(self, name='', args=None, operator='ilike', limit=100):
        if Products := self.env['product.template'].sudo():
            return Products.search([]).name_get()
        return []
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)

    assert any(f.rule_id == "odoo-access-override-sudo-search" for f in findings)


def test_flags_starred_tuple_sudo_search_override(tmp_path: Path) -> None:
    """Starred tuple sudo aliases should still be visible in search overrides."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import models

class Product(models.Model):
    _inherit = 'product.template'

    def name_search(self, name='', args=None, operator='ilike', limit=100):
        *Products, label = self.env['product.template'].sudo(), name
        return Products.search([]).name_get()
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)

    assert any(f.rule_id == "odoo-access-override-sudo-search" for f in findings)


def test_flags_starred_rest_sudo_search_override(tmp_path: Path) -> None:
    """Sudo hidden inside starred-rest aliases should still be visible."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "product.py").write_text(
        """
from odoo import models

class Product(models.Model):
    _inherit = 'product.template'

    def name_search(self, name='', args=None, operator='ilike', limit=100):
        first, *items = name, limit, self.env['product.template'].sudo()
        return items[1].search([]).name_get()
""",
        encoding="utf-8",
    )

    findings = scan_access_overrides(tmp_path)

    assert any(f.rule_id == "odoo-access-override-sudo-search" for f in findings)


def test_super_access_override_is_ignored(tmp_path: Path) -> None:
    """Access overrides that preserve super should not be noisy."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "safe.py").write_text(
        """
from odoo import models

class Safe(models.Model):
    _inherit = 'res.partner'

    def check_access_rule(self, operation):
        return super().check_access_rule(operation)
""",
        encoding="utf-8",
    )

    assert scan_access_overrides(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_access.py").write_text(
        """
class Sale(models.Model):
    def check_access_rights(self, operation, raise_exception=True):
        return True
""",
        encoding="utf-8",
    )

    assert scan_access_overrides(tmp_path) == []
