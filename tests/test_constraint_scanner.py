"""Tests for risky Odoo constraint scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.constraint_scanner import scan_constraints


def test_flags_empty_and_dynamic_constraint_fields(tmp_path: Path) -> None:
    """Constraints should declare literal watched fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "empty.py").write_text(
        """
from odoo import api, models

FIELD_NAME = 'code'

class Product(models.Model):
    _name = 'x.product'

    @api.constrains()
    def _check_empty(self):
        pass

    @api.constrains(FIELD_NAME.upper())
    def _check_dynamic(self):
        pass
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-empty-fields" in rule_ids
    assert "odoo-constraint-dynamic-field" in rule_ids


def test_flags_direct_model_base_constraint(tmp_path: Path) -> None:
    """Direct Model bases should not hide constraint methods."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "empty.py").write_text(
        """
from odoo import api
from odoo.models import Model

class Product(Model):
    _name = 'x.product'

    @api.constrains()
    def _check_empty(self):
        pass
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)

    assert any(f.rule_id == "odoo-constraint-empty-fields" for f in findings)


def test_flags_aliased_odoo_api_module_constraint(tmp_path: Path) -> None:
    """Aliased Odoo API modules should not hide constraint decorators."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "empty.py").write_text(
        """
from odoo import api as odoo_api, models

class Product(models.Model):
    _name = 'x.product'

    @odoo_api.constrains()
    def _check_empty(self):
        pass
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)

    assert any(f.rule_id == "odoo-constraint-empty-fields" for f in findings)


def test_flags_imported_odoo_api_module_constraint(tmp_path: Path) -> None:
    """Direct odoo.api module imports should not hide constraint decorators."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "empty.py").write_text(
        """
import odoo.api as odoo_api
from odoo import models

class Product(models.Model):
    _name = 'x.product'

    @odoo_api.constrains()
    def _check_empty(self):
        pass
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)

    assert any(f.rule_id == "odoo-constraint-empty-fields" for f in findings)


def test_flags_imported_odoo_module_api_constraint(tmp_path: Path) -> None:
    """Direct odoo module imports should not hide constraint decorators."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "empty.py").write_text(
        """
import odoo as od

class Product(od.models.Model):
    _name = 'x.product'

    @od.api.constrains()
    def _check_empty(self):
        pass
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)

    assert any(f.rule_id == "odoo-constraint-empty-fields" for f in findings)


def test_flags_aliased_imported_constraint_decorator(tmp_path: Path) -> None:
    """Aliased direct constraint decorator imports should remain visible."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "empty.py").write_text(
        """
from odoo import models
from odoo.api import constrains as validates

class Product(models.Model):
    _name = 'x.product'

    @validates()
    def _check_empty(self):
        pass
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)

    assert any(f.rule_id == "odoo-constraint-empty-fields" for f in findings)


def test_flags_dotted_constraint_field_and_ignored_return(tmp_path: Path) -> None:
    """Dotted fields do not reliably trigger and returned values do not reject records."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import api, models

class Partner(models.Model):
    _name = 'x.partner'

    @api.constrains('company_id.name')
    def _check_company_name(self):
        return False
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-dotted-field" in rule_ids
    assert "odoo-constraint-return-ignored" in rule_ids


def test_flags_constant_backed_dotted_field_model_and_ignored_return(tmp_path: Path) -> None:
    """Constant-backed model names, fields, and returns should still be reviewed."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import api, models

MODEL_NAME = 'x.partner'
DOTTED_FIELD = 'company_id.name'
IGNORED = False

class Partner(models.Model):
    _name = MODEL_NAME

    @api.constrains(DOTTED_FIELD)
    def _check_company_name(self):
        return IGNORED
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-dotted-field" in rule_ids
    assert "odoo-constraint-return-ignored" in rule_ids
    assert any(f.model == "x.partner" for f in findings)


def test_flags_class_constant_backed_dotted_field_model_and_ignored_return(tmp_path: Path) -> None:
    """Class-scoped constant aliases should still drive constraint checks."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import api, models

class Partner(models.Model):
    MODEL_BASE = 'x.partner'
    MODEL_NAME = MODEL_BASE
    DOTTED_BASE = 'company_id.name'
    DOTTED_FIELD = DOTTED_BASE
    IGNORED_BASE = False
    IGNORED = IGNORED_BASE
    _name = MODEL_NAME

    @api.constrains(DOTTED_FIELD)
    def _check_company_name(self):
        return IGNORED
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-dotted-field" in rule_ids
    assert "odoo-constraint-return-ignored" in rule_ids
    assert "odoo-constraint-dynamic-field" not in rule_ids
    assert any(f.model == "x.partner" for f in findings)


def test_flags_sudo_and_unbounded_search_in_constraint(tmp_path: Path) -> None:
    """Constraint searches should avoid sudo() bypasses and unbounded scans."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "code.py").write_text(
        """
from odoo import api, models

class Code(models.Model):
    _name = 'x.code'

    @api.constrains('code')
    def _check_code_unique(self):
        duplicates = self.env['x.code'].sudo().search([('code', '=', self.code)])
        if duplicates:
            raise ValidationError('duplicate')
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-sudo-search" in rule_ids
    assert "odoo-constraint-unbounded-search" in rule_ids


def test_flags_aliased_sudo_search_in_constraint(tmp_path: Path) -> None:
    """Sudo model aliases in constraints should keep sudo-read posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "code.py").write_text(
        """
from odoo import api, models

class Code(models.Model):
    _name = 'x.code'

    @api.constrains('code')
    def _check_code_unique(self):
        Codes = self.env['x.code'].sudo()
        duplicates = Codes.search([('code', '=', self.code)])
        if duplicates:
            raise ValidationError('duplicate')
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-sudo-search" in rule_ids
    assert "odoo-constraint-unbounded-search" in rule_ids


def test_flags_with_user_superuser_search_in_constraint(tmp_path: Path) -> None:
    """SUPERUSER_ID elevation in constraints should be treated like sudo."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "code.py").write_text(
        """
from odoo import SUPERUSER_ID, api, models

class Code(models.Model):
    _name = 'x.code'

    @api.constrains('code')
    def _check_code_unique(self):
        duplicates = self.env['x.code'].with_user(SUPERUSER_ID).search([('code', '=', self.code)])
        if duplicates:
            raise ValidationError('duplicate')
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-sudo-search" in rule_ids
    assert "odoo-constraint-unbounded-search" in rule_ids


def test_flags_import_aliased_superuser_search_in_constraint(tmp_path: Path) -> None:
    """Imported SUPERUSER_ID aliases in constraints should be treated like sudo."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "code.py").write_text(
        """
from odoo import SUPERUSER_ID as ROOT_UID, api, models

class Code(models.Model):
    _name = 'x.code'

    @api.constrains('code')
    def _check_code_unique(self):
        duplicates = self.env['x.code'].with_user(ROOT_UID).search([('code', '=', self.code)])
        if duplicates:
            raise ValidationError('duplicate')
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-sudo-search" in rule_ids
    assert "odoo-constraint-unbounded-search" in rule_ids


def test_flags_sudo_search_count_in_constraint(tmp_path: Path) -> None:
    """search_count() in constraints has the same sudo and unbounded-query risk as search()."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "code.py").write_text(
        """
from odoo import api, models

class Code(models.Model):
    _name = 'x.code'

    @api.constrains('code')
    def _check_code_unique(self):
        if self.env['x.code'].sudo().search_count([('code', '=', self.code)]):
            raise ValidationError('duplicate')
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-sudo-search" in rule_ids
    assert "odoo-constraint-unbounded-search" in rule_ids


def test_flags_sudo_read_group_in_constraint(tmp_path: Path) -> None:
    """read_group() in constraints can bypass visibility and aggregate large tables."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "code.py").write_text(
        """
from odoo import api, models

class Code(models.Model):
    _name = 'x.code'

    @api.constrains('code')
    def _check_code_unique(self):
        groups = self.env['x.code'].sudo().read_group(
            [('code', '=', self.code)],
            ['id:count'],
            ['company_id'],
        )
        if groups:
            raise ValidationError('duplicate')
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-sudo-search" in rule_ids
    assert "odoo-constraint-unbounded-search" in rule_ids


def test_flags_unbounded_search_count_without_sudo_in_constraint(tmp_path: Path) -> None:
    """search_count() without sudo should still be visible as a potentially expensive validation query."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "code.py").write_text(
        """
from odoo import api, models

class Code(models.Model):
    _name = 'x.code'

    @api.constrains('code')
    def _check_code_unique(self):
        if self.env['x.code'].search_count([('code', '=', self.code)]):
            raise ValidationError('duplicate')
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-unbounded-search" in rule_ids
    assert "odoo-constraint-sudo-search" not in rule_ids


def test_flags_keyword_with_user_superuser_search_in_constraint(tmp_path: Path) -> None:
    """Keyword with_user(user=SUPERUSER_ID) constraints are elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "code.py").write_text(
        """
from odoo import SUPERUSER_ID, api, models

class Code(models.Model):
    _name = 'x.code'

    @api.constrains('code')
    def _check_code_unique(self):
        duplicates = self.env['x.code'].with_user(user=SUPERUSER_ID).search([('code', '=', self.code)])
        if duplicates:
            raise ValidationError('duplicate')
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-sudo-search" in rule_ids
    assert "odoo-constraint-unbounded-search" in rule_ids


def test_flags_aliased_with_user_one_search_in_constraint(tmp_path: Path) -> None:
    """Aliases elevated with user id 1 should keep sudo-read posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "code.py").write_text(
        """
from odoo import api, models

class Code(models.Model):
    _name = 'x.code'

    @api.constrains('code')
    def _check_code_unique(self):
        Codes = self.env['x.code'].with_user(1)
        duplicates = Codes.search([('code', '=', self.code)])
        if duplicates:
            raise ValidationError('duplicate')
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-sudo-search" in rule_ids
    assert "odoo-constraint-unbounded-search" in rule_ids


def test_flags_constant_backed_with_user_root_search_in_constraint(tmp_path: Path) -> None:
    """Constant-backed superuser values should keep sudo-read posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "code.py").write_text(
        """
from odoo import api, models

ROOT_UID = 1
CODE_FIELD = 'code'

class Code(models.Model):
    _name = 'x.code'

    @api.constrains(CODE_FIELD)
    def _check_code_unique(self):
        Codes = self.env['x.code'].with_user(ROOT_UID)
        duplicates = Codes.search([('code', '=', self.code)])
        if duplicates:
            raise ValidationError('duplicate')
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-sudo-search" in rule_ids
    assert "odoo-constraint-unbounded-search" in rule_ids
    assert "odoo-constraint-dynamic-field" not in rule_ids


def test_flags_class_constant_backed_with_user_root_search_in_constraint(tmp_path: Path) -> None:
    """Class-scoped superuser and field aliases should keep sudo-read posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "code.py").write_text(
        """
from odoo import api, models

class Code(models.Model):
    ROOT_BASE = 1
    ROOT_UID = ROOT_BASE
    CODE_BASE = 'code'
    CODE_FIELD = CODE_BASE
    MODEL_NAME = 'x.code'
    _name = MODEL_NAME

    @api.constrains(CODE_FIELD)
    def _check_code_unique(self):
        Codes = self.env['x.code'].with_user(ROOT_UID)
        duplicates = Codes.search([('code', '=', self.code)])
        if duplicates:
            raise ValidationError('duplicate')
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-sudo-search" in rule_ids
    assert "odoo-constraint-unbounded-search" in rule_ids
    assert "odoo-constraint-dynamic-field" not in rule_ids
    assert any(f.model == "x.code" for f in findings)


def test_flags_env_ref_admin_search_in_constraint(tmp_path: Path) -> None:
    """Aliases elevated with base.user_admin should keep sudo-read posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "code.py").write_text(
        """
from odoo import api, models

class Code(models.Model):
    _name = 'x.code'

    @api.constrains('code')
    def _check_code_unique(self):
        Codes = self.env['x.code'].with_user(self.env.ref('base.user_admin'))
        duplicates = Codes.search([('code', '=', self.code)])
        if duplicates:
            raise ValidationError('duplicate')
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-sudo-search" in rule_ids
    assert "odoo-constraint-unbounded-search" in rule_ids


def test_flags_tuple_unpacked_sudo_search_in_constraint(tmp_path: Path) -> None:
    """Tuple-unpacked sudo model aliases in constraints should keep sudo-read posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "code.py").write_text(
        """
from odoo import api, models

class Code(models.Model):
    _name = 'x.code'

    @api.constrains('code')
    def _check_code_unique(self):
        Codes, Partners = self.env['x.code'].sudo(), self.env['res.partner'].sudo()
        duplicates = Codes.search([('code', '=', self.code)])
        if duplicates:
            raise ValidationError('duplicate')
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-sudo-search" in rule_ids
    assert "odoo-constraint-unbounded-search" in rule_ids


def test_flags_named_expression_sudo_search_in_constraint(tmp_path: Path) -> None:
    """Walrus-assigned sudo model aliases in constraints should keep sudo-read posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "code.py").write_text(
        """
from odoo import api, models

class Code(models.Model):
    _name = 'x.code'

    @api.constrains('code')
    def _check_code_unique(self):
        if Codes := self.env['x.code'].sudo():
            duplicates = Codes.search([('code', '=', self.code)])
            if duplicates:
                raise ValidationError('duplicate')
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-sudo-search" in rule_ids
    assert "odoo-constraint-unbounded-search" in rule_ids


def test_flags_starred_tuple_sudo_search_in_constraint(tmp_path: Path) -> None:
    """Starred tuple sudo aliases in constraints should keep sudo-read posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "code.py").write_text(
        """
from odoo import api, models

class Code(models.Model):
    _name = 'x.code'

    @api.constrains('code')
    def _check_code_unique(self):
        *Codes, label = self.env['x.code'].sudo(), self.code
        duplicates = Codes.search([('code', '=', self.code)])
        if duplicates:
            raise ValidationError('duplicate')
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-sudo-search" in rule_ids
    assert "odoo-constraint-unbounded-search" in rule_ids


def test_flags_starred_rest_sudo_search_in_constraint(tmp_path: Path) -> None:
    """Starred-rest sudo aliases in constraints should keep sudo-read posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "code.py").write_text(
        """
from odoo import api, models

class Code(models.Model):
    _name = 'x.code'

    @api.constrains('code')
    def _check_code_unique(self):
        label, *items = self.code, self.env['x.code'].sudo(), self.env['res.partner']
        Codes = items[0]
        duplicates = Codes.search([('code', '=', self.code)])
        if duplicates:
            raise ValidationError('duplicate')
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-constraint-sudo-search" in rule_ids
    assert "odoo-constraint-unbounded-search" in rule_ids


def test_mixed_tuple_sudo_alias_does_not_overtaint_constraint(tmp_path: Path) -> None:
    """Mixed tuple assignments should not mark non-sudo constraint neighbors."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "code.py").write_text(
        """
from odoo import api, models

class Code(models.Model):
    _name = 'x.code'

    @api.constrains('code')
    def _check_code_unique(self):
        Codes, Partners = self.env['x.code'].sudo(), self.env['res.partner']
        partners = Partners.search([('name', '=', self.name)])
        if partners:
            raise ValidationError('duplicate')
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)

    assert not any(f.rule_id == "odoo-constraint-sudo-search" for f in findings)


def test_flags_ensure_one_in_constraint(tmp_path: Path) -> None:
    """Constraints should validate multi-record recordsets safely."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "singleton.py").write_text(
        """
from odoo import api, models

class Singleton(models.Model):
    _name = 'x.singleton'

    @api.constrains('name')
    def _check_name(self):
        self.ensure_one()
        if not self.name:
            raise ValidationError('missing')
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)

    assert any(finding.rule_id == "odoo-constraint-ensure-one" for finding in findings)


def test_named_constraint_method_is_scanned(tmp_path: Path) -> None:
    """Legacy _check methods should still be reviewed for risky logic."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "legacy.py").write_text(
        """
from odoo import models

class Legacy(models.Model):
    _name = 'x.legacy'

    def _check_legacy(self):
        return None
""",
        encoding="utf-8",
    )

    findings = scan_constraints(tmp_path)

    assert any(finding.rule_id == "odoo-constraint-return-ignored" for finding in findings)


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Constraint fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_constraint.py").write_text(
        """
from odoo import api, models

class Product(models.Model):
    @api.constrains()
    def _check_empty(self):
        pass
""",
        encoding="utf-8",
    )

    assert scan_constraints(tmp_path) == []
