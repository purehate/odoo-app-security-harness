"""Tests for Odoo runtime raw SQL scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.raw_sql_scanner import scan_raw_sql


def test_flags_interpolated_query_variable(tmp_path: Path) -> None:
    """Runtime cr.execute should not receive interpolated SQL variables."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import models

class Partner(models.Model):
    _name = 'x.partner'

    def by_name(self, name):
        query = "SELECT * FROM res_partner WHERE name = '%s'" % name
        self.env.cr.execute(query)
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-interpolated-query" for f in findings)


def test_flags_keyword_interpolated_query(tmp_path: Path) -> None:
    """Keyword SQL arguments should receive the same interpolation review."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import models

class Partner(models.Model):
    _name = 'x.partner'

    def by_name(self, name):
        query = "SELECT * FROM res_partner WHERE name = '%s'" % name
        self.env.cr.execute(query=query)
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-interpolated-query" for f in findings)


def test_flags_aliased_cursor_interpolated_query(tmp_path: Path) -> None:
    """Cursor aliases should not hide interpolated raw SQL."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import models

class Partner(models.Model):
    _name = 'x.partner'

    def by_name(self, name):
        cursor = self.env.cr
        query = f"SELECT * FROM res_partner WHERE name = {name}"
        cursor.execute(query)
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-interpolated-query" for f in findings)


def test_flags_named_expression_cursor_interpolated_query(tmp_path: Path) -> None:
    """Walrus-bound cursor aliases should not hide interpolated raw SQL."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import models

class Partner(models.Model):
    _name = 'x.partner'

    def by_name(self, name):
        query = f"SELECT * FROM res_partner WHERE name = {name}"
        if cursor := self.env.cr:
            cursor.execute(query)
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-interpolated-query" for f in findings)


def test_flags_named_expression_query_alias_interpolated_query(tmp_path: Path) -> None:
    """Walrus-bound unsafe query aliases should still be reported."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import models

class Partner(models.Model):
    _name = 'x.partner'

    def by_name(self, name):
        if query := f"SELECT * FROM res_partner WHERE name = {name}":
            self.env.cr.execute(query)
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-interpolated-query" for f in findings)


def test_flags_copy_expert_interpolated_query(tmp_path: Path) -> None:
    """Cursor copy_expert runs raw SQL and should reject interpolated SQL text."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "export.py").write_text(
        """
from io import StringIO
from odoo import models

class Export(models.Model):
    _name = 'x.export'

    def export_table(self, table_name):
        query = "COPY %s TO STDOUT WITH CSV" % table_name
        self.env.cr.copy_expert(query, StringIO())
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-interpolated-query" and f.sink == "self.env.cr.copy_expert" for f in findings)


def test_flags_execute_values_interpolated_query(tmp_path: Path) -> None:
    """psycopg2 bulk helpers should be treated like raw SQL sinks."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "importer.py").write_text(
        """
from psycopg2.extras import execute_values
from odoo import models

class Importer(models.Model):
    _name = 'x.importer'

    def import_rows(self, table_name, rows):
        query = f"INSERT INTO {table_name} (name) VALUES %s"
        execute_values(self.env.cr, query, rows)
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-interpolated-query" and f.sink == "execute_values" for f in findings)


def test_flags_execute_batch_request_derived_params(tmp_path: Path) -> None:
    """Request-derived bulk helper parameter lists need the same raw SQL review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "importer.py").write_text(
        """
from psycopg2.extras import execute_batch
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/import', auth='user', type='json')
    def import_rows(self):
        payload = request.get_json_data()
        execute_batch(request.env.cr, "INSERT INTO x_table (name) VALUES (%s)", payload.get('rows'))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" and f.sink == "execute_batch" for f in findings)


def test_flags_starred_cursor_interpolated_query(tmp_path: Path) -> None:
    """Starred cursor aliases should not hide interpolated raw SQL."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import models

class Partner(models.Model):
    _name = 'x.partner'

    def by_name(self, name):
        *cursor, marker = self.env.cr, 'x'
        query = f"SELECT * FROM res_partner WHERE name = {name}"
        cursor.execute(query)
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-interpolated-query" for f in findings)


def test_flags_starred_rest_cursor_interpolated_query(tmp_path: Path) -> None:
    """Starred-rest cursor aliases should not hide interpolated raw SQL."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import models

class Partner(models.Model):
    _name = 'x.partner'

    def by_name(self, name):
        marker, *items = 'x', self.env.cr, self.env.user
        cursor = items[0]
        query = f"SELECT * FROM res_partner WHERE name = {name}"
        cursor.execute(query)
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-interpolated-query" for f in findings)


def test_flags_starred_rest_query_alias_interpolated_query(tmp_path: Path) -> None:
    """Starred-rest unsafe SQL aliases should still be reported."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import models

class Partner(models.Model):
    _name = 'x.partner'

    def by_name(self, name):
        marker, *items = 'x', f"SELECT * FROM res_partner WHERE name = {name}", self.env.user
        query = items[0]
        self.env.cr.execute(query)
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-interpolated-query" for f in findings)


def test_reassigned_interpolated_query_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing a query variable for safe SQL should clear prior unsafe-SQL state."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import models

class Partner(models.Model):
    _name = 'x.partner'

    def by_name(self, name):
        query = "SELECT * FROM res_partner WHERE name = '%s'" % name
        query = "SELECT * FROM res_partner WHERE active"
        self.env.cr.execute(query)
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert not any(f.rule_id == "odoo-raw-sql-interpolated-query" for f in findings)


def test_reassigned_cursor_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing a cursor alias for another object should clear prior cursor state."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "cleanup.py").write_text(
        """
from odoo import models

class Cleanup(models.Model):
    _name = 'x.cleanup'

    def cleanup(self):
        cursor = self.env.cr
        cursor = object()
        cursor.execute("DELETE FROM sale_order")
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert not any(f.rule_id == "odoo-raw-sql-broad-destructive-query" for f in findings)


def test_flags_request_derived_sql_parameter(tmp_path: Path) -> None:
    """Request-derived SQL inputs should still be surfaced for binding/access review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/lookup', auth='user')
    def lookup(self, **kwargs):
        partner_id = kwargs.get('partner_id')
        request.env.cr.execute("SELECT * FROM res_partner WHERE id = %s", (partner_id,))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_flags_keyword_request_derived_sql_parameter(tmp_path: Path) -> None:
    """Keyword SQL parameters should still surface request-derived input."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/lookup', auth='user')
    def lookup(self, **kwargs):
        partner_id = kwargs.get('partner_id')
        request.env.cr.execute(
            sql="SELECT * FROM res_partner WHERE id = %s",
            params=(partner_id,),
        )
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_flags_dict_union_keyword_request_derived_sql_parameter(tmp_path: Path) -> None:
    """Dict-union execute **kwargs should surface request-derived input."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/lookup', auth='user')
    def lookup(self, **kwargs):
        partner_id = kwargs.get('partner_id')
        execute_kwargs = {
            'sql': 'SELECT * FROM res_partner WHERE id = %s',
            'params': (),
        } | {'params': (partner_id,)}
        request.env.cr.execute(**execute_kwargs)
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_boolop_derived_sql_parameter_is_reported(tmp_path: Path) -> None:
    """Boolean fallback expressions should not clear request taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/lookup', auth='user')
    def lookup(self, **kwargs):
        partner_id = kwargs.get('partner_id') or self.env.user.partner_id.id
        request.env.cr.execute("SELECT * FROM res_partner WHERE id = %s", (partner_id,))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_reassigned_request_sql_parameter_is_not_stale(tmp_path: Path) -> None:
    """Safe reassignment should clear request taint before raw SQL use."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/lookup', auth='user')
    def lookup(self, **kwargs):
        partner_id = kwargs.get('partner_id')
        partner_id = self.env.user.partner_id.id
        request.env.cr.execute("SELECT * FROM res_partner WHERE id = %s", (partner_id,))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert not any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_flags_loop_derived_sql_parameter(tmp_path: Path) -> None:
    """Loop variables from request-derived iterables should remain tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/lookup', auth='user')
    def lookup(self, **kwargs):
        partner_ids = kwargs.get('partner_ids')
        for partner_id in partner_ids:
            request.env.cr.execute("SELECT * FROM res_partner WHERE id = %s", (partner_id,))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_safe_loop_reassignment_clears_sql_parameter_taint(tmp_path: Path) -> None:
    """Safe loop targets should clear stale request taint before raw SQL use."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/lookup', auth='user')
    def lookup(self, **kwargs):
        partner_id = kwargs.get('partner_id')
        for partner_id in [self.env.user.partner_id.id]:
            request.env.cr.execute("SELECT * FROM res_partner WHERE id = %s", (partner_id,))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert not any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_flags_comprehension_derived_sql_parameter(tmp_path: Path) -> None:
    """Comprehensions carrying request data into SQL parameters should be reported."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/lookup', auth='user')
    def lookup(self, **kwargs):
        partner_ids = kwargs.get('partner_ids')
        ids = [partner_id for partner_id in partner_ids]
        request.env.cr.execute("SELECT * FROM res_partner WHERE id = ANY(%s)", (ids,))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_flags_comprehension_filter_derived_sql_parameter(tmp_path: Path) -> None:
    """Request-only comprehension filters should taint generated SQL parameters."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/lookup', auth='user')
    def lookup(self, **kwargs):
        ids = [1 for _ in range(1) if kwargs.get('partner_ids')]
        request.env.cr.execute("SELECT * FROM res_partner WHERE id = ANY(%s)", (ids,))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_flags_named_expression_derived_sql_parameter(tmp_path: Path) -> None:
    """Walrus-bound request parameters should remain tainted after the condition."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/lookup', auth='user')
    def lookup(self, **kwargs):
        if partner_id := kwargs.get('partner_id'):
            request.env.cr.execute("SELECT * FROM res_partner WHERE id = %s", (partner_id,))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_flags_aliased_cursor_request_derived_sql_parameter(tmp_path: Path) -> None:
    """Cursor aliases should still surface request-derived SQL parameters."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/lookup', auth='user')
    def lookup(self, **kwargs):
        cursor = request.env.cr
        partner_id = kwargs.get('partner_id')
        cursor.execute("SELECT * FROM res_partner WHERE id = %s", (partner_id,))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_flags_get_json_data_sql_parameter(tmp_path: Path) -> None:
    """JSON payload values should be request-derived when passed to raw SQL."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/lookup', auth='user', type='json')
    def lookup(self):
        payload = request.get_json_data()
        request.env.cr.execute("SELECT * FROM res_partner WHERE id = %s", (payload.get('partner_id'),))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_flags_get_http_params_sql_parameter(tmp_path: Path) -> None:
    """Merged query/form values should be request-derived when passed to raw SQL."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/lookup', auth='user')
    def lookup(self):
        payload = request.get_http_params()
        request.env.cr.execute("SELECT * FROM res_partner WHERE id = %s", (payload.get('partner_id'),))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_flags_aliased_request_sql_parameter(tmp_path: Path) -> None:
    """Aliased Odoo request imports should still seed raw SQL taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Controller(http.Controller):
    @http.route('/lookup', auth='user')
    def lookup(self):
        payload = req.get_http_params()
        req.env.cr.execute("SELECT * FROM res_partner WHERE id = %s", (payload.get('partner_id'),))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_flags_imported_odoo_http_module_sql_parameter(tmp_path: Path) -> None:
    """Direct odoo.http request access should seed raw SQL taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
import odoo.http as odoo_http

class Controller(odoo_http.Controller):
    @odoo_http.route('/lookup', auth='user')
    def lookup(self):
        payload = odoo_http.request.get_http_params()
        odoo_http.request.env.cr.execute("SELECT * FROM res_partner WHERE id = %s", (payload.get('partner_id'),))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_flags_imported_odoo_module_sql_parameter(tmp_path: Path) -> None:
    """Direct odoo module request access should seed raw SQL taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
import odoo as od

class Controller(od.http.Controller):
    @od.http.route('/lookup', auth='user')
    def lookup(self):
        payload = od.http.request.get_http_params()
        od.http.request.env.cr.execute("SELECT * FROM res_partner WHERE id = %s", (payload.get('partner_id'),))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_flags_route_path_sql_parameter(tmp_path: Path) -> None:
    """Odoo route path parameters should remain request-derived in raw SQL parameters."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/lookup/<int:partner_id>', auth='public')
    def lookup(self, partner_id):
        request.env.cr.execute("SELECT * FROM res_partner WHERE id = %s", (partner_id,))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_flags_aliased_imported_route_path_sql_parameter(tmp_path: Path) -> None:
    """Aliased imported route decorators should still taint route path parameters."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request, route as odoo_route

class Controller(http.Controller):
    @odoo_route('/lookup/<int:partner_id>', auth='public')
    def lookup(self, partner_id):
        request.env.cr.execute("SELECT * FROM res_partner WHERE id = %s", (partner_id,))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_flags_aliased_http_module_route_path_sql_parameter(tmp_path: Path) -> None:
    """Aliased Odoo http modules should still taint route path parameters."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http as odoo_http
from odoo.http import request

class Controller(odoo_http.Controller):
    @odoo_http.route('/lookup/<int:partner_id>', auth='public')
    def lookup(self, partner_id):
        request.env.cr.execute("SELECT * FROM res_partner WHERE id = %s", (partner_id,))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_flags_imported_odoo_http_module_route_path_sql_parameter(tmp_path: Path) -> None:
    """Direct odoo.http imports should still taint route path parameters."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
import odoo.http as odoo_http

class Controller(odoo_http.Controller):
    @odoo_http.route('/lookup/<int:partner_id>', auth='public')
    def lookup(self, partner_id):
        odoo_http.request.env.cr.execute("SELECT * FROM res_partner WHERE id = %s", (partner_id,))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_flags_imported_odoo_module_route_path_sql_parameter(tmp_path: Path) -> None:
    """Direct odoo module imports should still taint route path parameters."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
import odoo as od

class Controller(od.http.Controller):
    @od.http.route('/lookup/<int:partner_id>', auth='public')
    def lookup(self, partner_id):
        od.http.request.env.cr.execute("SELECT * FROM res_partner WHERE id = %s", (partner_id,))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_ignores_non_odoo_bare_route_decorator_parameters(tmp_path: Path) -> None:
    """Bare route decorators should not taint parameters without an Odoo route import."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo.http import request

def route(path, **kwargs):
    return lambda func: func

class Controller:
    @route('/lookup/<int:partner_id>', auth='public')
    def lookup(self, partner_id):
        request.env.cr.execute("SELECT * FROM res_partner WHERE id = %s", (partner_id,))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert not any(f.rule_id == "odoo-raw-sql-request-derived-input" for f in findings)


def test_flags_broad_destructive_runtime_sql(tmp_path: Path) -> None:
    """Runtime destructive SQL without WHERE should be a high-signal review finding."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "cleanup.py").write_text(
        """
from odoo import models

class Cleanup(models.Model):
    _name = 'x.cleanup'

    def cleanup(self):
        self.env.cr.execute("DELETE FROM sale_order")
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-broad-destructive-query" for f in findings)


def test_flags_broad_destructive_runtime_sql_alias(tmp_path: Path) -> None:
    """Destructive SQL should stay visible when assigned before execute."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "cleanup.py").write_text(
        """
from odoo import models

class Cleanup(models.Model):
    _name = 'x.cleanup'

    def cleanup(self):
        query = "DELETE FROM sale_order"
        self.env.cr.execute(query)
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-broad-destructive-query" for f in findings)


def test_flags_dict_union_keyword_broad_destructive_runtime_sql(tmp_path: Path) -> None:
    """Dict-union execute **kwargs should not hide destructive SQL literals."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "cleanup.py").write_text(
        """
from odoo import models

class Cleanup(models.Model):
    _name = 'x.cleanup'

    def cleanup(self):
        execute_kwargs = {'query': 'SELECT 1'} | {'query': 'DELETE FROM sale_order'}
        self.env.cr.execute(**execute_kwargs)
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-broad-destructive-query" for f in findings)


def test_reassigned_broad_destructive_runtime_sql_alias_is_not_stale(tmp_path: Path) -> None:
    """Reassigned SQL aliases should clear literal destructive-query state."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "cleanup.py").write_text(
        """
from odoo import models

class Cleanup(models.Model):
    _name = 'x.cleanup'

    def cleanup(self):
        query = "DELETE FROM sale_order"
        query = "SELECT * FROM sale_order WHERE id = %s"
        self.env.cr.execute(query, (self.id,))
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert not any(f.rule_id == "odoo-raw-sql-broad-destructive-query" for f in findings)


def test_flags_runtime_sql_write_without_company_scope(tmp_path: Path) -> None:
    """Runtime UPDATE/DELETE should be checked for company-equivalent scoping."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "orders.py").write_text(
        """
from odoo import models

class Orders(models.Model):
    _name = 'x.orders'

    def close_old(self):
        self.env.cr.execute("UPDATE sale_order SET state = 'done' WHERE state = 'sale'")
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-write-no-company-scope" for f in findings)


def test_flags_runtime_sql_write_alias_without_company_scope(tmp_path: Path) -> None:
    """Literal UPDATE aliases should still be reviewed for company scoping."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "orders.py").write_text(
        """
from odoo import models

class Orders(models.Model):
    _name = 'x.orders'

    def close_old(self):
        query = "UPDATE sale_order SET state = 'done' WHERE state = 'sale'"
        self.env.cr.execute(query)
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-write-no-company-scope" for f in findings)


def test_flags_manual_transaction_control(tmp_path: Path) -> None:
    """Runtime commit/rollback should be surfaced outside migration-specific scanning."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "txn.py").write_text(
        """
from odoo import models

class Txn(models.Model):
    _name = 'x.txn'

    def partial(self):
        self.env.cr.commit()
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-manual-transaction" for f in findings)


def test_flags_aliased_cursor_manual_transaction_control(tmp_path: Path) -> None:
    """Manual transaction calls should be reported through cursor aliases."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "txn.py").write_text(
        """
from odoo import models

class Txn(models.Model):
    _name = 'x.txn'

    def partial(self):
        cursor = self.env.cr
        cursor.rollback()
""",
        encoding="utf-8",
    )

    findings = scan_raw_sql(tmp_path)

    assert any(f.rule_id == "odoo-raw-sql-manual-transaction" for f in findings)


def test_parameterized_non_request_query_is_ignored(tmp_path: Path) -> None:
    """Plain parameterized reads should not be noisy."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "safe.py").write_text(
        """
from odoo import models

class Safe(models.Model):
    _name = 'x.safe'

    def lookup(self):
        self.env.cr.execute("SELECT * FROM res_partner WHERE id = %s", (self.partner_id.id,))
""",
        encoding="utf-8",
    )

    assert scan_raw_sql(tmp_path) == []


def test_repo_scan_skips_tests_and_migrations(tmp_path: Path) -> None:
    """Raw SQL scanner should leave test and migration SQL to their own checks."""
    tests = tmp_path / "tests"
    migrations = tmp_path / "module" / "migrations" / "17.0.1.0"
    tests.mkdir()
    migrations.mkdir(parents=True)
    (tests / "test_sql.py").write_text("env.cr.execute(f'SELECT {name}')", encoding="utf-8")
    (migrations / "post-migrate.py").write_text("cr.execute('DELETE FROM sale_order')", encoding="utf-8")

    assert scan_raw_sql(tmp_path) == []
