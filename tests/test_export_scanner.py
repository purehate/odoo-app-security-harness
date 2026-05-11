"""Tests for CSV/XLSX export formula injection scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.export_scanner import ExportScanner, scan_exports


def test_csv_writerow_with_record_data_is_reported(tmp_path: Path) -> None:
    """CSV exports should neutralize formula-prefixed record data."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(writer, records):
    for record in records:
        writer.writerow([record.name, record.email])
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-csv-formula-injection" for f in findings)


def test_csv_writerow_with_nonstandard_loop_variable_is_reported(tmp_path: Path) -> None:
    """Loop targets derived from records should taint arbitrary variable names."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(writer, records):
    for partner in records:
        writer.writerow([partner.name, partner.email])
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-csv-formula-injection" for f in findings)


def test_safe_loop_reassignment_clears_export_taint(tmp_path: Path) -> None:
    """Loop targets should not stay tainted after rebinding from safe data."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(writer, records):
    for row in records:
        pass
    for row in [['Name', 'Email']]:
        writer.writerow(row)
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-export-csv-formula-injection" for f in findings)


def test_xlsx_write_with_record_data_is_reported(tmp_path: Path) -> None:
    """XLSX exports should avoid writing unsanitized user/customer fields."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(sheet, records):
    for row, record in enumerate(records):
        sheet.write(row, 0, record.name)
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-xlsx-formula-injection" for f in findings)


def test_annotated_export_rows_are_reported(tmp_path: Path) -> None:
    """Annotated aliases should preserve export taint before writerows."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(writer, records):
    rows: list = records
    writer.writerows(rows)
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-csv-formula-injection" for f in findings)


def test_tuple_unpacked_export_rows_are_reported(tmp_path: Path) -> None:
    """Tuple-unpacked record-derived rows should preserve export taint."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(writer, records):
    rows, filename = records, 'partners.csv'
    writer.writerows(rows)
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-csv-formula-injection" for f in findings)


def test_starred_rest_export_rows_are_reported(tmp_path: Path) -> None:
    """Starred-rest record-derived rows should preserve export taint."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(writer, records):
    label, *items = 'partners.csv', records, ['Name', 'Email']
    rows = items[0]
    writer.writerows(rows)
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-csv-formula-injection" for f in findings)


def test_tuple_unpacked_safe_value_is_not_tainted_by_neighbor(tmp_path: Path) -> None:
    """Mixed tuple assignment should not taint safe neighbors beside record data."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(writer, records):
    rows, header = records, ['Name', 'Email']
    writer.writerow(header)
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-export-csv-formula-injection" for f in findings)


def test_tainted_xlsx_formula_is_high_severity(tmp_path: Path) -> None:
    """Formula sinks are higher risk when formula text is data-derived."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(sheet, **kwargs):
    formula = kwargs.get('formula')
    sheet.write_formula(0, 0, formula)
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-tainted-formula" and f.severity == "high" for f in findings)


def test_csv_dictwriter_with_request_data_is_reported(tmp_path: Path) -> None:
    """DictWriter-style exports should not hide request-derived cell values."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(writer, **kwargs):
    writer.writerow({'name': kwargs.get('name'), 'email': kwargs.get('email')})
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-csv-formula-injection" for f in findings)


def test_request_alias_csv_writerow_is_reported(tmp_path: Path) -> None:
    """Aliased Odoo request payloads should taint exported CSV rows."""
    py = tmp_path / "export.py"
    py.write_text(
        """
from odoo.http import request as req

def export(writer):
    row = req.get_json_data().get('row')
    writer.writerow(row)
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-csv-formula-injection" for f in findings)


def test_xlsx_write_row_with_record_data_is_reported(tmp_path: Path) -> None:
    """Bulk XLSX row/column helpers need the same formula review as cell writes."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(sheet, records):
    for row, record in enumerate(records):
        sheet.write_row(row, 0, [record.name, record.email])
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-xlsx-formula-injection" for f in findings)


def test_pandas_to_csv_with_record_dataframe_is_reported(tmp_path: Path) -> None:
    """DataFrame exports built from record data can still carry formulas."""
    py = tmp_path / "export.py"
    py.write_text(
        """
import pandas

def export(stream, records):
    rows = [{'name': record.name, 'email': record.email} for record in records]
    frame = pandas.DataFrame(rows)
    frame.to_csv(stream)
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-csv-formula-injection" for f in findings)


def test_comprehension_filter_derived_csv_row_is_reported(tmp_path: Path) -> None:
    """Request-derived comprehension filters should taint exported rows."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(writer, **kwargs):
    requested = kwargs.get('include')
    rows = [['Name', 'Email'] for marker in ['x'] if requested]
    writer.writerows(rows)
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-csv-formula-injection" for f in findings)


def test_named_expression_derived_csv_row_is_reported(tmp_path: Path) -> None:
    """Walrus-assigned request export rows should remain tainted."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(writer, **kwargs):
    if row := kwargs.get('row'):
        writer.writerow(row)
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-csv-formula-injection" for f in findings)


def test_boolop_derived_csv_row_is_reported(tmp_path: Path) -> None:
    """Boolean fallback expressions should keep exported rows tainted."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(writer, **kwargs):
    row = kwargs.get('row') or ['Name', 'Email']
    writer.writerow(row)
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-csv-formula-injection" for f in findings)


def test_sanitized_csv_value_is_not_reported(tmp_path: Path) -> None:
    """Visible sanitizer helpers should suppress formula-injection findings."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(writer, records):
    for record in records:
        writer.writerow([escape_formula(record.name)])
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-export-csv-formula-injection" for f in findings)


def test_flags_request_controlled_export_data_fields(tmp_path: Path) -> None:
    """Odoo export_data field lists should not come directly from request input."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(self, **kwargs):
    fields = kwargs.get('fields')
    return self.env['res.partner'].export_data(fields)
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-request-controlled-fields" for f in findings)


def test_request_alias_controlled_export_data_fields(tmp_path: Path) -> None:
    """Aliased request params should taint ORM export field lists."""
    py = tmp_path / "export.py"
    py.write_text(
        """
from odoo.http import request as req

def export(self):
    fields = req.params.get('fields')
    return self.env['res.partner'].export_data(fields)
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-request-controlled-fields" for f in findings)


def test_comprehension_filter_derived_export_fields_are_reported(tmp_path: Path) -> None:
    """Request-derived comprehension filters should taint ORM export fields."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(self, **kwargs):
    requested = kwargs.get('fields')
    fields = ['name' for marker in ['x'] if requested]
    return self.env['res.partner'].export_data(fields)
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-request-controlled-fields" for f in findings)


def test_flags_sensitive_export_data_fields(tmp_path: Path) -> None:
    """Sensitive ORM fields in export_data should be surfaced for authorization review."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(self):
    return self.env['res.users'].export_data(['login', 'groups_id', 'password'])
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-sensitive-fields" and f.sink == "export_data" for f in findings)


def test_flags_integration_key_export_data_fields(tmp_path: Path) -> None:
    """Integration-key shaped ORM fields in exports should be surfaced."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(self):
    return self.env['x.connector'].export_data(['name', 'access_key', 'license_key'])
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-export-sensitive-fields"
        and f.sink == "export_data"
        and "access_key" in f.message
        and "license_key" in f.message
        for f in findings
    )


def test_flags_search_read_sensitive_or_request_fields(tmp_path: Path) -> None:
    """search_read/read field arguments can become direct export surfaces."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(self, domain, **kwargs):
    self.env['res.users'].search_read(domain, fields=kwargs.get('fields'))
    self.env['res.partner'].search_read([], ['name', 'bank_ids'])
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-export-request-controlled-fields" in rule_ids
    assert "odoo-export-sensitive-fields" in rule_ids


def test_flags_read_sensitive_or_request_fields(tmp_path: Path) -> None:
    """read() receives its export field list as the first positional argument."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(self, **kwargs):
    self.env['res.users'].read(kwargs.get('fields'))
    self.env['res.users'].read(['login', 'groups_id'])
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-export-request-controlled-fields" in rule_ids
    assert "odoo-export-sensitive-fields" in rule_ids


def test_flags_route_path_controlled_search_read_fields(tmp_path: Path) -> None:
    """Odoo route path parameters should not control ORM export field lists."""
    py = tmp_path / "export.py"
    py.write_text(
        """
from odoo import http
from odoo.http import request

class ExportController(http.Controller):
    @http.route('/public/export/<string:field_names>', auth='public')
    def export(self, field_names):
        return request.env['res.users'].sudo().search_read([], fields=field_names.split(','))
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-request-controlled-fields" for f in findings)


def test_aliased_imported_route_path_controlled_search_read_fields(tmp_path: Path) -> None:
    """Aliased route decorators should still mark path parameters as export input."""
    py = tmp_path / "export.py"
    py.write_text(
        """
from odoo import http
from odoo.http import request, route as odoo_route

class ExportController(http.Controller):
    @odoo_route('/public/export/<string:field_names>', auth='public')
    def export(self, field_names):
        return request.env['res.users'].sudo().search_read([], fields=field_names.split(','))
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-request-controlled-fields" for f in findings)


def test_aliased_http_module_route_path_controlled_search_read_fields(tmp_path: Path) -> None:
    """Aliased odoo.http route decorators should mark path parameters as export input."""
    py = tmp_path / "export.py"
    py.write_text(
        """
from odoo import http as odoo_http
from odoo.http import request

class ExportController(odoo_http.Controller):
    @odoo_http.route('/public/export/<string:field_names>', auth='public')
    def export(self, field_names):
        return request.env['res.users'].sudo().search_read([], fields=field_names.split(','))
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-request-controlled-fields" for f in findings)


def test_imported_odoo_http_route_path_controlled_search_read_fields(tmp_path: Path) -> None:
    """Direct odoo.http imports should mark path parameters as export input."""
    py = tmp_path / "export.py"
    py.write_text(
        """
import odoo.http as odoo_http

class ExportController(odoo_http.Controller):
    @odoo_http.route('/public/export/<string:field_names>', auth='public')
    def export(self, field_names):
        return odoo_http.request.env['res.users'].sudo().search_read([], fields=field_names.split(','))
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-request-controlled-fields" for f in findings)


def test_imported_odoo_module_route_path_controlled_search_read_fields(tmp_path: Path) -> None:
    """Direct odoo imports should mark path parameters as export input."""
    py = tmp_path / "export.py"
    py.write_text(
        """
import odoo as od

class ExportController(od.http.Controller):
    @od.http.route('/public/export/<string:field_names>', auth='public')
    def export(self, field_names):
        return od.http.request.env['res.users'].sudo().search_read([], fields=field_names.split(','))
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert any(f.rule_id == "odoo-export-request-controlled-fields" for f in findings)


def test_non_odoo_route_decorator_does_not_taint_export_path_parameter(tmp_path: Path) -> None:
    """Local route decorators should not make arbitrary path parameters export input."""
    py = tmp_path / "export.py"
    py.write_text(
        """
from odoo import http
from odoo.http import request

class Router:
    def route(self, *args, **kwargs):
        def decorate(func):
            return func
        return decorate

router = Router()

class ExportController(http.Controller):
    @router.route('/public/export/<string:field_names>', auth='public')
    def export(self, field_names):
        return request.env['res.users'].sudo().search_read([], fields=field_names.split(','))
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-export-request-controlled-fields" for f in findings)


def test_flags_sensitive_model_search_read_without_field_allowlist(tmp_path: Path) -> None:
    """Sensitive model search_read/read calls should name the allowed fields."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(self):
    self.env['res.users'].sudo().search_read([])
    self.env['payment.transaction'].read()
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()
    default_field_exports = [
        finding for finding in findings if finding.rule_id == "odoo-export-sensitive-model-default-fields"
    ]

    assert len(default_field_exports) == 2
    assert {finding.sink for finding in default_field_exports} == {"search_read", "read"}


def test_flags_security_model_default_field_exports(tmp_path: Path) -> None:
    """Security configuration reads should also require explicit field allowlists."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(self):
    self.env['ir.config_parameter'].sudo().search_read([])
    self.env['ir.rule'].read()
    self.env['res.groups'].search_read([])
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()
    default_field_exports = [
        finding for finding in findings if finding.rule_id == "odoo-export-sensitive-model-default-fields"
    ]

    assert len(default_field_exports) == 3


def test_non_sensitive_search_read_without_fields_is_ignored(tmp_path: Path) -> None:
    """Default fields on ordinary models should not create export noise."""
    py = tmp_path / "export.py"
    py.write_text(
        """
def export(self):
    return self.env['product.category'].search_read([])
""",
        encoding="utf-8",
    )

    findings = ExportScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-export-sensitive-model-default-fields" for f in findings)


def test_repository_scan_finds_exports(tmp_path: Path) -> None:
    """Repository scanner should include addon Python files and skip tests."""
    module = tmp_path / "module"
    tests = tmp_path / "tests"
    module.mkdir()
    tests.mkdir()
    (module / "export.py").write_text(
        "def export(writer, records):\n    writer.writerows([[record.name] for record in records])\n",
        encoding="utf-8",
    )
    (tests / "test_export.py").write_text(
        "def export(writer, records):\n    writer.writerows([[record.name] for record in records])\n",
        encoding="utf-8",
    )

    findings = scan_exports(tmp_path)

    assert len([f for f in findings if f.rule_id == "odoo-export-csv-formula-injection"]) == 1
