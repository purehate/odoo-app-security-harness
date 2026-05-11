"""Tests for Odoo deep pattern analyzer."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.analyzer import OdooDeepAnalyzer, analyze_directory


class TestOdooDeepAnalyzer:
    """Test deep pattern analyzer."""

    def test_public_route_with_sudo(self) -> None:
        """Test detecting public route with sudo."""
        source = """
from odoo import http
from odoo.http import request

class TestController(http.Controller):
    @http.route('/test/public', auth='public')
    def test_public(self):
        users = request.env['res.users'].sudo().search([])
        return {'count': len(users)}
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert len(findings) >= 1
        finding = next(f for f in findings if "public" in f.rule_id)
        assert "public" in finding.rule_id
        assert finding.severity == "high"

    def test_constant_backed_public_route_with_sudo(self) -> None:
        """Constant-backed route auth should not hide public sudo searches."""
        source = """
from odoo import http
from odoo.http import request

PUBLIC_ROUTE = '/test/public'
PUBLIC_AUTH = 'public'

class TestController(http.Controller):
    @http.route(PUBLIC_ROUTE, auth=PUBLIC_AUTH)
    def test_public(self):
        users = request.env['res.users'].sudo().search([])
        return {'count': len(users)}
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)
        rule_ids = {finding.rule_id for finding in findings}

        assert "odoo-deep-public-sudo" in rule_ids
        assert "odoo-deep-public-sudo-search" in rule_ids

    def test_class_constant_backed_public_route_with_sudo(self) -> None:
        """Class-scoped route auth constants should not hide public sudo searches."""
        source = """
from odoo import http
from odoo.http import request

class TestController(http.Controller):
    BASE_AUTH = 'public'
    PUBLIC_AUTH = BASE_AUTH
    BASE_ROUTE = '/test/public'
    PUBLIC_ROUTE = BASE_ROUTE

    @http.route(PUBLIC_ROUTE, auth=PUBLIC_AUTH)
    def test_public(self):
        users = request.env['res.users'].sudo().search([])
        return {'count': len(users)}
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)
        rule_ids = {finding.rule_id for finding in findings}

        assert "odoo-deep-public-sudo" in rule_ids
        assert "odoo-deep-public-sudo-search" in rule_ids

    def test_static_route_kwargs_public_route_with_sudo(self) -> None:
        """Static **kwargs should not hide public route posture."""
        source = """
from odoo import http
from odoo.http import request

PUBLIC_ROUTE = '/test/public'
ROUTE_OPTIONS = {'route': PUBLIC_ROUTE, 'auth': 'public'}

class TestController(http.Controller):
    @http.route(**ROUTE_OPTIONS)
    def test_public(self):
        users = request.env['res.users'].sudo().search([])
        return {'count': len(users)}
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)
        rule_ids = {finding.rule_id for finding in findings}

        assert "odoo-deep-public-sudo" in rule_ids
        assert "odoo-deep-public-sudo-search" in rule_ids

    def test_nested_static_route_kwargs_auth_none_request_env(self) -> None:
        """Nested static **kwargs should preserve auth='none' route checks."""
        source = """
from odoo import http
from odoo.http import request

BASE_ROUTE = {'route': '/bootstrap'}
ROUTE_OPTIONS = {**BASE_ROUTE, 'auth': 'none', 'type': 'json'}

class TestController(http.Controller):
    @http.route(**ROUTE_OPTIONS)
    def bootstrap(self):
        return request.env['ir.config_parameter'].sudo().get_param('web.base.url')
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-auth-none-env" for f in findings)

    def test_static_route_kwargs_csrf_false_on_write(self) -> None:
        """Static **kwargs should not hide csrf=False on state-changing routes."""
        source = """
from odoo import http
from odoo.http import request

ROUTE_OPTIONS = {'route': '/test/action', 'auth': 'user', 'csrf': False, 'methods': ['POST']}

class TestController(http.Controller):
    @http.route(**ROUTE_OPTIONS)
    def test_action(self):
        return request.env['test.model'].write({'state': 'done'})
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-csrf-write" for f in findings)

    def test_aliased_http_route_with_sudo(self) -> None:
        """Aliased Odoo http imports should still expose public route context."""
        source = """
from odoo import http as odoo_http
from odoo.http import request

class TestController(odoo_http.Controller):
    @odoo_http.route('/test/public', auth='public')
    def test_public(self):
        return request.env['res.users'].sudo().search([])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)
        rule_ids = {finding.rule_id for finding in findings}

        assert "odoo-deep-public-sudo" in rule_ids
        assert "odoo-deep-public-sudo-search" in rule_ids

    def test_aliased_imported_route_with_sudo(self) -> None:
        """Aliased imported route decorators should still expose public route context."""
        source = """
from odoo import http
from odoo.http import request, route as odoo_route

class TestController(http.Controller):
    @odoo_route('/test/public', auth='public')
    def test_public(self):
        return request.env['res.users'].sudo().search([])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)
        rule_ids = {finding.rule_id for finding in findings}

        assert "odoo-deep-public-sudo" in rule_ids
        assert "odoo-deep-public-sudo-search" in rule_ids

    def test_local_route_decorator_with_sudo_is_not_public_route(self) -> None:
        """Local route decorators should not create Odoo public route context."""
        source = """
from odoo import http
from odoo.http import request

def route(*args, **kwargs):
    def decorate(func):
        return func
    return decorate

class TestController(http.Controller):
    @route('/test/public', auth='public')
    def test_public(self):
        return request.env['res.users'].sudo().search([])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)
        rule_ids = {finding.rule_id for finding in findings}

        assert "odoo-deep-public-sudo" not in rule_ids
        assert "odoo-deep-public-sudo-search" not in rule_ids

    def test_constant_backed_auth_none_request_env(self) -> None:
        """Constant-backed auth='none' should still flag request.env usage."""
        source = """
from odoo import http
from odoo.http import request

BOOTSTRAP_ROUTE = '/bootstrap'
BOOTSTRAP_AUTH = 'none'

class TestController(http.Controller):
    @http.route(route=BOOTSTRAP_ROUTE, auth=BOOTSTRAP_AUTH, type='json')
    def bootstrap(self):
        return request.env['ir.config_parameter'].sudo().get_param('web.base.url')
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-auth-none-env" for f in findings)

    def test_constant_backed_csrf_false_on_write(self) -> None:
        """Constant-backed csrf=False should still flag state-changing routes."""
        source = """
from odoo import http
from odoo.http import request

ACTION_ROUTE = '/test/action'
ACTION_CSRF = False
ACTION_METHODS = ['POST']

class TestController(http.Controller):
    @http.route(ACTION_ROUTE, auth='user', csrf=ACTION_CSRF, methods=ACTION_METHODS)
    def test_action(self):
        return request.env['test.model'].write({'state': 'done'})
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-csrf-write" for f in findings)

    def test_request_alias_public_route_with_sudo_and_mass_assignment(self) -> None:
        """Aliased Odoo request imports should keep taint and env detection."""
        source = """
from odoo import http
from odoo.http import request as req

class TestController(http.Controller):
    @http.route('/test/public', auth='public', csrf=False)
    def test_public(self):
        payload = req.get_http_params()
        users = req.env['res.users'].sudo().search([])
        req.env['res.partner'].sudo().write(payload)
        return {'count': len(users)}
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)
        rule_ids = {finding.rule_id for finding in findings}

        assert "odoo-deep-public-sudo" in rule_ids
        assert "odoo-deep-public-sudo-search" in rule_ids
        assert "odoo-deep-mass-assignment" in rule_ids
        assert "odoo-deep-request-sudo-write" in rule_ids

    def test_imported_odoo_http_alias_keeps_route_and_request_taint(self) -> None:
        """import odoo.http as aliases should preserve route and request detection."""
        source = """
import odoo.http as odoo_http

class TestController(odoo_http.Controller):
    @odoo_http.route('/test/public', auth='public', csrf=False)
    def test_public(self):
        payload = odoo_http.request.get_http_params()
        odoo_http.request.env['res.partner'].sudo().write(payload)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)
        rule_ids = {finding.rule_id for finding in findings}

        assert "odoo-deep-public-sudo" in rule_ids
        assert "odoo-deep-mass-assignment" in rule_ids
        assert "odoo-deep-request-sudo-write" in rule_ids

    def test_imported_odoo_alias_keeps_route_and_request_taint(self) -> None:
        """import odoo as aliases should preserve od.http route and request detection."""
        source = """
import odoo as od

class TestController(od.http.Controller):
    @od.http.route('/test/public', auth='public')
    def test_public(self):
        payload = od.http.request.params
        return od.http.request.env['res.partner'].create(payload)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)
        rule_ids = {finding.rule_id for finding in findings}

        assert "odoo-deep-mass-assignment" in rule_ids
        assert "odoo-deep-public-write-route" in rule_ids

    def test_request_params_to_superuser_write(self) -> None:
        """Request payloads reaching admin-root with_user writes are privileged mutations."""
        source = """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class TestController(http.Controller):
    @http.route('/test/public', auth='public', csrf=False)
    def test_public(self):
        payload = request.get_http_params()
        request.env['res.partner'].with_user(user=SUPERUSER_ID).write(payload)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)
        rule_ids = {finding.rule_id for finding in findings}

        assert "odoo-deep-public-sudo" in rule_ids
        assert "odoo-deep-mass-assignment" in rule_ids
        assert "odoo-deep-request-sudo-write" in rule_ids

    def test_httprequest_form_get_taints_privileged_write(self) -> None:
        """Werkzeug request form helpers should be treated as request-controlled."""
        source = """
from odoo import http
from odoo.http import request

class TestController(http.Controller):
    @http.route('/test/public', auth='public', csrf=False)
    def test_public(self):
        payload = request.httprequest.form.get('payload')
        return request.env['res.partner'].sudo().write(payload)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)
        rule_ids = {finding.rule_id for finding in findings}

        assert "odoo-deep-mass-assignment" in rule_ids
        assert "odoo-deep-request-sudo-write" in rule_ids

    def test_httprequest_args_subscript_taints_safe_eval(self) -> None:
        """Werkzeug query-string access should taint dynamic evaluation."""
        source = """
from odoo import http
from odoo.http import request

class TestController(http.Controller):
    @http.route('/test/eval', auth='public')
    def test_eval(self):
        return safe_eval(request.httprequest.args['expr'])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-safe-eval-user-input" for f in findings)

    def test_request_params_get_taints_raw_sql(self) -> None:
        """Method calls on tainted request containers should remain tainted."""
        source = """
from odoo import http
from odoo.http import request

class TestController(http.Controller):
    @http.route('/lookup', auth='user')
    def lookup(self):
        table = request.params.get('table')
        request.env.cr.execute('SELECT * FROM ' + table)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)
        rule_ids = {finding.rule_id for finding in findings}

        assert "odoo-deep-sql-concat" in rule_ids
        assert "odoo-deep-request-to-sql" in rule_ids

    def test_route_string_parameter_taints_safe_eval(self) -> None:
        """Named Odoo route path parameters should be treated as request-controlled."""
        source = """
from odoo import http

class TestController(http.Controller):
    @http.route('/public/eval/<string:expression>', auth='public')
    def test_eval(self, expression):
        return safe_eval(expression)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-safe-eval-user-input" for f in findings)

    def test_route_path_parameter_taints_raw_sql(self) -> None:
        """Non-ID route path parameters should be tainted in SQL flows."""
        source = """
from odoo import http
from odoo.http import request

class TestController(http.Controller):
    @http.route('/lookup/<path:table_name>', auth='user')
    def lookup(self, table_name):
        request.env.cr.execute('SELECT * FROM ' + table_name)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)
        rule_ids = {finding.rule_id for finding in findings}

        assert "odoo-deep-sql-concat" in rule_ids
        assert "odoo-deep-request-to-sql" in rule_ids

    def test_cr_execute_fstring(self) -> None:
        """Test detecting SQL injection with f-string."""
        source = """
class TestModel(models.Model):
    def get_data(self, name):
        self.env.cr.execute(f"SELECT * FROM test WHERE name = '{name}'")
        return self.env.cr.fetchall()
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        sql_findings = [f for f in findings if "sql" in f.rule_id]
        assert len(sql_findings) >= 1

    def test_safe_eval_user_input(self) -> None:
        """Test detecting safe_eval with user input."""
        source = """
class TestController(http.Controller):
    @http.route('/test/eval', auth='public')
    def test_eval(self):
        expr = request.params['expression']
        result = safe_eval(expr)
        return result
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        eval_findings = [f for f in findings if "safe-eval" in f.rule_id]
        assert len(eval_findings) >= 1
        assert eval_findings[0].severity == "critical"

    def test_mass_assignment(self) -> None:
        """Test detecting direct mass assignment."""
        source = """
class TestController(http.Controller):
    @http.route('/test/create', auth='user')
    def test_create(self):
        return request.env['test.model'].create(request.params)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        ma_findings = [f for f in findings if "mass-assignment" in f.rule_id]
        assert len(ma_findings) >= 1

    def test_get_json_data_mass_assignment(self) -> None:
        """Test detecting modern JSON payload mass assignment."""
        source = """
class TestController(http.Controller):
    @http.route('/test/create', auth='user', type='json')
    def test_create(self):
        payload = request.get_json_data()
        return request.env['test.model'].create(payload)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-mass-assignment" for f in findings)

    def test_annotated_get_json_data_mass_assignment(self) -> None:
        """Annotated request payload aliases should stay tainted."""
        source = """
class TestController(http.Controller):
    @http.route('/test/create', auth='user', type='json')
    def test_create(self):
        payload: dict = request.get_json_data()
        return request.env['test.model'].create(payload)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-mass-assignment" for f in findings)

    def test_get_http_params_mass_assignment(self) -> None:
        """Test detecting modern HTTP parameter helper mass assignment."""
        source = """
class TestController(http.Controller):
    @http.route('/test/create', auth='user')
    def test_create(self):
        payload = request.get_http_params()
        return request.env['test.model'].write(payload)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-mass-assignment" for f in findings)

    def test_subscript_from_tainted_params_taints_safe_eval(self) -> None:
        """Aliases of request containers should taint values read by subscript."""
        source = """
class TestController(http.Controller):
    @http.route('/test/eval', auth='public')
    def test_eval(self):
        params = request.params
        expr = params['expression']
        return safe_eval(expr)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-safe-eval-user-input" for f in findings)

    def test_subscript_from_json_payload_taints_mass_assignment(self) -> None:
        """Subscript reads from tainted JSON payload aliases should stay tainted."""
        source = """
class TestController(http.Controller):
    @http.route('/test/create', auth='user', type='json')
    def test_create(self):
        payload = request.get_json_data()
        values = payload['values']
        return request.env['test.model'].create(values)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-mass-assignment" for f in findings)

    def test_nested_function_does_not_clear_outer_taint(self) -> None:
        """Nested helpers should not clear taint tracked for the outer controller."""
        source = """
class TestController(http.Controller):
    @http.route('/test/create', auth='user', type='json')
    def test_create(self):
        payload = request.get_json_data()
        def normalize(value):
            return value
        normalize(payload)
        return request.env['test.model'].create(payload)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-mass-assignment" for f in findings)

    def test_named_expression_mass_assignment(self) -> None:
        """Test detecting walrus-assigned request payload mass assignment."""
        source = """
class TestController(http.Controller):
    @http.route('/test/create', auth='user', type='json')
    def test_create(self):
        if payload := request.get_json_data():
            return request.env['test.model'].create(payload)
        return False
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-mass-assignment" for f in findings)

    def test_boolop_mass_assignment(self) -> None:
        """Test detecting request payloads through boolean fallback aliases."""
        source = """
class TestController(http.Controller):
    @http.route('/test/create', auth='user', type='json')
    def test_create(self):
        payload = request.get_json_data() or {'name': 'fallback'}
        return request.env['test.model'].create(payload)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-mass-assignment" for f in findings)

    def test_reassigned_payload_is_not_stale_mass_assignment(self) -> None:
        """Request-derived aliases should clear when rebound before ORM writes."""
        source = """
class TestController(http.Controller):
    @http.route('/test/create', auth='user', type='json')
    def test_create(self):
        payload = request.get_json_data()
        payload = {'name': 'safe'}
        return request.env['test.model'].create(payload)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert not any(f.rule_id == "odoo-deep-mass-assignment" for f in findings)

    def test_annotated_reassigned_payload_is_not_stale_mass_assignment(self) -> None:
        """Annotated request aliases should clear when rebound to safe data."""
        source = """
class TestController(http.Controller):
    @http.route('/test/create', auth='user', type='json')
    def test_create(self):
        payload: dict = request.get_json_data()
        payload: dict = {'name': 'safe'}
        return request.env['test.model'].create(payload)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert not any(f.rule_id == "odoo-deep-mass-assignment" for f in findings)

    def test_csrf_disabled_on_write(self) -> None:
        """Test detecting CSRF disabled on state-changing route."""
        source = """
class TestController(http.Controller):
    @http.route('/test/action', auth='user', csrf=False)
    def test_action(self):
        return request.env['test.model'].write({'state': 'done'})
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        csrf_findings = [f for f in findings if "csrf" in f.rule_id]
        assert len(csrf_findings) >= 1

    def test_with_user_admin(self) -> None:
        """Test detecting with_user to admin."""
        source = """
class TestModel(models.Model):
    def do_admin_thing(self):
        return self.with_user(self.env.ref('base.user_admin')).search([])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        admin_findings = [f for f in findings if "admin" in f.rule_id.lower()]
        assert len(admin_findings) >= 1

    def test_with_user_superuser_keyword(self) -> None:
        """Test detecting keyword with_user to SUPERUSER_ID."""
        source = """
from odoo import SUPERUSER_ID

class TestModel(models.Model):
    def do_admin_thing(self):
        return self.with_user(user=SUPERUSER_ID).search([])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        admin_findings = [f for f in findings if f.rule_id == "odoo-deep-with-user-admin"]
        assert len(admin_findings) >= 1

    def test_class_constant_backed_with_user_superuser_keyword(self) -> None:
        """Class-scoped superuser constants should preserve admin-root detection."""
        source = """
class TestModel(models.Model):
    ROOT_BASE = 1
    ROOT_UID = ROOT_BASE

    def do_admin_thing(self):
        return self.with_user(user=ROOT_UID).search([])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-with-user-admin" for f in findings)

    def test_with_user_regular_user_is_not_admin(self) -> None:
        """Regular user context switches should not be labeled admin/root."""
        source = """
class TestModel(models.Model):
    def as_current_user(self):
        return self.with_user(self.env.user).search([])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert not any(f.rule_id == "odoo-deep-with-user-admin" for f in findings)

    def test_no_false_positives(self) -> None:
        """Test that safe code doesn't trigger findings."""
        source = """
class TestModel(models.Model):
    def safe_method(self):
        # Parameterized query
        self.env.cr.execute("SELECT * FROM test WHERE id = %s", (self.id,))
        return self.search([('state', '=', 'done')])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        # Should not have SQL injection finding for parameterized query
        sql_findings = [f for f in findings if "sql" in f.rule_id]
        assert len(sql_findings) == 0

    def test_sql_query_variable_built_unsafely(self) -> None:
        """Test detecting SQL injection when an unsafe query is assigned first."""
        source = """
class TestModel(models.Model):
    def get_data(self, table):
        query = "SELECT * FROM {}".format(table)
        self.env.cr.execute(query)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-sql-built-query-var" for f in findings)

    def test_reassigned_sql_query_variable_is_not_stale(self) -> None:
        """Unsafe SQL query aliases should clear when rebound to a static query."""
        source = """
class TestModel(models.Model):
    def get_data(self, table):
        query = "SELECT * FROM {}".format(table)
        query = "SELECT * FROM res_partner WHERE active = true"
        self.env.cr.execute(query)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert not any(f.rule_id == "odoo-deep-sql-built-query-var" for f in findings)

    def test_empty_domain_sudo_search(self) -> None:
        """Test detecting sudo search over all records."""
        source = """
class TestModel(models.Model):
    def get_everything(self):
        return self.env['sale.order'].sudo().search([])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-empty-search-sudo" for f in findings)

    def test_empty_domain_sudo_search_count(self) -> None:
        """Sudo search_count([]) still exposes full-table metadata."""
        source = """
class TestModel(models.Model):
    def count_everything(self):
        return self.env['sale.order'].sudo().search_count([])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-empty-search-sudo" for f in findings)

    def test_empty_domain_sudo_read_group(self) -> None:
        """Sudo read_group([]) aggregates across records outside caller visibility."""
        source = """
class TestModel(models.Model):
    def count_by_company(self):
        return self.env['sale.order'].sudo().read_group([], ['id:count'], ['company_id'])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-empty-search-sudo" for f in findings)

    def test_empty_domain_superuser_search(self) -> None:
        """Test detecting SUPERUSER_ID with_user search over all records."""
        source = """
from odoo import SUPERUSER_ID

class TestModel(models.Model):
    def get_everything(self):
        return self.env['sale.order'].with_user(SUPERUSER_ID).search([])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-empty-search-sudo" for f in findings)

    def test_class_constant_empty_domain_superuser_search(self) -> None:
        """Class-scoped superuser and domain constants should expose unbounded reads."""
        source = """
class TestModel(models.Model):
    ROOT_BASE = 1
    ROOT_UID = ROOT_BASE
    EMPTY_BASE = []
    EMPTY_DOMAIN = EMPTY_BASE

    def get_everything(self):
        return self.env['sale.order'].with_user(ROOT_UID).search(EMPTY_DOMAIN)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-empty-search-sudo" for f in findings)

    def test_public_route_with_superuser_read(self) -> None:
        """Public routes using admin-root with_user should count as privileged reads."""
        source = """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class TestController(http.Controller):
    @http.route('/orders', auth='public')
    def orders(self):
        return request.env['sale.order'].with_user(user=SUPERUSER_ID).search([])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)
        rule_ids = {finding.rule_id for finding in findings}

        assert "odoo-deep-public-sudo" in rule_ids
        assert "odoo-deep-public-sudo-search" in rule_ids

    def test_public_route_with_sudo_search_count(self) -> None:
        """Public sudo record counts should be treated as privileged search exposure."""
        source = """
from odoo import http
from odoo.http import request

class TestController(http.Controller):
    @http.route('/orders/count', auth='public')
    def order_count(self):
        return request.env['sale.order'].sudo().search_count([])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)
        rule_ids = {finding.rule_id for finding in findings}

        assert "odoo-deep-public-sudo" in rule_ids
        assert "odoo-deep-empty-search-sudo" in rule_ids
        assert "odoo-deep-public-sudo-search" in rule_ids

    def test_public_route_with_sudo_read_group(self) -> None:
        """Public sudo aggregates should be treated as privileged search exposure."""
        source = """
from odoo import http
from odoo.http import request

class TestController(http.Controller):
    @http.route('/orders/by-company', auth='public')
    def order_count_by_company(self):
        return request.env['sale.order'].sudo().read_group([], ['id:count'], ['company_id'])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)
        rule_ids = {finding.rule_id for finding in findings}

        assert "odoo-deep-public-sudo" in rule_ids
        assert "odoo-deep-empty-search-sudo" in rule_ids
        assert "odoo-deep-public-sudo-search" in rule_ids

    def test_public_route_create_from_kwargs(self) -> None:
        """Test detecting public controller kwargs flowing to ORM create."""
        source = """
class TestController(http.Controller):
    @http.route('/lead', auth='public', csrf=False)
    def lead(self, **kwargs):
        return request.env['crm.lead'].sudo().create(kwargs)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        rule_ids = {f.rule_id for f in findings}
        assert "odoo-deep-mass-assignment" in rule_ids
        assert "odoo-deep-public-write-route" in rule_ids
        assert "odoo-deep-request-sudo-write" not in rule_ids

    def test_tainted_search_domain(self) -> None:
        """Test detecting user-controlled domains passed into ORM search."""
        source = """
class TestController(http.Controller):
    @http.route('/search', auth='user')
    def search(self):
        domain = request.jsonrequest
        return request.env['res.partner'].search(domain).read(['name'])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-tainted-search-domain" for f in findings)

    def test_annotated_tainted_search_domain(self) -> None:
        """Annotated request domains should be detected in ORM searches."""
        source = """
class TestController(http.Controller):
    @http.route('/search', auth='user')
    def search(self):
        domain: list = request.jsonrequest
        return request.env['res.partner'].search(domain).read(['name'])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-tainted-search-domain" for f in findings)

    def test_auth_none_request_env(self) -> None:
        """Test detecting auth='none' routes that use request.env."""
        source = """
class TestController(http.Controller):
    @http.route('/bootstrap', auth='none', type='json')
    def bootstrap(self):
        return request.env['ir.config_parameter'].sudo().get_param('web.base.url')
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-auth-none-env" for f in findings)

    def test_markup_user_input(self) -> None:
        """Test detecting Markup applied to request-controlled data."""
        source = """
class TestController(http.Controller):
    @http.route('/html', auth='public')
    def html(self):
        body = request.params['body']
        return Markup(body)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-markup-user-input" for f in findings)

    def test_html_field_sanitize_false(self) -> None:
        """Test detecting unsafe HTML field configuration."""
        source = """
class TestModel(models.Model):
    _name = 'test.model'
    body = fields.Html(sanitize=False)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-html-sanitize-false" for f in findings)

    def test_direct_html_field_constructor_sanitize_false(self) -> None:
        """Directly imported HTML field constructors should be recognized."""
        source = """
from odoo.fields import Html

class TestModel(models.Model):
    _name = 'test.model'
    body = Html(sanitize=False)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-html-sanitize-false" for f in findings)

    def test_aliased_odoo_fields_module_html_sanitize_false(self) -> None:
        """Aliased Odoo fields modules should expose unsafe HTML fields."""
        source = """
from odoo import fields as odoo_fields

class TestModel(models.Model):
    _name = 'test.model'
    body = odoo_fields.Html(sanitize=False)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-html-sanitize-false" for f in findings)

    def test_imported_odoo_fields_module_html_sanitize_false(self) -> None:
        """Direct odoo.fields imports should expose unsafe HTML fields."""
        source = """
import odoo.fields as odoo_fields

class TestModel(models.Model):
    _name = 'test.model'
    body = odoo_fields.Html(sanitize=False)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-html-sanitize-false" for f in findings)

    def test_imported_odoo_module_fields_html_sanitize_false(self) -> None:
        """Direct odoo module imports should expose unsafe HTML fields."""
        source = """
import odoo as od

class TestModel(od.models.Model):
    _name = 'test.model'
    body = od.fields.Html(sanitize=False)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-html-sanitize-false" for f in findings)

    def test_class_constant_html_field_sanitize_false(self) -> None:
        """Class-scoped sanitize constants should expose raw HTML fields."""
        source = """
class TestModel(models.Model):
    _name = 'test.model'
    SANITIZE_BASE = False
    SANITIZE = SANITIZE_BASE
    body = fields.Html(sanitize=SANITIZE)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-html-sanitize-false" for f in findings)

    def test_html_sanitize_strict_false(self) -> None:
        """Non-strict HTML sanitization should remain visible for review."""
        source = """
from odoo import tools

class TestModel(models.Model):
    _name = 'test.model'

    def clean(self, body):
        return tools.html_sanitize(body, strict=False)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-html-sanitize-strict-false" for f in findings)

    def test_imported_html_sanitize_strict_false(self) -> None:
        """Directly imported html_sanitize calls should be recognized."""
        source = """
from odoo.tools import html_sanitize

class TestModel(models.Model):
    _name = 'test.model'

    def clean(self, body):
        return html_sanitize(body, strict=False)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-html-sanitize-strict-false" for f in findings)

    def test_html_sanitize_disabled_sanitizer_options(self) -> None:
        """Disabled html_sanitize tag/attribute filtering should be review-visible."""
        source = """
from odoo import tools

class TestModel(models.Model):
    _name = 'test.model'

    def clean(self, body):
        safe_tags = tools.html_sanitize(body, sanitize_tags=False)
        safe_attrs = tools.html_sanitize(body, sanitize_attributes=False)
        return safe_tags + safe_attrs
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        relaxed = [f for f in findings if f.rule_id == "odoo-deep-html-sanitize-relaxed-option"]
        assert len(relaxed) == 2
        assert all(f.severity == "high" for f in relaxed)

    def test_route_id_sudo_browse_without_access_check(self) -> None:
        """Test detecting route-controlled IDs loaded through sudo().browse()."""
        source = """
class PortalController(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='user', website=True)
    def portal_order(self, order_id):
        order = request.env['sale.order'].sudo().browse(order_id)
        return request.render('sale.portal_order_page', {'order': order})
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)
        rule_ids = {f.rule_id for f in findings}

        assert "odoo-deep-route-id-sudo-browse" in rule_ids
        assert "odoo-deep-portal-idor-sudo-browse" in rule_ids

    def test_route_id_superuser_browse_without_access_check(self) -> None:
        """Route-controlled IDs loaded through admin-root with_user should be reported."""
        source = """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class PortalController(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='user', website=True)
    def portal_order(self, order_id):
        order = request.env['sale.order'].with_user(user=SUPERUSER_ID).browse(order_id)
        return request.render('sale.portal_order_page', {'order': order})
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)
        rule_ids = {f.rule_id for f in findings}

        assert "odoo-deep-route-id-sudo-browse" in rule_ids
        assert "odoo-deep-portal-idor-sudo-browse" in rule_ids

    def test_route_id_sudo_browse_with_document_check_is_not_idor(self) -> None:
        """Recognized portal access helpers should suppress the post-function IDOR warning."""
        source = """
class PortalController(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='user', website=True)
    def portal_order(self, order_id, access_token=None):
        order = self._document_check_access('sale.order', order_id, access_token=access_token)
        return request.render('sale.portal_order_page', {'order': order})
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert not any(f.rule_id == "odoo-deep-portal-idor-sudo-browse" for f in findings)

    def test_attachment_sudo_access_in_controller(self) -> None:
        """Test detecting sudo reads from ir.attachment in controllers."""
        source = """
class PortalController(http.Controller):
    @http.route('/my/attachment/<int:attachment_id>', auth='user')
    def attachment(self, attachment_id):
        attachment = request.env['ir.attachment'].sudo().browse(attachment_id)
        return request.make_response(attachment.raw)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-attachment-sudo-access" for f in findings)

    def test_attachment_superuser_access_in_controller(self) -> None:
        """Admin-root with_user attachment reads should be treated like sudo reads."""
        source = """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class PortalController(http.Controller):
    @http.route('/my/attachment/<int:attachment_id>', auth='user')
    def attachment(self, attachment_id):
        attachment = request.env['ir.attachment'].with_user(user=SUPERUSER_ID).browse(attachment_id)
        return request.make_response(attachment.raw)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-attachment-sudo-access" for f in findings)

    def test_attachment_sudo_search_count_in_controller(self) -> None:
        """Sudo attachment counts in controllers still expose attachment metadata."""
        source = """
class PortalController(http.Controller):
    @http.route('/my/attachments/count', auth='user')
    def attachment_count(self, order_id):
        return request.env['ir.attachment'].sudo().search_count([('res_id', '=', order_id)])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-attachment-sudo-access" for f in findings)

    def test_attachment_sudo_read_group_in_controller(self) -> None:
        """Sudo attachment aggregates in controllers still expose attachment metadata."""
        source = """
class PortalController(http.Controller):
    @http.route('/my/attachments/by-model', auth='user')
    def attachment_count_by_model(self, order_id):
        return request.env['ir.attachment'].sudo().read_group([('res_id', '=', order_id)], ['id:count'], ['res_model'])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-attachment-sudo-access" for f in findings)

    def test_class_constant_attachment_model_sudo_in_controller(self) -> None:
        """Class-scoped env model constants should not hide sudo attachment reads."""
        source = """
class PortalController(http.Controller):
    ATTACHMENT_BASE = 'ir.attachment'
    ATTACHMENT_MODEL = ATTACHMENT_BASE

    @http.route('/my/attachments', auth='user')
    def attachments(self, order_id):
        return request.env[ATTACHMENT_MODEL].sudo().search([('res_id', '=', order_id)])
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-attachment-sudo-access" for f in findings)

    def test_field_compute_sudo(self) -> None:
        """Test detecting computed fields that run as sudo."""
        source = """
class TestModel(models.Model):
    _name = 'test.model'
    secret_total = fields.Monetary(compute='_compute_secret_total', compute_sudo=True)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-field-compute-sudo" for f in findings)

    def test_direct_field_constructor_compute_sudo(self) -> None:
        """Directly imported field constructors should still flag compute_sudo."""
        source = """
from odoo.fields import Monetary

class TestModel(models.Model):
    _name = 'test.model'
    secret_total = Monetary(compute='_compute_secret_total', compute_sudo=True)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-field-compute-sudo" for f in findings)

    def test_class_constant_field_compute_sudo(self) -> None:
        """Class-scoped compute_sudo constants should expose sudo projections."""
        source = """
class TestModel(models.Model):
    _name = 'test.model'
    COMPUTE_BASE = True
    COMPUTE_SUDO = COMPUTE_BASE
    secret_total = fields.Monetary(compute='_compute_secret_total', compute_sudo=COMPUTE_SUDO)
"""
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert any(f.rule_id == "odoo-deep-field-compute-sudo" for f in findings)


def test_analyze_directory_does_not_skip_modules_with_test_in_name(tmp_path: Path) -> None:
    """Module names like test_module should not disable Python analysis."""
    controller = tmp_path / "test_module" / "controllers" / "main.py"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """
from odoo import http
from odoo.http import request

class TestController(http.Controller):
    @http.route('/public/orders', auth='public')
    def orders(self, **kwargs):
        return request.env['sale.order'].sudo().search([]).write(kwargs)
""",
        encoding="utf-8",
    )

    findings = analyze_directory(tmp_path)

    assert any(f.rule_id == "odoo-deep-public-write-route" for f in findings)


def test_analyze_directory_skips_tests_directory(tmp_path: Path) -> None:
    """Test fixtures under tests/ should not become scanner findings."""
    test_file = tmp_path / "tests" / "test_controller.py"
    test_file.parent.mkdir()
    test_file.write_text(
        """
from odoo import http

class TestController(http.Controller):
    @http.route('/fixture', auth='public')
    def fixture(self):
        return self.env['sale.order'].sudo().search([])
""",
        encoding="utf-8",
    )

    assert analyze_directory(tmp_path) == []
