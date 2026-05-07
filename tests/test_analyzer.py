"""Tests for Odoo deep pattern analyzer."""

from __future__ import annotations

from pathlib import Path

import pytest

from odoo_security_harness.analyzer import OdooDeepAnalyzer


class TestOdooDeepAnalyzer:
    """Test deep pattern analyzer."""

    def test_public_route_with_sudo(self) -> None:
        """Test detecting public route with sudo."""
        source = '''
from odoo import http
from odoo.http import request

class TestController(http.Controller):
    @http.route('/test/public', auth='public')
    def test_public(self):
        users = request.env['res.users'].sudo().search([])
        return {'count': len(users)}
'''
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        assert len(findings) >= 1
        finding = findings[0]
        assert "public" in finding.rule_id
        assert finding.severity == "high"

    def test_cr_execute_fstring(self) -> None:
        """Test detecting SQL injection with f-string."""
        source = '''
class TestModel(models.Model):
    def get_data(self, name):
        self.env.cr.execute(f"SELECT * FROM test WHERE name = '{name}'")
        return self.env.cr.fetchall()
'''
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        sql_findings = [f for f in findings if "sql" in f.rule_id]
        assert len(sql_findings) >= 1

    def test_safe_eval_user_input(self) -> None:
        """Test detecting safe_eval with user input."""
        source = '''
class TestController(http.Controller):
    @http.route('/test/eval', auth='public')
    def test_eval(self):
        expr = request.params['expression']
        result = safe_eval(expr)
        return result
'''
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        eval_findings = [f for f in findings if "safe-eval" in f.rule_id]
        assert len(eval_findings) >= 1
        assert eval_findings[0].severity == "critical"

    def test_mass_assignment(self) -> None:
        """Test detecting direct mass assignment."""
        source = '''
class TestController(http.Controller):
    @http.route('/test/create', auth='user')
    def test_create(self):
        return request.env['test.model'].create(request.params)
'''
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        ma_findings = [f for f in findings if "mass-assignment" in f.rule_id]
        assert len(ma_findings) >= 1

    def test_csrf_disabled_on_write(self) -> None:
        """Test detecting CSRF disabled on state-changing route."""
        source = '''
class TestController(http.Controller):
    @http.route('/test/action', auth='user', csrf=False)
    def test_action(self):
        return request.env['test.model'].write({'state': 'done'})
'''
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        csrf_findings = [f for f in findings if "csrf" in f.rule_id]
        assert len(csrf_findings) >= 1

    def test_with_user_admin(self) -> None:
        """Test detecting with_user to admin."""
        source = '''
class TestModel(models.Model):
    def do_admin_thing(self):
        return self.with_user(self.env.ref('base.user_admin')).search([])
'''
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        admin_findings = [f for f in findings if "admin" in f.rule_id.lower()]
        assert len(admin_findings) >= 1

    def test_no_false_positives(self) -> None:
        """Test that safe code doesn't trigger findings."""
        source = '''
class TestModel(models.Model):
    def safe_method(self):
        # Parameterized query
        self.env.cr.execute("SELECT * FROM test WHERE id = %s", (self.id,))
        return self.search([('state', '=', 'done')])
'''
        analyzer = OdooDeepAnalyzer("test.py")
        findings = analyzer.analyze(source)

        # Should not have SQL injection finding for parameterized query
        sql_findings = [f for f in findings if "sql" in f.rule_id]
        assert len(sql_findings) == 0
