"""Test fixtures and utilities for odoo-app-security-harness tests."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest


@pytest.fixture
def temp_repo() -> Generator[Path, None, None]:
    """Create a temporary Odoo-like repository structure."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)

        # Create module with manifest
        module_dir = repo / "test_module"
        module_dir.mkdir()
        manifest = module_dir / "__manifest__.py"
        manifest.write_text(
            json.dumps(
                {
                    "name": "Test Module",
                    "version": "1.0.0",
                    "depends": ["base", "web"],
                    "data": ["security/ir.model.access.csv", "views/templates.xml"],
                    "installable": True,
                    "application": False,
                }
            ),
            encoding="utf-8",
        )

        # Create controller with routes
        controllers_dir = module_dir / "controllers"
        controllers_dir.mkdir()
        controller = controllers_dir / "main.py"
        controller.write_text(
            """
from odoo import http
from odoo.http import request

class TestController(http.Controller):
    @http.route('/test/public', auth='public', type='http')
    def test_public(self, **kwargs):
        return request.render('test_module.template')

    @http.route('/test/user', auth='user', type='http', csrf=False)
    def test_user(self, **kwargs):
        data = request.params
        return http.Response(json.dumps(data))

    @http.route('/test/admin', auth='none', type='json')
    def test_admin(self, **kwargs):
        users = request.env['res.users'].sudo().search([])
        return {'count': len(users)}
""",
            encoding="utf-8",
        )

        # Create ACL file
        security_dir = module_dir / "security"
        security_dir.mkdir()
        acl = security_dir / "ir.model.access.csv"
        acl.write_text(
            "id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink\n"
            "access_test_model_user,test.model.user,model_test_model,base.group_user,1,0,0,0\n"
            "access_test_model_admin,test.model.admin,model_test_model,base.group_system,1,1,1,1\n",
            encoding="utf-8",
        )

        # Create QWeb template with t-raw
        views_dir = module_dir / "views"
        views_dir.mkdir()
        template = views_dir / "templates.xml"
        template.write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<odoo>
    <template id="template" name="Test Template">
        <div>
            <span t-raw="user_input"/>
        </div>
    </template>
</odoo>
""",
            encoding="utf-8",
        )

        # Create model with sudo and SQL
        models_dir = module_dir / "models"
        models_dir.mkdir()
        model = models_dir / "test_model.py"
        model.write_text(
            """
from odoo import models, fields, api

class TestModel(models.Model):
    _name = 'test.model'
    _description = 'Test Model'

    name = fields.Char()
    user_id = fields.Many2one('res.users')

    def get_all_records(self):
        self.env.cr.execute("SELECT * FROM test_model WHERE name = '%s'" % self.name)
        return self.env.cr.fetchall()

    def get_user_records(self):
        return self.sudo().search([('user_id', '=', self.env.user.id)])
""",
            encoding="utf-8",
        )

        yield repo


@pytest.fixture
def sample_manifest() -> dict:
    """Return a sample manifest dictionary."""
    return {
        "name": "Sample Module",
        "version": "16.0.1.0.0",
        "depends": ["base"],
        "data": ["security/ir.model.access.csv"],
        "installable": True,
        "application": False,
        "license": "LGPL-3",
    }


@pytest.fixture
def sample_findings() -> dict:
    """Return sample findings document."""
    return {
        "version": "1.0",
        "generated_at": "2024-01-01T00:00:00Z",
        "target": {"repo": "/test/repo"},
        "findings": [
            {
                "id": "F-001",
                "title": "SQL Injection in TestController",
                "severity": "critical",
                "triage": "ACCEPT",
                "file": "test_module/controllers/main.py",
                "line": 15,
                "module": "test_module",
                "description": "User input is directly interpolated into SQL query",
                "fingerprint": "sha256:abc123",
                "rule_id": "sql-injection",
            },
            {
                "id": "F-002",
                "title": "Missing CSRF Protection",
                "severity": "high",
                "triage": "ACCEPT",
                "file": "test_module/controllers/main.py",
                "line": 8,
                "module": "test_module",
                "description": "Controller has csrf=False without HMAC",
                "fingerprint": "sha256:def456",
                "rule_id": "missing-csrf",
            },
            {
                "id": "F-003",
                "title": "Public Route with sudo",
                "severity": "high",
                "triage": "ACCEPT",
                "file": "test_module/controllers/main.py",
                "line": 12,
                "module": "test_module",
                "description": "Public route uses sudo to access all users",
                "fingerprint": "sha256:ghi789",
                "rule_id": "public-sudo",
            },
        ],
    }


@pytest.fixture
def empty_repo() -> Generator[Path, None, None]:
    """Create an empty temporary directory."""
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)
