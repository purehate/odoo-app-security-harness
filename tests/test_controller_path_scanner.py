"""Tests for controller path traversal scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from odoo_security_harness.controller_path_scanner import (
    ControllerPathFinding,
    ControllerPathScanner,
    scan_controller_paths,
)


def test_detects_os_path_join_with_tainted_param(tmp_path: Path) -> None:
    source = """
from odoo import http
import os

class MyController(http.Controller):
    @http.route('/download', auth='public')
    def download(self):
        filename = request.params.get('file')
        path = os.path.join('/static', filename)
        return open(path, 'rb').read()
"""
    f = tmp_path / "controller.py"
    f.write_text(source, encoding="utf-8")
    findings = ControllerPathScanner(f).scan_file()
    assert any(f.rule_id == "odoo-controller-path-traversal" for f in findings)


def test_detects_pathlib_with_tainted_param(tmp_path: Path) -> None:
    source = """
from odoo import http
from pathlib import Path

class MyController(http.Controller):
    @http.route('/get', auth='user')
    def get_file(self):
        name = request.params['name']
        p = Path('/uploads') / name
        return p.read_bytes()
"""
    f = tmp_path / "controller.py"
    f.write_text(source, encoding="utf-8")
    findings = ControllerPathScanner(f).scan_file()
    assert any(f.rule_id == "odoo-controller-path-traversal" for f in findings)


def test_detects_send_file_with_tainted_path(tmp_path: Path) -> None:
    source = """
from odoo import http

class MyController(http.Controller):
    @http.route('/asset', auth='public')
    def asset(self):
        return send_file(request.params['path'])
"""
    f = tmp_path / "controller.py"
    f.write_text(source, encoding="utf-8")
    findings = ControllerPathScanner(f).scan_file()
    assert any(f.rule_id == "odoo-controller-unsafe-send-file" for f in findings)


def test_allows_os_path_join_with_basename_sanitization(tmp_path: Path) -> None:
    source = """
from odoo import http
import os

class MyController(http.Controller):
    @http.route('/download', auth='public')
    def download(self):
        filename = os.path.basename(request.params.get('file'))
        path = os.path.join('/static', filename)
        return open(path, 'rb').read()
"""
    f = tmp_path / "controller.py"
    f.write_text(source, encoding="utf-8")
    findings = ControllerPathScanner(f).scan_file()
    assert not any(f.rule_id == "odoo-controller-path-traversal" for f in findings)


def test_allows_safe_literal_path(tmp_path: Path) -> None:
    source = """
from odoo import http
import os

class MyController(http.Controller):
    @http.route('/download', auth='public')
    def download(self):
        path = os.path.join('/static', 'logo.png')
        return open(path, 'rb').read()
"""
    f = tmp_path / "controller.py"
    f.write_text(source, encoding="utf-8")
    findings = ControllerPathScanner(f).scan_file()
    assert not any(f.rule_id == "odoo-controller-path-traversal" for f in findings)


def test_public_route_gets_high_severity(tmp_path: Path) -> None:
    source = """
from odoo import http
import os

class MyController(http.Controller):
    @http.route('/download', auth='public')
    def download(self):
        path = os.path.join('/static', request.params['file'])
        return open(path, 'rb').read()
"""
    f = tmp_path / "controller.py"
    f.write_text(source, encoding="utf-8")
    findings = ControllerPathScanner(f).scan_file()
    finding = next(f for f in findings if f.rule_id == "odoo-controller-path-traversal")
    assert finding.severity == "high"


def test_user_route_gets_medium_severity(tmp_path: Path) -> None:
    source = """
from odoo import http
import os

class MyController(http.Controller):
    @http.route('/download', auth='user')
    def download(self):
        path = os.path.join('/static', request.params['file'])
        return open(path, 'rb').read()
"""
    f = tmp_path / "controller.py"
    f.write_text(source, encoding="utf-8")
    findings = ControllerPathScanner(f).scan_file()
    finding = next(f for f in findings if f.rule_id == "odoo-controller-path-traversal")
    assert finding.severity == "medium"
