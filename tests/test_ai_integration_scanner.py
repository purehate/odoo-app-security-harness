"""Tests for AI/LLM integration security scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.ai_integration_scanner import scan_ai_integrations


def test_detects_hardcoded_openai_key(tmp_path: Path) -> None:
    """Hardcoded OpenAI-style API keys should be flagged."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "ai.py").write_text(
        '''
from odoo import models

class AiHelper(models.Model):
    _name = "x.ai.helper"

    def ask(self, question):
        api_key = "sk-abcdefghijklmnopqrstuvwxyz1234567890abcd"
        return api_key
''',
        encoding="utf-8",
    )

    findings = scan_ai_integrations(tmp_path)

    assert any(f.rule_id == "odoo-ai-hardcoded-api-key" for f in findings)


def test_detects_tainted_prompt_via_openai(tmp_path: Path) -> None:
    """Passing request-derived data into an LLM prompt should be flagged."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "ai.py").write_text(
        '''
from odoo import http, models
from odoo.http import request
import openai

class AiController(http.Controller):
    @http.route("/ai/ask", auth="public", type="json")
    def ask(self, **kw):
        client = openai.OpenAI()
        response = client.chat.completions.create(
            messages=[{"role": "user", "content": kw.get("question")}],
            model="gpt-4",
        )
        return {"answer": response.choices[0].message.content}
''',
        encoding="utf-8",
    )

    findings = scan_ai_integrations(tmp_path)

    assert any(f.rule_id == "odoo-ai-tainted-prompt" for f in findings)


def test_detects_unsanitized_ai_output_to_markup(tmp_path: Path) -> None:
    """Rendering AI-generated content through Markup should be flagged."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "ai.py").write_text(
        '''
from odoo import models
from odoo.tools import Markup
import openai

class AiHelper(models.Model):
    _name = "x.ai.helper"

    def generate_html(self, prompt):
        client = openai.OpenAI()
        response = client.completions.create(prompt=prompt, model="gpt-4")
        return Markup(response.choices[0].text)
''',
        encoding="utf-8",
    )

    findings = scan_ai_integrations(tmp_path)

    assert any(f.rule_id == "odoo-ai-unsanitized-output" for f in findings)


def test_allows_safe_ai_usage(tmp_path: Path) -> None:
    """AI calls with hardcoded prompts and escaped output should not flag."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "ai.py").write_text(
        '''
from odoo import models
import openai

class AiHelper(models.Model):
    _name = "x.ai.helper"

    def summarize(self, text):
        client = openai.OpenAI()
        response = client.completions.create(
            prompt="Summarize: " + text,
            model="gpt-4",
        )
        return response.choices[0].text
''',
        encoding="utf-8",
    )

    findings = scan_ai_integrations(tmp_path)

    # No hardcoded key, no tainted prompt (text is not tracked as request-derived here),
    # no Markup render
    assert not any(f.rule_id == "odoo-ai-hardcoded-api-key" for f in findings)
    assert not any(f.rule_id == "odoo-ai-unsanitized-output" for f in findings)
