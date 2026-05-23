"""Intentionally vulnerable controller demonstrating XSS via t-raw."""
from odoo import http
from odoo.http import request
from odoo.tools import markupsafe


class VulnXSSController(http.Controller):
    @http.route('/vuln/xss/comment', auth='public', type='http')
    def show_comment(self, comment=None, **kwargs):
        # t-raw in the template will render this unsafely
        return request.render('vuln_xss_traw.comment_page', {
            'comment': comment or '',
        })

    @http.route('/vuln/xss/markup', auth='public', type='http')
    def show_markup(self, content=None, **kwargs):
        # VULNERABILITY: Markup with f-string on user input
        html = markupsafe.Markup(f"<div>{content}</div>")
        return request.make_response(html)
