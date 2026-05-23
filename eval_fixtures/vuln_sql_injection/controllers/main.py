"""Intentionally vulnerable controller demonstrating SQL injection."""
from odoo import http
from odoo.http import request


class VulnSQLController(http.Controller):
    @http.route('/vuln/sql/search', auth='public', type='http')
    def search_users(self, name=None, **kwargs):
        # VULNERABILITY: SQL injection via f-string interpolation
        query = f"SELECT id, name FROM res_users WHERE name LIKE '%{name}%'"
        request.env.cr.execute(query)
        results = request.env.cr.fetchall()
        return request.render('vuln_sql_injection.results', {'results': results})

    @http.route('/vuln/sql/update', auth='user', type='json')
    def update_email(self, user_id=None, email=None, **kwargs):
        # VULNERABILITY: SQL injection via string concatenation
        query = "UPDATE res_users SET email = '" + email + "' WHERE id = " + str(user_id)
        request.env.cr.execute(query)
        return {'status': 'ok'}
