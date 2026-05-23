"""Intentionally vulnerable controller demonstrating CSRF disabled."""
from odoo import http
from odoo.http import request


class VulnCSRFController(http.Controller):
    @http.route('/vuln/csrf/update_profile', auth='user', type='http', csrf=False)
    def update_profile(self, **kwargs):
        # VULNERABILITY: csrf=False allows cross-site POST
        user = request.env.user
        user.write({'name': kwargs.get('name')})
        return 'OK'

    @http.route('/vuln/csrf/transfer', auth='user', type='json', csrf=False)
    def transfer_credits(self, recipient_id=None, amount=None, **kwargs):
        # VULNERABILITY: JSON route with CSRF disabled
        return {'status': 'transferred'}
