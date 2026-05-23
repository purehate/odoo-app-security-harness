"""Intentionally vulnerable controller demonstrating IDOR via browse."""
from odoo import http
from odoo.http import request


class VulnIDORController(http.Controller):
    @http.route('/vuln/idor/document', auth='public', type='http')
    def get_document(self, doc_id=None, **kwargs):
        # VULNERABILITY: user-controlled ID passed directly to browse without access check
        doc = request.env['res.partner'].browse(int(doc_id))
        return request.render('vuln_idor_browse.document', {'doc': doc})

    @http.route('/vuln/idor/invoice', auth='user', type='json')
    def get_invoice(self, invoice_id=None, **kwargs):
        # VULNERABILITY: browse on user-controlled ID with sudo
        invoice = request.env['account.move'].sudo().browse(int(invoice_id))
        return {'amount': invoice.amount_total}
