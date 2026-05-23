"""Intentionally vulnerable model demonstrating sudo bypass."""
from odoo import models, fields, api


class ResPartnerVuln(models.Model):
    _inherit = 'res.partner'

    def public_search_all(self):
        # VULNERABILITY: sudo() bypasses record rules and company isolation
        return self.sudo().search([])

    def public_read_all(self):
        # VULNERABILITY: with_env on SUPERUSER_ID equivalent
        return self.with_user(self.env.ref('base.user_admin')).search([])

    @api.model
    def unsafe_mass_update(self, vals):
        # VULNERABILITY: sudo on write bypasses ACL checks
        all_records = self.sudo().search([])
        all_records.write(vals)
        return True
