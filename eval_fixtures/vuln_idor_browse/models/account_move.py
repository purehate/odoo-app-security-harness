"""Intentionally vulnerable model demonstrating IDOR in model methods."""
from odoo import models, api


class AccountMoveVuln(models.Model):
    _inherit = 'account.move'

    @api.model
    def portal_fetch(self, move_id):
        # VULNERABILITY: no access check before returning sensitive data
        move = self.browse(int(move_id))
        return {
            'name': move.name,
            'amount_total': move.amount_total,
            'partner_id': move.partner_id.id,
        }
