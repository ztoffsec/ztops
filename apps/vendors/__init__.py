"""Vendor — the entity a Finding is reported against.

Any authenticated user can register a Vendor. The creator owns it
and (along with superadmins) is the only one who can edit/delete.
Findings carry a FK to Vendor (PROTECT) so a vendor row can't be
removed while findings reference it.
"""
