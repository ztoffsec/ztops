"""Central registry of API token scopes.

Single source of truth: the model's DB check constraint, the creation form
and the permission class all derive from ``Scope``. A view that does not
declare the scopes it requires is denied (see ``permissions.HasTokenScopes``).

Never add a scope that maps to review approval (``review_state``) or to a
superadmin action: those are deliberately not reachable through the API.
"""

from __future__ import annotations

from django.db import models


class Scope(models.TextChoices):
    FINDINGS_READ = "findings:read", "Read findings you can access"
    FINDINGS_WRITE = "findings:write", "Create and update findings"
    FINDINGS_STATUS = "findings:status", "Change finding status"
    NOTES_WRITE = "notes:write", "Add notes to findings"
    ATTACHMENTS_WRITE = "attachments:write", "Upload attachments"


ALL_SCOPES: frozenset[str] = frozenset(Scope.values)


def normalize_scopes(values: list[str] | tuple[str, ...] | set[str]) -> list[str]:
    """Return a sorted, de-duplicated list of known scopes.

    Raises ``ValueError`` on any unknown value (allow-list, fail closed).
    """
    unknown = set(values) - ALL_SCOPES
    if unknown:
        msg = "unknown scope"
        raise ValueError(msg)
    return sorted(set(values))
