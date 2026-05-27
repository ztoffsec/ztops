"""Retired app.

The Engagement / Asset / ScopeRule models were removed when the Reports
feature absorbed engagement tracking (see apps.reports). This app is kept
only as a migration stub: its historical migrations are still referenced by
findings' migration graph, and migration 0002 deletes the old tables. It has
no models, views, urls, or templates.
"""

from __future__ import annotations
