"""Fixtures specific to cross-app integration / e2e tests under tests/.

The project-root `conftest.py` handles cross-cutting fixtures (e.g. the
public-tenant bootstrap). This file is reserved for fixtures that only
apply to integration scenarios — e2e browser flows, multi-tenant test
contexts, etc., landing in later pasos.
"""

from __future__ import annotations
