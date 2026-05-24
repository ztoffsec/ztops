"""Project-root pytest configuration.

Single-instance app: no tenant fixtures needed. pytest-django's `db`
fixture is enough — migrations create the one shared schema, per-test
transactions roll back row state.
"""
