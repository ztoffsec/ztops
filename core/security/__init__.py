"""Security primitives enforced at the framework layer.

Modules here implement the project's hard hardening requirements that must hold
for every request: HTTP security headers, trusted-proxy IP parsing, secret
loading. This package is the target of mypy `--strict` per the project's
type-discipline policy — keep annotations precise and avoid `Any`.
"""
