"""Cross-cutting helpers that are not Django apps.

`core` houses code that is policy-shaped or framework-shaped rather than
domain-shaped: security middleware, HTMX glue, logging configuration,
pagination helpers, exception handlers. Things in here run on every
request or every model regardless of which feature is being served.

`core.security` is a high-scrutiny zone (mypy `--strict`, dedicated review).
"""
