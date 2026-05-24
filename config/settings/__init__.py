"""Per-environment Django settings. Choose one via DJANGO_SETTINGS_MODULE.

Available modules:
    config.settings.dev   — local development on a developer workstation
    config.settings.test  — pytest runs (CI and local)
    config.settings.prod  — production droplet; asserts secrets present

The shared baseline lives in `config.settings.base`. Per-environment modules
import from base and override only what differs.
"""
