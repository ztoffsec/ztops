"""Attachment metadata — PoC files / screenshots / recordings on a Finding.

Phase 3 ships only the metadata row; the full upload pipeline (signed-URL
endpoints, ClamAV scanning, content sniffing, sandboxed storage outside
MEDIA_ROOT) lives in this app's later milestones. The model is shaped to
accept those fields without schema disruption when the pipeline lands.
"""
