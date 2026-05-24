"""Finding + FindingNote — the canonical disclosure record.

Single-instance app: one shared `findings_finding` / `findings_findingnote`
table for the whole team. FindingNote.author is a real FK to accounts.User
(same DB, same schema, real referential integrity).
"""
