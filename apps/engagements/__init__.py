"""Engagement, Asset, and ScopeRule — engagement scope tracking.

Single-instance app: one shared set of engagements for the team.
An Engagement is a disclosure cycle / bug-bounty project / pentest
engagement. Assets and ScopeRules describe what's in/out of scope for
the engagement. Findings (apps.findings) link back via FK.
"""
