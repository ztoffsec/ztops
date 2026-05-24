"""Two-person rule for privileged actions.

Per the project hardening spec: destructive or privilege-escalating
actions require a second superadmin approval inside a time-boxed
window. This app owns the `SuperAdminApproval` state machine that
encodes that rule.

Flow:
    pending --[approve(by)]--> approved --[auto-execute]--> executed
       |--[deny(by, reason)]--> denied
       |--[24h elapsed]------> expired
    approved -[execute fails]-> failed

Self-approval is rejected at two layers:
- DB CheckConstraint: approved_by_id != requested_by_id.
- App-level guard in services.approve() before any DB write.

The actual action handlers (register_superadmin, revoke_user, ...)
live in their own apps and register through `register_handler`.
"""
