# Threat Model

## Primary threats
- User attempts to exceed scope
- Log tampering after-the-fact
- Prompt injection in policy text
- Accidental execution of disallowed tools

## Mitigations
- RBAC + scope confirmation lock
- Signed receipts + hash-chained audit logs
- SafetyGuard keyword blocking + passive whitelist
- Explicit approvals (dry-run default in GUI)
