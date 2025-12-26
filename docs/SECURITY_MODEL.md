# Security Model

## Trust boundaries
- User input is untrusted
- Policy HTML is untrusted
- LLM output is untrusted (read-only and guarded)

## Hard controls
- RBAC gates scope confirmation and evidence exports
- SafetyGuard blocks scanning/exploitation keywords
- Passive tool whitelist enforced
- Tamper-evident audit logs (hash-chained)
- Signed scope receipts (Ed25519)
