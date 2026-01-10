# Bounty-Hive Core

**Bounty-Hive Core** is a security-focused disclosure and audit platform designed to
safely handle vulnerability findings without exposing exploit material.

This repository contains the **Core trust layer only**.

It is intentionally limited in scope.

---

## Core Stability

- Core freeze: `v0.1.1-core-freeze`
- Post-freeze hardening: `v0.1.2-core-hardened`

See:
- `CORE_STABILITY_NOTE.md`
- `PLATFORM_INVARIANTS.md`

## What This Project Is

Bounty-Hive Core provides:

- Deterministic audit trails for security findings
- Hash-chained, verifiable disclosure records
- Role-based visibility controls
- State-gated workflows (`created → validated → approved → delivered`)
- Redaction-by-design for sensitive artifacts
- Structured, deterministic reporting (e.g. SARIF)
- Proof of custody and non-access guarantees

The goal is to answer questions like:

- *When was this finding created?*
- *Who had access to it, and when?*
- *Has it been modified?*
- *Was sensitive material ever exposed prematurely?*

All answers are cryptographically verifiable.

---

## What This Project Is NOT

Bounty-Hive Core **does NOT**:

- Perform autonomous vulnerability discovery
- Execute exploits or proof-of-concept payloads
- Generate weaponized exploit code
- Perform scanning beyond basic, policy-safe analysis
- Bypass authentication, authorization, or safeguards
- Replace manual security testing methodologies

This repository contains **no exploit logic**.

---

## Architecture Overview

Bounty-Hive is intentionally split into two projects:

### 🧱 Bounty-Hive Core (this repository)
- Public, auditable, trust-focused
- Handles custody, auditability, visibility, and disclosure
- Safe for open-source review

### 🔒 Bounty-Hive Engine (not public)
- Paid, gated, and private
- Performs advanced vulnerability discovery and validation
- Never exposes weaponized artifacts to end users
- Integrated via strict, auditable interfaces

The Engine is **not included** in this repository.

---

## Security & Disclosure Philosophy

Sensitive vulnerability material must be treated as hazardous.

Bounty-Hive Core enforces:
- Least-privilege access
- Deterministic redaction
- Immutable audit checkpoints
- Explicit consent and approval gates

No exploit artifacts are ever exposed by default.

---

## Intended Use

This project is intended for:
- Responsible vulnerability disclosure
- Bug bounty workflow validation
- Auditability and compliance research
- Secure reporting pipelines

All usage must comply with:
- Target program scope
- Applicable laws
- Ethical security research practices

---

## License

This project is licensed under the MIT License.

See `LICENSE` for details.
