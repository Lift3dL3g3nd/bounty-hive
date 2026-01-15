# Bounty-Hive Core — Freeze Declaration

**Status:** FROZEN  
**Tag:** v0.6.0-core-sealed  
**Date:** 2026-01-14

---

## Purpose

This document declares a formal freeze of the **Bounty-Hive Core** system.

Bounty-Hive Core is responsible for **custody, verification, and lifecycle governance**
of vulnerability disclosure artifacts produced by the Bounty-Hive Engine.

Core does not perform vulnerability discovery, scanning, exploitation, or autonomous analysis.

This freeze establishes a stable, auditable trust boundary suitable for enterprise
evaluation, compliance review, and controlled pilot use.

---

## Scope of Core Responsibilities

At freeze, Bounty-Hive Core is responsible for:

- Verifying Engine-produced disclosure packages
- Enforcing schema correctness and canonical hash integrity
- Enforcing disclosure lifecycle transitions
- Maintaining tamper detection and auditability
- Managing role-based access control and permissions
- Storing **metadata and hashes only for Engine-originated disclosure packages**

Core does **not**:
- Generate vulnerabilities
- Perform scanning or exploitation
- Contain autonomous discovery logic
- Store exploit payloads or reproduction instructions
- Interpret or modify Engine findings

---

## Trust Boundary

Core treats **all Engine output as untrusted input**.

A single, explicit trust boundary exists at the following entrypoint:

bounty_hive.intake.engine.ingest_engine_disclosure

All Engine disclosure packages must pass, at this boundary:

- JSON Schema validation
- Canonical JSON SHA-256 integrity verification
- Finalization checks (presence of `package_id` and canonical hash)

No disclosure data may enter Core logic, storage, or workflows without passing validation.

This boundary is enforced by code and verified by automated tests.

---

## Disclosure Lifecycle Enforcement

Core enforces the following immutable lifecycle:

**created → validated → approved → purchased → delivered**

- Transitions are unidirectional
- Invalid transitions are rejected
- Core is the sole authority for lifecycle advancement

The Engine cannot advance lifecycle state.

---

## Integrity Guarantees

At freeze, Core guarantees:

- Acceptance of schema-valid disclosures only
- Canonical JSON SHA-256 tamper detection
- Explicit rejection of modified or malformed artifacts
- Deterministic verification behavior
- No implicit trust of upstream systems

All guarantees are enforced by automated tests that must pass for any future release.

---

## Auditability

Core provides:

- Deterministic validation results
- Cryptographically verifiable hashes
- Clear attribution of lifecycle state
- A foundation for append-only audit receipts (future work)

---

## Change Policy

This freeze applies to:

- Disclosure verification logic
- Trust boundary enforcement
- Schema validation
- Lifecycle enforcement rules

Any change to the above requires:

- A new version
- A new freeze declaration
- Updated tests proving invariants remain intact

---

## Intended Use

This frozen state is intended for:

- Enterprise pilot evaluations
- Internal security review
- Legal and compliance assessment
- Architecture and due-diligence review

---

**This system is designed exclusively for authorized, defensive vulnerability research and controlled disclosure.**
