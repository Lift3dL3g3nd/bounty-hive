# Contributing to Bounty-Hive

Thank you for your interest in contributing to the Bounty-Hive project.

Bounty-Hive is a **security-sensitive, compliance-oriented platform**.  
As such, contributions follow strict rules to preserve provenance, auditability, and trust.

Failure to follow these rules may result in rejected contributions.

---

## Core Principle

> **All code changes MUST originate from a local development environment.**  
> **The GitHub web editor is treated as read-only for source code.**

This policy exists to preserve:
- Code provenance
- Reproducibility
- Audit trails
- Security guarantees

---

## ❌ Prohibited Actions

The following actions are **not allowed**:

- Editing source files via the GitHub web UI
- Pushing directly to protected branches (e.g. `main`)
- Force-pushing to any branch
- Deleting history or rewriting commits
- Uploading generated or compiled artifacts
- Bypassing branch protections
- Introducing tools, scripts, or dependencies without review

---

## ✅ Required Workflow

All contributions must follow this workflow:

### 1. Work Locally
- Clone the repository to your machine
- Make changes using a local editor
- Review your changes with `git diff`

### 2. Create a Feature Branch
```bash
git checkout -b feature/short-description
