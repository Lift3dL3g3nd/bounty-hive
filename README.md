# Bounty Hive Enterprise (Kali-safe)

Passive-only, compliance-first policy normalizer + evidence system.

## Enterprise controls
- RBAC (viewer/analyst/lead/compliance/admin)
- Scope confirmation lock (lead/admin only) + ticket/justification required
- Signed scope confirmation receipts (Ed25519)
- Tamper-evident audit log (hash-chained JSONL) + `audit-verify`
- Evidence Index auto-generated (`docs/EVIDENCE_INDEX.md`)
- Audit bundle export (ZIP + `MANIFEST.sha256`), includes docs/receipts by default if present
- Pluggable policy adapters (registry + generic adapter)

## Kali prerequisites (GUI + whois)
```bash
sudo apt update
sudo apt install -y python3-tk whois
```

## Quickstart
```bash
python3 bounty_hive_enterprise_gen_v2.py
cd bounty-hive
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -e .
pytest -q

bounty-hive --help
bounty-hive gui --user alice --role lead
```

## Safety posture
- No scanning, exploitation, brute force, DoS, or social engineering
- Passive DNS resolve + WHOIS only, and only after:
  - lead/admin scope confirmation + signed receipt
  - explicit per-action approval (unless `--yes` used)
