#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-python3}"

echo "[*] Using: $($PYTHON --version)"

if [ ! -d ".venv" ]; then
  echo "[*] Creating venv..."
  $PYTHON -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

python -m pip install -U pip

echo "[*] Installing dependencies..."
pip install -r requirements.txt -r requirements-dev.txt

echo "[*] Installing editable package..."
pip install -e .

echo "[*] Running lint/type/tests..."
ruff check bounty_hive
mypy bounty_hive || true   # keep non-blocking until your typing is fully strict
pytest -q

echo "[+] Update complete."
