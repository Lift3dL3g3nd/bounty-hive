#!/usr/bin/env bash
set -euo pipefail

echo "[*] Starting automated repair..."

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ ! -d ".venv" ]; then
  echo "[!] .venv not found. Run tools/update.sh first."
  exit 1
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "[*] Installing missing type stubs..."
pip install -q types-requests

echo "[*] Auto-formatting and fixing imports..."
ruff format bounty_hive
ruff check bounty_hive --fix

echo "[*] Patching normalize_policy cache behavior..."

NORMALIZE_FILE="bounty_hive/normalize.py"

if grep -q "fetch_html(url, html_path)" "$NORMALIZE_FILE"; then
  python - << 'EOF'
from pathlib import Path
import re

path = Path("bounty_hive/normalize.py")
text = path.read_text(encoding="utf-8")

pattern = r"html\s*=\s*fetch_html\(url,\s*html_path\)"
replacement = """if html_path.exists() and not refresh:
        html = html_path.read_text(encoding="utf-8")
        source = "cache"
    else:
        html = fetch_html(url, html_path)
        source = "network\""""

text, n = re.subn(pattern, replacement, text)
if n:
    path.write_text(text, encoding="utf-8")
    print("[+] normalize_policy cache fix applied")
else:
    print("[=] normalize_policy already patched")
EOF
else
  echo "[=] normalize_policy already uses cache logic"
fi

echo "[*] Removing unused 'type: ignore' comments..."

python - << 'EOF'
from pathlib import Path
import re

for path in Path("bounty_hive").rglob("*.py"):
    text = path.read_text(encoding="utf-8")
    new = re.sub(r"#\s*type:\s*ignore\[.*?\]\s*\n", "", text)
    if new != text:
        path.write_text(new, encoding="utf-8")
        print(f"[+] Cleaned unused type ignore in {path}")
EOF

echo "[*] Ensuring adapter base has return annotations..."

ADAPTER="bounty_hive/adapters/base.py"
if [ -f "$ADAPTER" ]; then
  python - << 'EOF'
from pathlib import Path
import re

p = Path("bounty_hive/adapters/base.py")
t = p.read_text(encoding="utf-8")

t = re.sub(r"def supports\(self,\s*url:\s*str\):",
           "def supports(self, url: str) -> bool:", t)

t = re.sub(
    r"def normalize\((.*?)\):",
    r"def normalize(\1) -> NormalizedPolicy:",
    t,
    flags=re.S
)

p.write_text(t, encoding="utf-8")
print("[+] Adapter base annotations ensured")
EOF
fi

echo "[*] Running final checks..."

ruff check bounty_hive
pytest -q
mypy bounty_hive

echo "[✓] Repair complete. Repo is clean."
