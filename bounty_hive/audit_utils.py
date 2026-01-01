from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

from .models import NormalizedPolicy


def hash_policy(policy: NormalizedPolicy) -> str:
    data = asdict(policy)

    # defensive: remove anything future-sensitive here
    payload = json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()
