from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Action, NormalizedPolicy

_BANNED_KEYWORDS = [
    "nmap",
    "masscan",
    "zmap",
    "sqlmap",
    "ffuf",
    "wfuzz",
    "hydra",
    "medusa",
    "metasploit",
    "msfconsole",
    "reverse shell",
    "bind shell",
    "payload",
    "exploit",
    "rce",
    "spray",
    "password spraying",
    "bruteforce",
    "brute force",
    "dos",
    "ddos",
    "slowloris",
    "botnet",
    "credential stuffing",
    "remote code execution",
    "command injection",
]
_BANNED_REGEX = re.compile("|".join(re.escape(x) for x in _BANNED_KEYWORDS), re.IGNORECASE)


@dataclass
class GuardDecision:
    allowed: bool
    reason: str


class SafetyGuard:
    PASSIVE_TOOL_WHITELIST = {"resolve_a_records", "whois"}

    def __init__(self, policy: NormalizedPolicy | None):
        self.policy = policy

    def check_text(self, text: str) -> GuardDecision:
        if _BANNED_REGEX.search(text or ""):
            return GuardDecision(False, "Blocked: disallowed scanning/exploitation references.")
        return GuardDecision(True, "OK")

    def check_action(self, action: Action) -> GuardDecision:
        if action.category == "policy_fetch":
            return GuardDecision(True, "OK: policy fetch allowed.")
        if action.category not in {"planning", "passive_intel", "reporting"}:
            return GuardDecision(False, f"Blocked: unknown category '{action.category}'.")

        if action.category == "passive_intel":
            if not self.policy:
                return GuardDecision(False, "Blocked: no policy loaded.")
            if self.policy.requires_human_scope_confirmation:
                return GuardDecision(False, "Blocked: scope not confirmed by human.")
            tool = (action.metadata.get("tool") or "").strip()
            if tool not in self.PASSIVE_TOOL_WHITELIST:
                return GuardDecision(False, f"Blocked: tool '{tool}' not in passive whitelist.")
            if action.target and not self._is_in_scope(action.target):
                return GuardDecision(False, f"Blocked: target out of scope: {action.target}")
            return GuardDecision(True, "OK: passive intel allowed (with approval).")
        return GuardDecision(True, "OK")

    def _is_in_scope(self, target: str) -> bool:
        if not self.policy:
            return False
        t = target.strip().lower()
        for st in self.policy.in_scope:
            v = (st.value or "").strip().lower()
            if not v:
                continue
            if st.type == "domain":
                if t == v or t.endswith("." + v):
                    return True
            if st.type == "wildcard_domain":
                base = v.replace("*.", "")
                if t == base or t.endswith("." + base):
                    return True
        return False
