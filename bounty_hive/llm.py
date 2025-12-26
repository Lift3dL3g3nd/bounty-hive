from __future__ import annotations

import os
from dataclasses import dataclass

import requests


@dataclass
class LLMConfig:
    backend: str  # mock | ollama
    model: str
    timeout_s: int = 60


class LLMClient:
    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg

    @staticmethod
    def from_env() -> "LLMClient":
        backend = os.getenv("BOUNTY_HIVE_LLM_BACKEND", "mock").strip().lower()
        model = os.getenv("BOUNTY_HIVE_LLM_MODEL", "llama3.1").strip()
        return LLMClient(LLMConfig(backend=backend, model=model))

    def suggest(self, system: str, user: str) -> str:
        if self.cfg.backend == "ollama":
            return self._ollama(system, user)
        return self._mock(system, user)

    def _mock(self, system: str, user: str) -> str:
        u = (user or "").strip()
        return (
            "MOCK_SUGGESTIONS:\n"
            "- Confirm scope items manually; parsing is best-effort.\n"
            "- Record explicit 'no automated tools' language.\n"
            f"- Excerpt (first 600 chars): {u[:600]}\n"
        )

    def _ollama(self, system: str, user: str) -> str:
        url = os.getenv("BOUNTY_HIVE_OLLAMA_URL", "http://localhost:11434").rstrip("/")
        payload = {
            "model": self.cfg.model,
            "prompt": f"{system}\n\nUSER:\n{user}\n",
            "stream": False,
        }
        r = requests.post(f"{url}/api/generate", json=payload, timeout=self.cfg.timeout_s)
        r.raise_for_status()
        data = r.json()
        return str(data.get("response", "")).strip()
