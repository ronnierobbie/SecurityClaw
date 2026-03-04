"""
tests/mock_llm.py — Deterministic mock LLM for unit tests.

Avoids any real network I/O; returns canned or generated responses
based on the message content, making tests fully reproducible.
"""
from __future__ import annotations

import json
import random
from typing import Optional

from core.llm_provider import BaseLLMProvider
from tests.data_generator import deterministic_embed


class MockLLMProvider(BaseLLMProvider):
    """
    A deterministic, offline LLM mock.

    Behavior:
      - `embed()` uses deterministic_embed (hash-based, no LLM needed)
      - `chat()` inspects the last user message and returns a canned JSON
        response appropriate for the detected skill context.
    """

    def __init__(self, dims: int = 64) -> None:
        self.dims = dims
        self.call_log: list[dict] = []  # records every call for assertions

    def embed(self, text: str) -> list[float]:
        vec = deterministic_embed(text, dims=self.dims)
        self.call_log.append({"type": "embed", "text": text[:80]})
        return vec

    @property
    def embedding_dimension(self) -> int:
        """Return the dimension of embeddings produced by this mock."""
        return self.dims

    def chat(
        self,
        messages: list[dict],
        *,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> str:
        user_content = _last_user_message(messages)
        self.call_log.append({"type": "chat", "content": user_content[:120]})

        # Dispatch on keywords in the prompt — check most-specific patterns first
        if "verdict" in user_content.lower() or "false positive" in user_content.lower() or "anomaly finding" in user_content.lower():
            return self._threat_verdict_response()

        if "anomaly detection finding" in user_content.lower() or "enrich" in user_content.lower():
            return self._anomaly_enrich_response()

        if "normal behavior" in user_content.lower() or "baseline" in user_content.lower():
            return self._baseline_response()

        # Generic fallback
        return json.dumps({"response": "ok", "content": user_content[:50]})

    # ------------------------------------------------------------------
    # Canned responses
    # ------------------------------------------------------------------

    @staticmethod
    def _baseline_response() -> str:
        return json.dumps({
            "summary": (
                "Normal traffic is predominantly HTTPS (port 443) and HTTP (port 80). "
                "DNS over UDP port 53 is frequent but low-volume. "
                "Average connection size is approximately 10,240 bytes."
            ),
            "typical_ports": [80, 443, 53, 22],
            "typical_protocols": ["tcp", "udp"],
            "avg_bytes_per_connection": 10240.0,
            "category": "network_baseline",
        })

    @staticmethod
    def _anomaly_enrich_response() -> str:
        severities = ["MEDIUM", "HIGH", "CRITICAL"]
        return json.dumps({
            "detector": "default-detector",
            "entity": "10.0.1." + str(random.randint(2, 254)),
            "score": round(random.uniform(0.7, 0.99), 4),
            "severity": random.choice(severities),
            "description": (
                "Host generated an unusually high volume of outbound traffic "
                "to a single external IP on port 443, significantly deviating "
                "from the established baseline."
            ),
            "features": ["network.bytes", "unique_dest_ports"],
        })

    @staticmethod
    def _threat_verdict_response() -> str:
        verdicts = [
            {
                "verdict": "TRUE_THREAT",
                "confidence": 87,
                "reasoning": (
                    "The anomaly involves over 40 MB of outbound data to an external IP "
                    "outside business hours, far exceeding the 5 MB baseline threshold. "
                    "The source host is not the designated backup server. "
                    "This pattern is consistent with data exfiltration. "
                    "Baseline context confirms no scheduled transfer was expected."
                ),
                "mitre_tactic": "TA0010 - Exfiltration",
                "recommended_action": "Isolate host immediately and initiate IR playbook.",
            },
            {
                "verdict": "FALSE_POSITIVE",
                "confidence": 92,
                "reasoning": (
                    "The elevated traffic volume aligns with a known software update cycle "
                    "that runs every Tuesday evening. The destination IP belongs to a CDN "
                    "used by the organization's patch management system. "
                    "Baseline context confirms this pattern occurs regularly."
                ),
                "mitre_tactic": None,
                "recommended_action": "Add exclusion rule for this detector during patch window.",
            },
        ]
        return json.dumps(random.choice(verdicts))


# ──────────────────────────────────────────────────────────────────────────────
# Helper
# ──────────────────────────────────────────────────────────────────────────────

def _last_user_message(messages: list[dict]) -> str:
    for msg in reversed(messages):
        if msg.get("role") == "user":
            return msg.get("content", "")
    return ""
