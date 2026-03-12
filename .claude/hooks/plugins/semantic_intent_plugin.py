"""Semantic intent plugin — verb+target heuristic classification for suspicious command intent."""

import re
from plugins.base import SensitiveContentPlugin, DetectionResult


class SemanticIntentPlugin(SensitiveContentPlugin):
    name = "semantic_intent"
    tier = "EdgeDevice"

    # Dangerous verbs that strongly signal malicious intent
    DANGEROUS_VERBS = [
        "exfiltrate", "steal", "extract", "dump", "harvest",
        "scrape", "siphon", "smuggle", "leak",
    ]

    # Network-oriented exfiltration verbs (lower severity on their own)
    NETWORK_EXFIL_VERBS = [
        "upload", "send", "post", "transmit", "transfer",
        "forward", "relay",
    ]

    # Sensitive targets
    DANGEROUS_TARGETS = [
        "credentials", "secrets", "tokens", "passwords", "keys",
        "database", "userdata", "PII", "records",
    ]

    def __init__(self) -> None:
        self._custom_dangerous_verbs: list[str] = []
        self._custom_network_verbs: list[str] = []
        self._custom_targets: list[str] = []
        self._build_patterns()

    def _build_patterns(self) -> None:
        """Compile regex patterns from current verb/target lists."""
        all_dangerous = self.DANGEROUS_VERBS + self._custom_dangerous_verbs
        all_network = self.NETWORK_EXFIL_VERBS + self._custom_network_verbs
        all_targets = self.DANGEROUS_TARGETS + self._custom_targets

        dangerous_verb_pat = "|".join(re.escape(v) for v in all_dangerous)
        network_verb_pat = "|".join(re.escape(v) for v in all_network)
        target_pat = "|".join(re.escape(t) for t in all_targets)

        # verb ... target (up to ~60 chars apart)
        self._dangerous_re = re.compile(
            rf"\b({dangerous_verb_pat})\b.{{0,60}}\b({target_pat})\b",
            re.IGNORECASE,
        )
        self._network_re = re.compile(
            rf"\b({network_verb_pat})\b.{{0,60}}\b({target_pat})\b",
            re.IGNORECASE,
        )

    def is_available(self) -> bool:
        return True

    def detect(self, text: str, entity_types: list[str] | None = None) -> list[DetectionResult]:
        if entity_types and "SUSPICIOUS_INTENT" not in entity_types:
            return []

        results: list[DetectionResult] = []
        seen_spans: set[tuple[int, int]] = set()

        # High-confidence: dangerous verb + sensitive target (0.85)
        for m in self._dangerous_re.finditer(text):
            span = (m.start(), m.end())
            if span not in seen_spans:
                seen_spans.add(span)
                results.append(DetectionResult(
                    entity_type="SUSPICIOUS_INTENT",
                    text=m.group(),
                    score=0.85,
                    start=m.start(),
                    end=m.end(),
                    plugin_name=self.name,
                ))

        # Medium-confidence: network exfil verb + sensitive target (0.70)
        for m in self._network_re.finditer(text):
            span = (m.start(), m.end())
            if span not in seen_spans:
                seen_spans.add(span)
                results.append(DetectionResult(
                    entity_type="SUSPICIOUS_INTENT",
                    text=m.group(),
                    score=0.70,
                    start=m.start(),
                    end=m.end(),
                    plugin_name=self.name,
                ))

        return results

    def configure(self, plugin_config: dict) -> None:
        """Apply plugin-specific config. Supports custom_verbs, custom_network_verbs, custom_targets."""
        self._custom_dangerous_verbs = plugin_config.get("custom_verbs", [])
        self._custom_network_verbs = plugin_config.get("custom_network_verbs", [])
        self._custom_targets = plugin_config.get("custom_targets", [])
        self._build_patterns()
