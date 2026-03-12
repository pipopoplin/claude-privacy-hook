"""High-entropy secret detection plugin.

Detects potential secrets (API keys, tokens, passwords) that don't match
known patterns by calculating Shannon entropy of string tokens. Pure Python,
no external dependencies, ~1ms latency.

Entity type: HIGH_ENTROPY_SECRET
"""

import math
import re

from .base import DetectionResult, SensitiveContentPlugin

# Context keywords that boost confidence near high-entropy strings
SECRET_CONTEXT_WORDS = {
    "key", "token", "secret", "password", "credential", "auth",
    "api", "apikey", "api_key", "bearer", "authorization",
    "private", "signing", "encryption", "decrypt",
}

# Known hash lengths to skip (unless in assignment context)
HASH_LENGTHS = {32, 40, 64, 128}  # MD5, SHA1, SHA256, SHA512

# Regex to extract tokens: quoted strings and bare tokens
_TOKEN_RE = re.compile(
    r"""(?:['"])([A-Za-z0-9+/=_\-]{16,})(?:['"])|"""  # quoted strings
    r"""(?<=[=:\s])([A-Za-z0-9+/=_\-]{16,})(?=[\s'";,)}]|$)""",  # after = or : or space
    re.MULTILINE,
)


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _char_class_count(s: str) -> int:
    """Count distinct character classes (upper, lower, digit, special)."""
    classes = 0
    if any(c.isupper() for c in s):
        classes += 1
    if any(c.islower() for c in s):
        classes += 1
    if any(c.isdigit() for c in s):
        classes += 1
    if any(not c.isalnum() for c in s):
        classes += 1
    return classes


def _is_file_path(s: str) -> bool:
    """Check if token looks like a file path."""
    return "/" in s and not s.startswith("http") and s.count("/") >= 2


def _has_secret_context(text: str, start: int, window: int = 50) -> bool:
    """Check if there's a secret-related keyword near the token."""
    context_start = max(0, start - window)
    context = text[context_start:start].lower()
    return any(word in context for word in SECRET_CONTEXT_WORDS)


class EntropyDetectorPlugin(SensitiveContentPlugin):
    name = "entropy_detector"
    tier = "EdgeDevice"

    def __init__(self):
        self._min_entropy = 4.0
        self._min_length = 16

    def configure(self, plugin_config: dict) -> None:
        self._min_entropy = plugin_config.get("min_entropy", 4.0)
        self._min_length = plugin_config.get("min_length", 16)

    def is_available(self) -> bool:
        return True  # Pure Python, no external dependencies

    def detect(self, text: str, entity_types: list[str] | None = None) -> list[DetectionResult]:
        if entity_types and "HIGH_ENTROPY_SECRET" not in entity_types:
            return []

        results = []
        seen_tokens = set()

        for match in _TOKEN_RE.finditer(text):
            token = match.group(1) or match.group(2)
            if not token or len(token) < self._min_length:
                continue
            if token in seen_tokens:
                continue
            seen_tokens.add(token)

            # Skip file paths
            if _is_file_path(token):
                continue

            # Calculate entropy
            entropy = _shannon_entropy(token)
            if entropy < self._min_entropy:
                continue

            # Skip pure hex at known hash lengths (unless in secret context)
            is_pure_hex = all(c in "0123456789abcdefABCDEF" for c in token)
            if is_pure_hex and len(token) in HASH_LENGTHS:
                if not _has_secret_context(text, match.start()):
                    continue

            # Require at least 2 character classes for non-hex
            if not is_pure_hex and _char_class_count(token) < 2:
                continue

            # Score: base from entropy, boosted by context
            base_score = min(1.0, (entropy - 3.5) / 2.0)
            if _has_secret_context(text, match.start()):
                base_score = min(1.0, base_score + 0.15)

            if base_score < 0.5:
                continue

            results.append(DetectionResult(
                entity_type="HIGH_ENTROPY_SECRET",
                text=token[:20] + "..." if len(token) > 20 else token,
                score=round(base_score, 2),
                start=match.start(),
                end=match.end(),
                plugin_name=self.name,
            ))

        return results
