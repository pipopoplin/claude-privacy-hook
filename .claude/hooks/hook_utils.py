"""Shared utilities for Claude Code hooks.

Provides Unicode normalization (NFKC + homoglyph + zero-width stripping)
and dot-path field resolution used by regex_filter, llm_filter, and
output_sanitizer.
"""

import unicodedata


# Homoglyph map: visually similar Unicode chars -> ASCII equivalents
HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
    '\u03bf': 'o', '\u03b1': 'a', '\u03b9': 'i', '\u03ba': 'k',
    '\u03bd': 'v', '\u03c1': 'p',
    '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0397': 'H',
    '\u0399': 'I', '\u039a': 'K', '\u039c': 'M', '\u039d': 'N',
    '\u039f': 'O', '\u03a1': 'P', '\u03a4': 'T', '\u03a5': 'Y',
    '\u03a7': 'X',
}
ZERO_WIDTH_CHARS = {'\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad', '\u2060'}
_HOMOGLYPH_TRANS = str.maketrans(HOMOGLYPH_MAP)


def normalize_unicode(text: str) -> str:
    """Normalize Unicode to defeat homoglyph and zero-width bypasses."""
    # NFKC: collapse fullwidth chars, ligatures, compatibility forms
    text = unicodedata.normalize("NFKC", text)
    # Strip zero-width characters
    text = ''.join(c for c in text if c not in ZERO_WIDTH_CHARS)
    # Map common homoglyphs to ASCII
    text = text.translate(_HOMOGLYPH_TRANS)
    return text


def resolve_field(data: dict, field: str) -> str:
    """Resolve a dot-separated field path from the hook input JSON.

    e.g. "tool_input.command" -> data["tool_input"]["command"]
    """
    parts = field.split(".")
    current = data
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return ""
    return str(current) if current is not None else ""
