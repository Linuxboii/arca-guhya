"""Shannon entropy helpers used by the generic high-entropy detector."""

from __future__ import annotations

import math
import string
from collections import Counter

HEX_CHARS = frozenset(string.hexdigits)


def shannon_entropy(data: str) -> float:
    """Bits of entropy per character of ``data``."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_hex(data: str) -> bool:
    return bool(data) and all(ch in HEX_CHARS for ch in data)


def normalised_entropy(data: str) -> float:
    """Entropy relative to the maximum achievable for this length and alphabet.

    A string of length *n* drawn from an alphabet of size *k* can reach at most
    ``log2(min(n, k))`` bits per character, so dividing by that gives a score in
    ``[0, 1]`` that is comparable between short and long strings.
    """
    if len(data) < 2:
        return 0.0
    alphabet = 16 if is_hex(data) else 64
    ceiling = math.log2(min(len(data), alphabet))
    return shannon_entropy(data) / ceiling if ceiling else 0.0


def looks_random(data: str, min_length: int = 20, threshold: float = 0.85) -> bool:
    """Heuristic: does ``data`` look like a randomly generated credential?

    Requires a minimum length, a mix of letters and digits (so long
    identifiers and words are ignored) and a high normalised entropy.
    """
    stripped = data.rstrip("=")
    if len(stripped) < min_length:
        return False
    if not any(ch.isdigit() for ch in stripped) or not any(ch.isalpha() for ch in stripped):
        return False
    if shannon_entropy(stripped) < 3.5:
        return False
    return normalised_entropy(stripped) >= threshold
