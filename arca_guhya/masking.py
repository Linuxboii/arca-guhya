"""Redaction of secret values for display."""


def mask(secret: str, head: int = 4, tail: int = 2) -> str:
    """Keep a few leading/trailing characters for recognition, hide the rest.

    Values of 8 characters or fewer are hidden completely. The masked value
    keeps the original length so column alignment in snippets is preserved.
    """
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:head] + "*" * (len(secret) - head - tail) + secret[-tail:]
