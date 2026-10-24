"""Refang defanged text back to real indicators, and defang them again."""

import re

# Refang: turn analyst-safe notation back into real indicators so the regexes
# can match. Order matters: do the longer tokens first.
_REFANG_REPLACEMENTS = [
    (re.compile(r"h\s?x\s?x\s?p", re.IGNORECASE), "http"),  # hxxp, hXXp -> http
    (re.compile(r"\[\s*\.\s*\]"), "."),
    (re.compile(r"\(\s*\.\s*\)"), "."),
    (re.compile(r"\{\s*\.\s*\}"), "."),
    (re.compile(r"\[\s*dot\s*\]", re.IGNORECASE), "."),
    (re.compile(r"\(\s*dot\s*\)", re.IGNORECASE), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*/\s*/\s*\]"), "//"),
    (re.compile(r"\[\s*at\s*\]", re.IGNORECASE), "@"),
    (re.compile(r"\(\s*at\s*\)", re.IGNORECASE), "@"),
    (re.compile(r"\[\s*@\s*\]"), "@"),
]


def refang(text: str) -> str:
    """Convert defanged text (hxxp, [.], [at]) back to real indicators."""
    for pattern, repl in _REFANG_REPLACEMENTS:
        text = pattern.sub(repl, text)
    return text


def defang(value: str) -> str:
    """Make an indicator safe to paste into a report or ticket."""
    value = value.replace("http", "hxxp")  # covers https -> hxxps too
    value = value.replace("@", "[at]")
    value = value.replace(".", "[.]")
    return value
