"""Filename and content-type classes for attachment risk."""

from __future__ import annotations

RISKY_EXTENSIONS = frozenset(
    {
        ".exe",
        ".scr",
        ".js",
        ".jse",
        ".vbs",
        ".vbe",
        ".iso",
        ".lnk",
        ".bat",
        ".cmd",
        ".ps1",
        ".jar",
        ".msi",
        ".dll",
        ".com",
        ".hta",
        ".wsf",
        ".cpl",
    }
)
HTML_EXTENSIONS = frozenset({".html", ".htm"})
MACRO_EXTENSIONS = frozenset(
    {
        ".docm",
        ".dotm",
        ".xlsm",
        ".xltm",
        ".pptm",
        ".potm",
        ".ppam",
        ".xlam",
        ".xlsb",
    }
)


def suffixes(filename: str) -> list[str]:
    name = (filename or "").strip().strip('"').casefold()
    parts = [part for part in name.split(".") if part != ""]
    if len(parts) <= 1:
        return []
    return ["." + part for part in parts[1:]]


def last_suffix(filename: str) -> str:
    parts = suffixes(filename)
    return parts[-1] if parts else ""


def is_risky_filename(filename: str) -> bool:
    return last_suffix(filename) in RISKY_EXTENSIONS


def is_html_filename(filename: str) -> bool:
    return last_suffix(filename) in HTML_EXTENSIONS


def is_macro_filename(filename: str) -> bool:
    return last_suffix(filename) in MACRO_EXTENSIONS


def is_macro_type(filename: str, content_type: str) -> bool:
    if is_macro_filename(filename):
        return True
    media = (content_type or "").split(";", 1)[0].strip().casefold()
    return "macroenabled" in media


def is_html_attachment(filename: str, content_type: str) -> bool:
    if is_html_filename(filename):
        return True
    media = (content_type or "").split(";", 1)[0].strip().casefold()
    return media == "text/html"


def has_double_extension(filename: str) -> bool:
    """True when a dangerous final suffix sits behind at least one other suffix."""
    parts = suffixes(filename)
    if len(parts) < 2:
        return False
    last = parts[-1]
    return last in RISKY_EXTENSIONS or last in HTML_EXTENSIONS or last in MACRO_EXTENSIONS
