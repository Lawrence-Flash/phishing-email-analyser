"""Defang URLs, domains, and addresses so a report is safer to paste."""

from __future__ import annotations

import re


_URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>'\"]+")
_EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,}\b")
_DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b")
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)


def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")


def defang_ip(ip: str) -> str:
    if ":" in ip:
        return ip.replace(":", "[:]")
    return ip.replace(".", "[.]")


def defang_email(address: str) -> str:
    local, sep, domain = address.partition("@")
    if not sep:
        return defang_domain(address)
    return f"{local}@{defang_domain(domain)}"


def defang_url(url: str) -> str:
    """Turn http(s) into hxxp(s) and replace dots so the link is not live."""
    stripped = url.strip()
    lowered = stripped.lower()
    if lowered.startswith("data:"):
        return "data:(content omitted)"
    if lowered.startswith("javascript:"):
        return "javascript:(content omitted)"
    match = re.match(r"(?i)^(https?)(://)(.*)$", stripped)
    if not match:
        return stripped.replace(".", "[.]")
    scheme = "hxxps" if match.group(1).lower() == "https" else "hxxp"
    return scheme + "://" + match.group(3).replace(".", "[.]")


def defang_embedded(text: str) -> str:
    """Defang URLs, emails, bare domains, and IPv4 addresses inside prose."""
    text = _URL_RE.sub(lambda match: defang_url(match.group(0)), text)
    text = _EMAIL_RE.sub(lambda match: defang_email(match.group(0)), text)
    text = _DOMAIN_RE.sub(lambda match: defang_domain(match.group(0)), text)
    text = _IPV4_RE.sub(lambda match: defang_ip(match.group(0)), text)
    return text


def present_evidence(item: str) -> str:
    """Render an internal evidence token for humans and JSON."""
    kind, sep, value = item.partition(":")
    if not sep:
        return defang_embedded(item)
    if kind == "url":
        return defang_url(value)
    if kind == "domain":
        return defang_domain(value)
    if kind == "email":
        return defang_email(value)
    if kind == "ip":
        return defang_ip(value)
    if kind == "file":
        return value
    if kind == "text":
        return defang_embedded(value)
    return defang_embedded(item)
