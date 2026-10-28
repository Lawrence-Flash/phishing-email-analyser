"""Host, IP, and registrable-domain helpers used by several analysers."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


# A small public-suffix slice. Enough for SA brands and common mail domains.
# This is not the full Public Suffix List.
MULTI_SUFFIXES = frozenset(
    {
        "co.za",
        "org.za",
        "gov.za",
        "net.za",
        "ac.za",
        "web.za",
        "edu.za",
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "net.uk",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "co.nz",
        "org.nz",
        "net.nz",
        "co.jp",
        "ne.jp",
        "or.jp",
        "com.br",
        "com.mx",
        "co.in",
        "com.tr",
        "co.kr",
    }
)

_DOC_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

_RESERVED_EXACT = frozenset({"example.com", "example.net", "example.org"})
_RESERVED_SUFFIXES = (
    ".example",
    ".invalid",
    ".test",
    ".localhost",
    ".example.com",
    ".example.net",
    ".example.org",
)


def is_ip(host: str) -> bool:
    value = host.strip().strip("[]")
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def to_unicode_host(host: str) -> str:
    """Lowercase a host and decode punycode when it is ASCII IDNA."""
    host = host.strip().casefold().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        return ""
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        return host
    try:
        return host.encode("ascii").decode("idna").casefold()
    except UnicodeError:
        return host


def to_ascii_host(host: str) -> str:
    """ASCII form suitable for a DNS query."""
    uni = to_unicode_host(host)
    if not uni or is_ip(uni):
        return uni
    try:
        return uni.encode("idna").decode("ascii")
    except UnicodeError:
        return uni


def registrable_domain(host: str) -> str:
    host = to_unicode_host(host)
    if not host or is_ip(host):
        return host
    labels = [label for label in host.split(".") if label]
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return ".".join(labels)


def sld(host: str) -> str:
    reg = registrable_domain(host)
    return reg.split(".", 1)[0] if reg else ""


def different_org(left: str, right: str) -> bool:
    if not left or not right:
        return False
    return registrable_domain(left) != registrable_domain(right)


def hostname_of(url: str) -> str:
    candidate = url.strip()
    if not candidate or candidate.lower().startswith(("data:", "javascript:", "mailto:")):
        return ""
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        host = urlparse(candidate).hostname or ""
    except ValueError:
        return ""
    return to_unicode_host(host)


def is_documentation_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return False
    return any(ip in network for network in _DOC_NETWORKS)


def is_reserved_domain(domain: str) -> bool:
    """True for RFC 2606 names and documentation IPs used in the samples."""
    host = to_unicode_host(domain)
    if not host:
        return False
    if is_ip(host):
        return is_documentation_ip(host)
    if host in _RESERVED_EXACT:
        return True
    return host.endswith(_RESERVED_SUFFIXES)


def extract_ips(value: str) -> tuple[str, ...]:
    """Pull IPv4 addresses and bracketed IPv6 addresses from a header."""
    found: list[str] = []
    ipv4 = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
    )
    for match in ipv4.finditer(value):
        found.append(match.group(0))
    for match in re.finditer(r"\[([^\]]+)\]", value):
        inner = match.group(1)
        if ":" not in inner:
            continue
        try:
            ip = ipaddress.ip_address(inner)
        except ValueError:
            continue
        found.append(str(ip))
    seen: set[str] = set()
    ordered: list[str] = []
    for item in found:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return tuple(ordered)
