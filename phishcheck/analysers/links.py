"""Extract links and flag mismatches, IP hosts, shorteners, and dangerous schemes."""

from __future__ import annotations

import re
from html import unescape
from urllib.parse import urlparse

from phishcheck.domains import hostname_of, is_ip, registrable_domain
from phishcheck.models import Finding, Link, ParsedEmail
from phishcheck.rules import make_finding


_ANCHOR_RE = re.compile(
    r"(?is)<a\b[^>]*?\bhref\s*=\s*(['\"])(.*?)\1[^>]*>(.*?)</a>"
)
_TAG_RE = re.compile(r"(?is)<[^>]+>")
_URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>'\"\]]+")
_DATA_RE = re.compile(r"(?i)\bdata:[^\s<>'\"]+")
_JS_RE = re.compile(r"(?i)\bjavascript:[^\s<>'\"]+")
_BARE_DOMAIN_RE = re.compile(
    r"(?i)\b(?:[a-z0-9-]+\.)+(?:[a-z]{2,}|xn--[a-z0-9-]{2,})\b"
)
_TRAILING = ".,);:!?»\"'"

SHORTENERS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "cutt.ly",
        "rebrand.ly",
        "tiny.cc",
        "shorturl.at",
        "rb.gy",
        "s.id",
        "v.gd",
        "bit.do",
        "t.ly",
        "lnkd.in",
    }
)

_CREDENTIAL_WORDS = (
    "login",
    "log-in",
    "logon",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "password",
    "passwd",
    "otp",
    "credential",
    "webscr",
    "banking",
    "unlock",
    "suspended",
    "wallet",
)


def _strip_trailing(value: str) -> str:
    return value.rstrip(_TRAILING)


def _strip_tags(value: str) -> str:
    text = _TAG_RE.sub(" ", value)
    return re.sub(r"\s+", " ", unescape(text)).strip()


def _scheme(url: str) -> str:
    lowered = url.strip().casefold()
    if lowered.startswith("data:"):
        return "data"
    if lowered.startswith("javascript:"):
        return "javascript"
    if lowered.startswith("mailto:"):
        return "mailto"
    return "http"


def _hosts_in_display(text: str) -> list[str]:
    hosts: list[str] = []
    for match in _URL_RE.finditer(text):
        host = hostname_of(_strip_trailing(match.group(0)))
        if host:
            hosts.append(host)
    for match in _BARE_DOMAIN_RE.finditer(text):
        hosts.append(match.group(0).casefold())
    return hosts


def _is_shortener(host: str) -> bool:
    host = host.casefold().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host in SHORTENERS


def _credential(url: str) -> bool:
    candidate = url.strip()
    if "://" not in candidate and not candidate.lower().startswith("www."):
        return False
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return False
    haystack = f"{parsed.path}?{parsed.query}".casefold()
    return any(word in haystack for word in _CREDENTIAL_WORDS)


def _add_link(links: list[Link], seen: set[tuple[str, str, str]], url: str, display: str, source: str) -> None:
    url = _strip_trailing(unescape(url.strip()))
    display = _strip_tags(display)
    if not url:
        return
    key = (url, display, source)
    if key in seen:
        return
    seen.add(key)
    links.append(Link(url=url, display=display, source=source))


def extract_links(text: str, html: str) -> tuple[Link, ...]:
    links: list[Link] = []
    seen: set[tuple[str, str, str]] = set()
    working_html = html or ""
    for match in _ANCHOR_RE.finditer(working_html):
        _add_link(links, seen, match.group(2), match.group(3), "html")
    without_anchors = _ANCHOR_RE.sub(" ", working_html)
    plain_html = _strip_tags(without_anchors)
    for source, blob in (("text", text or ""), ("html", plain_html)):
        for match in _URL_RE.finditer(blob):
            _add_link(links, seen, match.group(0), "", source)
        for match in _DATA_RE.finditer(blob):
            _add_link(links, seen, match.group(0), "", source)
        for match in _JS_RE.finditer(blob):
            _add_link(links, seen, match.group(0), "", source)
    return tuple(links)


def _mismatch(link: Link) -> bool:
    if not link.display or _scheme(link.url) != "http":
        return False
    href_host = hostname_of(link.url)
    if not href_host:
        return False
    display_hosts = _hosts_in_display(link.display)
    if not display_hosts:
        return False
    href_org = href_host if is_ip(href_host) else registrable_domain(href_host)
    for host in display_hosts:
        other = host if is_ip(host) else registrable_domain(host)
        if other and other != href_org:
            return True
    return False


def analyse_links(parsed: ParsedEmail) -> tuple[tuple[Finding, ...], tuple[Link, ...]]:
    links = extract_links(parsed.plain_text, parsed.html_text)
    mismatches: list[str] = []
    ip_urls: list[str] = []
    shorteners: list[str] = []
    credentials: list[str] = []
    data_uris: list[str] = []
    scripts: list[str] = []

    def remember(bucket: list[str], value: str) -> None:
        if value not in bucket:
            bucket.append(value)

    for link in links:
        scheme = _scheme(link.url)
        if scheme == "data":
            remember(data_uris, link.url)
            continue
        if scheme == "javascript":
            remember(scripts, link.url)
            continue
        if scheme != "http":
            continue
        if _mismatch(link):
            remember(mismatches, f"{link.display} -> {link.url}")
        host = hostname_of(link.url)
        if host and is_ip(host):
            remember(ip_urls, link.url)
        elif host and _is_shortener(host):
            remember(shorteners, link.url)
        if _credential(link.url):
            remember(credentials, link.url)

    findings: list[Finding] = []
    if mismatches:
        findings.append(
            make_finding(
                "link-href-mismatch",
                "At least one link shows a different host in the visible text than the href actually uses.",
                evidence=tuple(f"text:{item}" for item in mismatches[:8]),
            )
        )
    if ip_urls:
        findings.append(
            make_finding(
                "link-ip-address",
                "At least one link points at a raw IP address instead of a hostname.",
                evidence=tuple(f"url:{item}" for item in ip_urls[:8]),
            )
        )
    if shorteners:
        findings.append(
            make_finding(
                "link-shortener",
                "At least one link uses a URL shortener, which hides the destination until it is opened.",
                evidence=tuple(f"url:{item}" for item in shorteners[:8]),
            )
        )
    if credentials:
        findings.append(
            make_finding(
                "link-credential",
                "At least one link path or query uses credential-harvest wording such as login, verify, or password.",
                evidence=tuple(f"url:{item}" for item in credentials[:8]),
            )
        )
    if data_uris:
        findings.append(
            make_finding(
                "link-data-uri",
                "A data: URI is present. The payload is omitted from this report.",
                evidence=("text:data: URI present (content omitted)",),
            )
        )
    if scripts:
        findings.append(
            make_finding(
                "link-script-uri",
                "A javascript: link is present. The script body is omitted from this report.",
                evidence=("text:javascript: URI present (content omitted)",),
            )
        )
    return tuple(findings), links
