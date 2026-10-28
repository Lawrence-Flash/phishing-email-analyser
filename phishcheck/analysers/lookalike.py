"""Brand lookalikes: homoglyphs, punycode, typos, keyword compounds, odd TLDs."""

from __future__ import annotations

import re

from phishcheck.brands import Brand, is_official_host
from phishcheck.domains import hostname_of, is_ip, to_ascii_host, to_unicode_host
from phishcheck.models import Finding, Link, ParsedEmail
from phishcheck.parse import domain_of, message_id_domain
from phishcheck.rules import make_finding


# Practical homoglyphs, not the full Unicode confusables table (UTS #39).
_CONFUSABLES = str.maketrans(
    {
        "0": "o",
        "3": "e",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ѕ": "s",
        "һ": "h",
        "ј": "j",
        "ӏ": "l",
        "ԁ": "d",
        "α": "a",
        "ε": "e",
        "ι": "i",
        "κ": "k",
        "ο": "o",
        "ρ": "p",
        "τ": "t",
        "χ": "x",
        "ν": "v",
    }
)
_CONFUSABLES_ONE_AS_I = str.maketrans({"1": "i"})
_CONFUSABLES_ONE_AS_L = str.maketrans({"1": "l"})

_SUFFIXES = (
    "secure",
    "login",
    "support",
    "refund",
    "efiling",
    "account",
    "alert",
    "alerts",
    "verify",
    "banking",
    "online",
    "update",
    "service",
    "helpdesk",
    "billing",
    "payment",
    "unlock",
    "suspended",
    "reward",
    "rewards",
    "delivery",
    "customs",
    "notification",
    "notifications",
    "security",
    "express",
    "parcel",
    "shipment",
    "tracking",
    "portal",
    "centre",
    "center",
)

SUSPICIOUS_TLDS = frozenset(
    {
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "buzz",
        "click",
        "country",
        "support",
        "rest",
        "loan",
        "cam",
        "bond",
        "sbs",
        "cfd",
        "icu",
        "monster",
        "quest",
        "xyz",
        "top",
        "zip",
        "mov",
        "work",
        "email",
    }
)

_INFRA_LABELS = frozenset(
    {
        "www",
        "mail",
        "smtp",
        "mx",
        "email",
        "news",
        "bounce",
        "bounces",
        "reply",
        "noreply",
        "newsletter",
        "updates",
        "info",
        "support",
        "admin",
        "static",
        "cdn",
        "api",
        "ns",
        "ns1",
        "ns2",
        "webmail",
        "imap",
        "pop",
        "ftp",
        "mta",
        "gateway",
        "edge",
        "outbound",
        "inbound",
    }
)


def _folds(label: str) -> set[str]:
    base = label.translate(_CONFUSABLES)
    folded = {base}
    if "1" in label:
        folded.add(base.translate(_CONFUSABLES_ONE_AS_I))
        folded.add(base.translate(_CONFUSABLES_ONE_AS_L))
    return {item for item in folded if item and item != label}


def _labels(host: str) -> list[str]:
    return [label for label in to_unicode_host(host).split(".") if label]


def _token_in_label(label: str, token: str, allow_exact: bool) -> bool:
    if allow_exact and label == token:
        return True
    parts = [part for part in re.split(r"[-_]", label) if part]
    if len(parts) > 1 and token in parts:
        return True
    for suffix in _SUFFIXES:
        if label == token + suffix or label == suffix + token:
            return True
    if len(token) >= 6 and token in label and label != token:
        return True
    return False


def _brand_targets(brands: tuple[Brand, ...]) -> set[str]:
    targets: set[str] = set()
    for brand in brands:
        targets.update(brand.tokens)
        for domain in brand.domains:
            targets.add(domain.split(".", 1)[0])
    return {target for target in targets if target}


def levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, ca in enumerate(left, start=1):
        current = [i]
        for j, cb in enumerate(right, start=1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            substitute = previous[j - 1] + (ca != cb)
            current.append(min(insert, delete, substitute))
        previous = current
    return previous[-1]


def _subdomain_trick(host: str, brands: tuple[Brand, ...]) -> str | None:
    labels = _labels(host)
    for brand in brands:
        for domain in brand.domains:
            brand_labels = [part for part in domain.split(".") if part]
            width = len(brand_labels)
            if len(labels) <= width:
                continue
            for index in range(0, len(labels) - width):
                if labels[index : index + width] == brand_labels:
                    return brand.name
    return None


def _homoglyph(host: str, brands: tuple[Brand, ...], targets: set[str]) -> str | None:
    for label in _labels(host):
        for folded in _folds(label):
            if folded in targets:
                return folded
    return None


def _keyword(host: str, brands: tuple[Brand, ...]) -> str | None:
    for label in _labels(host):
        for brand in brands:
            for token in brand.tokens:
                if _token_in_label(label, token, brand.allow_exact):
                    return brand.name
    return None


def _typosquat(host: str, targets: set[str]) -> tuple[int, str] | None:
    best: tuple[int, str] | None = None
    for label in _labels(host):
        if len(label) < 5 or label in _INFRA_LABELS:
            continue
        for target in targets:
            if len(target) < 5:
                continue
            if abs(len(label) - len(target)) > 2:
                continue
            distance = levenshtein(label, target)
            if distance in {1, 2} and (best is None or distance < best[0]):
                best = (distance, target)
                if distance == 1:
                    return best
    return best


def _mixed_script(host: str) -> bool:
    for label in _labels(host):
        scripts: set[str] = set()
        for char in label:
            if not char.isalpha():
                continue
            code = ord(char)
            if code <= 0x024F:
                scripts.add("latin")
            elif 0x0370 <= code <= 0x03FF:
                scripts.add("greek")
            elif 0x0400 <= code <= 0x04FF:
                scripts.add("cyrillic")
        if len(scripts) >= 2:
            return True
    return False


def _suspicious_tld(host: str) -> bool:
    labels = _labels(host)
    if not labels:
        return False
    return labels[-1] in SUSPICIOUS_TLDS


def _describe(host: str) -> str:
    uni = to_unicode_host(host)
    if uni and any(ord(char) > 127 for char in uni):
        escaped = uni.encode("unicode_escape").decode("ascii")
        return f"{to_ascii_host(uni)} (decodes to {escaped})"
    return uni or host


def _collect_hosts(parsed: ParsedEmail, links: tuple[Link, ...]) -> list[tuple[str, str]]:
    hosts: list[tuple[str, str]] = []
    from_domain = domain_of(parsed.from_addr)
    if from_domain:
        hosts.append((from_domain, "header:from"))
    for address in parsed.reply_addrs:
        domain = domain_of(address)
        if domain:
            hosts.append((domain, "header:reply-to"))
    return_domain = domain_of(parsed.return_addr)
    if return_domain:
        hosts.append((return_domain, "header:return-path"))
    mid = message_id_domain(parsed.message_id)
    if mid:
        hosts.append((mid, "header:message-id"))
    for link in links:
        host = hostname_of(link.url)
        if host:
            hosts.append((host, f"link:{link.source}"))
    return hosts


def analyse_lookalikes(
    parsed: ParsedEmail,
    links: tuple[Link, ...],
    brands: tuple[Brand, ...],
) -> tuple[Finding, ...]:
    targets = _brand_targets(brands)
    grouped: dict[str, list[str]] = {}
    suspicious: list[str] = []

    def add(code: str, host: str) -> None:
        bucket = grouped.setdefault(code, [])
        described = _describe(host)
        if described not in bucket:
            bucket.append(described)

    seen: set[str] = set()
    for host, _context in _collect_hosts(parsed, links):
        key = to_unicode_host(host)
        if not key or is_ip(key) or key in seen:
            continue
        seen.add(key)
        if is_official_host(key, brands):
            continue
        if _subdomain_trick(key, brands):
            add("lookalike-subdomain-trick", host)
        elif _homoglyph(key, brands, targets):
            add("lookalike-homoglyph", host)
        elif _keyword(key, brands):
            add("lookalike-keyword", host)
        else:
            typo = _typosquat(key, targets)
            if typo is not None:
                code = "lookalike-typosquat" if typo[0] == 1 else "lookalike-typosquat-weak"
                add(code, host)
            elif _mixed_script(key):
                add("lookalike-mixed-script", host)
        if _suspicious_tld(key):
            described = _describe(host)
            if described not in suspicious:
                suspicious.append(described)

    findings: list[Finding] = []
    details = {
        "lookalike-homoglyph": "A domain imitates a watched brand with confusable characters or punycode.",
        "lookalike-subdomain-trick": "A watched brand's domain is placed in front of a different parent domain.",
        "lookalike-typosquat": "A domain label is one character edit from a watched brand.",
        "lookalike-typosquat-weak": "A domain label is two character edits from a watched brand.",
        "lookalike-keyword": "A domain uses a watched brand token in a lookalike name.",
        "lookalike-mixed-script": "A domain label mixes Latin letters with Cyrillic or Greek letters.",
    }
    for code, hosts in grouped.items():
        evidence = tuple(f"text:{item}" for item in hosts[:8])
        findings.append(make_finding(code, details[code], evidence=evidence))
    if suspicious:
        findings.append(
            make_finding(
                "lookalike-suspicious-tld",
                "A domain uses a top-level domain that shows up often in opportunistic phishing.",
                evidence=tuple(f"text:{item}" for item in suspicious[:8]),
            )
        )
    return tuple(findings)
