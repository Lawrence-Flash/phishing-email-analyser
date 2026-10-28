"""Header alignment: From, Reply-To, Return-Path, display name, Message-ID."""

from __future__ import annotations

import re

from phishcheck.brands import Brand, host_aligns, is_free_mail
from phishcheck.domains import different_org
from phishcheck.models import Finding, ParsedEmail
from phishcheck.parse import domain_of, message_id_domain
from phishcheck.rules import make_finding


_EMAIL_IN_NAME = re.compile(r"([^\s<>\"']+@[^\s<>\"']+)")


def _mentions(text: str, phrase: str) -> bool:
    if not phrase:
        return False
    pattern = rf"(?<![a-z0-9]){re.escape(phrase.casefold())}(?![a-z0-9])"
    return re.search(pattern, text.casefold()) is not None


def _display_brand(name: str, brands: tuple[Brand, ...]) -> Brand | None:
    for brand in brands:
        for phrase in brand.phrases():
            if _mentions(name, phrase):
                return brand
    return None


def analyse_headers(parsed: ParsedEmail, brands: tuple[Brand, ...]) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    from_domain = domain_of(parsed.from_addr)
    from_name = parsed.from_name or ""

    hidden = _EMAIL_IN_NAME.search(from_name)
    if hidden and hidden.group(1).casefold() != parsed.from_addr:
        findings.append(
            make_finding(
                "header-display-address",
                "The display name contains an email address that is not the sending address.",
                evidence=(
                    f"text:{hidden.group(1)}",
                    f"email:{parsed.from_addr}",
                ),
            )
        )

    brand = _display_brand(from_name, brands)
    if brand is not None and from_domain and not host_aligns(from_domain, brand):
        if is_free_mail(from_domain):
            detail = (
                f"The display name mentions {brand.name}, and the sender is on a free mailbox domain."
            )
        else:
            detail = (
                f"The display name mentions {brand.name}, but the sender domain is not an official domain for that brand."
            )
        findings.append(
            make_finding(
                "header-display-spoof",
                detail,
                evidence=(f"text:{from_name}", f"email:{parsed.from_addr}", f"text:{brand.name}"),
            )
        )

    if parsed.reply_addrs:
        mismatched = [
            addr for addr in parsed.reply_addrs if different_org(from_domain, domain_of(addr))
        ]
        if mismatched:
            evidence = [f"email:{parsed.from_addr}"] if parsed.from_addr else []
            evidence.extend(f"email:{addr}" for addr in mismatched)
            findings.append(
                make_finding(
                    "header-reply-to-mismatch",
                    "Reply-To uses a different organisation domain from From, so a reply may not go to the visible sender.",
                    evidence=tuple(evidence),
                )
            )

    return_domain = domain_of(parsed.return_addr)
    if return_domain and different_org(from_domain, return_domain):
        findings.append(
            make_finding(
                "header-return-path-mismatch",
                "Return-Path uses a different organisation domain from From. The bounce address does not match the visible sender.",
                evidence=(f"email:{parsed.from_addr}", f"email:{parsed.return_addr}"),
            )
        )

    if not parsed.message_id.strip():
        findings.append(
            make_finding(
                "header-message-id-missing",
                "The message has no Message-ID header.",
            )
        )
    else:
        mid_domain = message_id_domain(parsed.message_id)
        if mid_domain and different_org(from_domain, mid_domain):
            findings.append(
                make_finding(
                    "header-message-id-mismatch",
                    "The Message-ID domain does not match From. Mailing platforms sometimes do this, so it is a weak signal on its own.",
                    evidence=(f"domain:{from_domain}", f"domain:{mid_domain}"),
                )
            )

    return tuple(findings)
