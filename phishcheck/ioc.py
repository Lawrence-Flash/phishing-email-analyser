"""Defanged IOC export for a ticket. Not a blocklist."""

from __future__ import annotations

import csv
import io
import json

from phishcheck.brands import Brand, is_official_host
from phishcheck.defang import defang_domain, defang_ip, defang_url
from phishcheck.domains import hostname_of, is_ip, is_reserved_domain, to_ascii_host
from phishcheck.models import AnalysisResult, Indicator, Link, ParsedEmail
from phishcheck.parse import domain_of, message_id_domain


def _add(
    items: list[Indicator],
    seen: set[tuple[str, str, str]],
    kind: str,
    value: str,
    context: str,
) -> None:
    value = value.strip()
    if not value:
        return
    if kind == "domain" and is_ip(value):
        kind = "ip"
    key = (kind, value.casefold(), context)
    if key in seen:
        return
    seen.add(key)
    reserved = is_reserved_domain(value) if kind in {"domain", "ip", "url"} else False
    if kind == "url":
        host = hostname_of(value)
        reserved = is_reserved_domain(host) if host else False
    items.append(Indicator(type=kind, value=value, context=context, reserved=reserved))


def build_indicators(
    parsed: ParsedEmail,
    links: tuple[Link, ...],
    brands: tuple[Brand, ...],
) -> tuple[Indicator, ...]:
    """Observed sender infrastructure, link targets, received IPs, and hashes.

    Official brand domains are left out so a lure that displays the real
    bank is not written up as a malicious indicator. Display-text URLs are
    not included; only href and naked URL targets are.
    """
    items: list[Indicator] = []
    seen: set[tuple[str, str, str]] = set()

    def consider_domain(domain: str, context: str) -> None:
        if not domain or is_ip(domain) or is_official_host(domain, brands):
            return
        _add(items, seen, "domain", to_ascii_host(domain), context)

    consider_domain(domain_of(parsed.from_addr), "header:from")
    for address in parsed.reply_addrs:
        consider_domain(domain_of(address), "header:reply-to")
    consider_domain(domain_of(parsed.return_addr), "header:return-path")
    consider_domain(message_id_domain(parsed.message_id), "header:message-id")

    for link in links:
        lowered = link.url.strip().casefold()
        if lowered.startswith("mailto:"):
            continue
        host = hostname_of(link.url)
        # The real brand site is a lure, not an indicator to block.
        if host and not is_ip(host) and is_official_host(host, brands):
            continue
        if host and not is_ip(host):
            consider_domain(host, f"link:{link.source}")
        elif host and is_ip(host):
            _add(items, seen, "ip", host, f"link:{link.source}")
        _add(items, seen, "url", link.url, f"link:{link.source}")

    for hop in parsed.hops:
        if hop.host and not is_ip(hop.host):
            consider_domain(hop.host, "received")
        for ip in hop.ips:
            _add(items, seen, "ip", ip, "received")

    for attachment in parsed.attachments:
        _add(
            items,
            seen,
            "sha256",
            attachment.sha256,
            f"attachment:{attachment.filename}",
        )
    return tuple(items)


def present_value(indicator: Indicator) -> str:
    if indicator.type == "url":
        return defang_url(indicator.value)
    if indicator.type == "domain":
        return defang_domain(indicator.value)
    if indicator.type == "ip":
        return defang_ip(indicator.value)
    return indicator.value


def indicator_dicts(result: AnalysisResult) -> list[dict[str, object]]:
    return [
        {
            "type": item.type,
            "value": present_value(item),
            "context": item.context,
            "reserved": item.reserved,
        }
        for item in result.indicators
    ]


def render_ioc_json(result: AnalysisResult) -> str:
    payload = {
        "tool": "phishcheck",
        "version": result.version,
        "source": result.path,
        "defanged": True,
        "note": (
            "Observed indicators for a ticket or a hunt. Do not load this file "
            "into a blocklist without review. Official brand domains and "
            "display-text lures are omitted. reserved=true marks documentation "
            "names and ranges."
        ),
        "indicators": indicator_dicts(result),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def render_ioc_csv(result: AnalysisResult) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["type", "value", "context", "reserved"])
    for item in result.indicators:
        writer.writerow([item.type, present_value(item), item.context, "true" if item.reserved else "false"])
    return buffer.getvalue()
