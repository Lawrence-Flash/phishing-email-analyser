"""Shared records for a parsed message and its analysis."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    """One heuristic signal. Points of zero are notes, not score contributors."""

    analyser: str
    code: str
    title: str
    detail: str
    points: int
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class Hop:
    """One Received header, in the order it appears (nearest hop first)."""

    index: int
    host: str
    ips: tuple[str, ...]
    timestamp: str


@dataclass(frozen=True)
class Link:
    url: str
    display: str
    source: str


@dataclass(frozen=True)
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass(frozen=True)
class AuthReport:
    """Authentication status copied from headers, not re-computed."""

    spf: str
    dkim: str
    dmarc: str


@dataclass(frozen=True)
class Indicator:
    """An observed IOC. ``value`` is raw; output writers defang it."""

    type: str
    value: str
    context: str
    reserved: bool = False


@dataclass(frozen=True)
class ParsedEmail:
    path: str
    subject: str
    from_header: str
    from_name: str
    from_addr: str
    reply_to_header: str
    reply_addrs: tuple[str, ...]
    return_path_header: str
    return_addr: str
    message_id: str
    date: str
    hops: tuple[Hop, ...]
    body_text: str
    plain_text: str
    html_text: str
    combined_text: str
    links: tuple[Link, ...]
    attachments: tuple[Attachment, ...]
    auth_headers: tuple[str, ...]
    received_spf: tuple[str, ...]
    synthetic: bool


@dataclass(frozen=True)
class AnalysisResult:
    path: str
    subject: str
    from_header: str
    reply_to: str
    return_path: str
    message_id: str
    date: str
    synthetic: bool
    findings: tuple[Finding, ...]
    auth: AuthReport
    hops: tuple[Hop, ...]
    links: tuple[Link, ...]
    attachments: tuple[Attachment, ...]
    indicators: tuple[Indicator, ...]
    dns_notes: tuple[Finding, ...]
    dns_checked: bool
    score: int
    score_raw: int
    verdict: str
    advice: str
    version: str
