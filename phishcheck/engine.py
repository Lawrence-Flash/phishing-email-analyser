"""Run every analyser and build one result."""

from __future__ import annotations

from pathlib import Path

from phishcheck import __version__
from phishcheck.analysers.attachments import analyse_attachments
from phishcheck.analysers.auth import analyse_auth, auth_report
from phishcheck.analysers.content import analyse_content
from phishcheck.analysers.headers import analyse_headers
from phishcheck.analysers.links import analyse_links
from phishcheck.analysers.lookalike import analyse_lookalikes
from phishcheck.brands import Brand, load_brands
from phishcheck.dns_check import check_published, system_nameserver
from phishcheck.ioc import build_indicators
from phishcheck.models import AnalysisResult, Finding
from phishcheck.parse import domain_of, parse_path
from phishcheck.score import advice_for, score_findings


def analyse(
    path: str | Path,
    *,
    dns: bool = False,
    brands_path: str | None = None,
    dns_server: str | None = None,
    dns_lookup=None,
    brands: tuple[Brand, ...] | None = None,
) -> AnalysisResult:
    """Analyse one .eml file. Network is used only when ``dns`` is true."""
    parsed = parse_path(path)
    brand_list = brands if brands is not None else load_brands(brands_path)
    link_findings, links = analyse_links(parsed)
    findings: list[Finding] = []
    findings.extend(analyse_headers(parsed, brand_list))
    findings.extend(analyse_auth(parsed))
    findings.extend(analyse_lookalikes(parsed, links, brand_list))
    findings.extend(link_findings)
    findings.extend(analyse_attachments(parsed))
    findings.extend(analyse_content(parsed))
    scored = tuple(sorted((item for item in findings if item.points > 0), key=lambda item: (-item.points, item.code)))
    score, raw, verdict = score_findings(scored)
    dns_notes: tuple[Finding, ...] = ()
    if dns:
        server = dns_server or system_nameserver()
        dns_notes = check_published(
            domain_of(parsed.from_addr),
            domain_of(parsed.return_addr),
            server=server,
            lookup=dns_lookup,
        )
    return AnalysisResult(
        path=str(path),
        subject=parsed.subject,
        from_header=parsed.from_header,
        reply_to=parsed.reply_to_header,
        return_path=parsed.return_path_header,
        message_id=parsed.message_id,
        date=parsed.date,
        synthetic=parsed.synthetic,
        findings=scored,
        auth=auth_report(parsed),
        hops=parsed.hops,
        links=links,
        attachments=parsed.attachments,
        indicators=build_indicators(parsed, links, brand_list),
        dns_notes=dns_notes,
        dns_checked=dns,
        score=score,
        score_raw=raw,
        verdict=verdict,
        advice=advice_for(verdict, scored),
        version=__version__,
    )
