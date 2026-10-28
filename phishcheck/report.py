"""Human markdown and machine JSON for one analysis."""

from __future__ import annotations

import json

from phishcheck.defang import defang_domain, defang_embedded, defang_ip, defang_url, present_evidence
from phishcheck.ioc import present_value
from phishcheck.models import AnalysisResult, Finding
from phishcheck.rules import SCORE_CAP


def _cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def render_markdown(result: AnalysisResult) -> str:
    lines: list[str] = ["# phishcheck report", ""]
    if result.synthetic:
        lines.append(
            "This file is marked synthetic. It is a demo fixture, not a live incident."
        )
        lines.append("")
    capped = ""
    if result.score_raw != result.score:
        capped = f" (raw {result.score_raw}, capped at {SCORE_CAP})"
    lines.extend(
        [
            f"- File: {result.path}",
            f"- Subject: {_cell(defang_embedded(result.subject))}",
            f"- From: {_cell(defang_embedded(result.from_header))}",
            f"- Reply-To: {_cell(defang_embedded(result.reply_to) or '(none)')}",
            f"- Return-Path: {_cell(defang_embedded(result.return_path) or '(none)')}",
            f"- Message-ID: {_cell(defang_embedded(result.message_id) or '(none)')}",
            f"- Date: {_cell(result.date) or '(none)'}",
            f"- Score: {result.score}/{SCORE_CAP}{capped}",
            f"- Verdict: **{result.verdict}**",
            "",
            "## What to do",
            "",
            result.advice,
            "",
            "## Authentication (as recorded in headers)",
            "",
            "These values are copied from Authentication-Results and Received-SPF. "
            "phishcheck does not re-verify DKIM signatures and does not evaluate SPF "
            "against DNS unless you pass `--dns`. Even then it only fetches TXT records.",
            "",
            "| Check | Result |",
            "| --- | --- |",
            f"| SPF | {result.auth.spf} |",
            f"| DKIM | {result.auth.dkim} |",
            f"| DMARC | {result.auth.dmarc} |",
            "",
            "## Why this score",
            "",
        ]
    )
    if not result.findings:
        lines.append("No scored signals.")
        lines.append("")
    else:
        lines.extend(
            [
                "| Points | Code | Detail |",
                "| ---: | --- | --- |",
            ]
        )
        for finding in result.findings:
            evidence = "; ".join(present_evidence(item) for item in finding.evidence)
            detail = defang_embedded(finding.detail)
            if evidence:
                detail = f"{detail} Evidence: {evidence}."
            lines.append(f"| {finding.points} | `{finding.code}` | {_cell(detail)} |")
        lines.append("")

    lines.extend(["## Received chain", ""])
    if not result.hops:
        lines.append("No Received headers.")
        lines.append("")
    else:
        lines.append("Hop 1 is the first Received header, closest to the recipient.")
        lines.append("")
        lines.extend(
            [
                "| Hop | Host | IPs | Time |",
                "| ---: | --- | --- | --- |",
            ]
        )
        for hop in result.hops:
            host = defang_domain(hop.host) if hop.host else ""
            ips = ", ".join(defang_ip(ip) for ip in hop.ips)
            lines.append(f"| {hop.index} | {_cell(host)} | {_cell(ips)} | {_cell(hop.timestamp)} |")
        lines.append("")

    lines.extend(["## Links", ""])
    if not result.links:
        lines.append("No links extracted.")
        lines.append("")
    else:
        lines.extend(
            [
                "| Source | URL | Display text |",
                "| --- | --- | --- |",
            ]
        )
        for link in result.links:
            lines.append(
                f"| {link.source} | {_cell(defang_url(link.url))} | {_cell(defang_embedded(link.display))} |"
            )
        lines.append("")

    lines.extend(["## Attachments", ""])
    if not result.attachments:
        lines.append("No attachments.")
        lines.append("")
    else:
        lines.extend(
            [
                "| Name | Type | Size | SHA-256 |",
                "| --- | --- | ---: | --- |",
            ]
        )
        for item in result.attachments:
            lines.append(
                f"| {_cell(item.filename)} | {_cell(item.content_type)} | {item.size} | `{item.sha256}` |"
            )
        lines.append("")

    lines.extend(["## DNS TXT", ""])
    if not result.dns_checked:
        lines.append(
            "Not checked. Re-run with `--dns` to fetch published SPF and DMARC TXT records. "
            "That sends the domain name to a resolver. It does not change the score and it "
            "does not contact a web reputation service."
        )
        lines.append("")
    elif not result.dns_notes:
        lines.append("DNS was enabled, but there was no sender domain to query.")
        lines.append("")
    else:
        for note in result.dns_notes:
            lines.append(f"- **{note.title}.** {defang_embedded(note.detail)}")
        lines.append("")

    lines.extend(["## Indicators (defanged)", ""])
    if not result.indicators:
        lines.append("No indicators.")
        lines.append("")
    else:
        lines.extend(
            [
                "| Type | Value | Context | Reserved |",
                "| --- | --- | --- | --- |",
            ]
        )
        for item in result.indicators:
            reserved = "yes" if item.reserved else "no"
            lines.append(
                f"| {item.type} | {_cell(present_value(item))} | {_cell(item.context)} | {reserved} |"
            )
        lines.append("")

    lines.extend(
        [
            "## Limitations",
            "",
            "Heuristic checklist only. A quiet phish can score low and an odd legitimate mail can score higher. "
            "Not a mail gateway, and not a substitute for the verdict from your mail security product.",
            "",
        ]
    )
    return "\n".join(lines)


def _finding_dict(finding: Finding) -> dict[str, object]:
    return {
        "analyser": finding.analyser,
        "code": finding.code,
        "title": finding.title,
        "detail": defang_embedded(finding.detail),
        "points": finding.points,
        "evidence": [present_evidence(item) for item in finding.evidence],
    }


def render_json(result: AnalysisResult) -> str:
    payload = {
        "tool": "phishcheck",
        "version": result.version,
        "source": result.path,
        "subject": defang_embedded(result.subject),
        "from": defang_embedded(result.from_header),
        "reply_to": defang_embedded(result.reply_to),
        "return_path": defang_embedded(result.return_path),
        "message_id": defang_embedded(result.message_id),
        "date": result.date,
        "synthetic": result.synthetic,
        "score": result.score,
        "score_raw": result.score_raw,
        "score_cap": SCORE_CAP,
        "verdict": result.verdict,
        "advice": result.advice,
        "authentication_as_reported": {
            "spf": result.auth.spf,
            "dkim": result.auth.dkim,
            "dmarc": result.auth.dmarc,
            "note": "Header-reported only. DKIM signatures were not re-verified.",
        },
        "findings": [_finding_dict(finding) for finding in result.findings],
        "received": [
            {
                "hop": hop.index,
                "host": defang_domain(hop.host) if hop.host else "",
                "ips": [defang_ip(ip) for ip in hop.ips],
                "timestamp": hop.timestamp,
            }
            for hop in result.hops
        ],
        "links": [
            {
                "url": defang_url(link.url),
                "display": defang_embedded(link.display),
                "source": link.source,
            }
            for link in result.links
        ],
        "attachments": [
            {
                "filename": item.filename,
                "content_type": item.content_type,
                "size": item.size,
                "sha256": item.sha256,
            }
            for item in result.attachments
        ],
        "dns": {
            "checked": result.dns_checked,
            "notes": [_finding_dict(note) for note in result.dns_notes],
        },
        "indicators": [
            {
                "type": item.type,
                "value": present_value(item),
                "context": item.context,
                "reserved": item.reserved,
            }
            for item in result.indicators
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
