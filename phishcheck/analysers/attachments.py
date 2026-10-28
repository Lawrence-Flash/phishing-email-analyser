"""Attachment name, type, and content-type risk."""

from __future__ import annotations

from phishcheck.filetypes import (
    has_double_extension,
    is_html_attachment,
    is_macro_type,
    is_risky_filename,
)
from phishcheck.models import Finding, ParsedEmail
from phishcheck.rules import make_finding


def analyse_attachments(parsed: ParsedEmail) -> tuple[Finding, ...]:
    risky: list[str] = []
    doubles: list[str] = []
    macros: list[str] = []
    htmls: list[str] = []
    for item in parsed.attachments:
        name = item.filename or "(unnamed)"
        if is_risky_filename(name):
            risky.append(name)
        if has_double_extension(name):
            doubles.append(name)
        if is_macro_type(name, item.content_type):
            macros.append(name)
        if is_html_attachment(name, item.content_type):
            htmls.append(name)

    findings: list[Finding] = []
    if risky:
        findings.append(
            make_finding(
                "attachment-risky",
                "An attachment uses an extension that can run code or mount a disk image.",
                evidence=tuple(f"file:{name}" for name in risky[:8]),
            )
        )
    if doubles:
        findings.append(
            make_finding(
                "attachment-double-ext",
                "An attachment hides a dangerous extension behind another suffix.",
                evidence=tuple(f"file:{name}" for name in doubles[:8]),
            )
        )
    if macros:
        findings.append(
            make_finding(
                "attachment-macro",
                "An attachment is a macro-enabled Office document.",
                evidence=tuple(f"file:{name}" for name in macros[:8]),
            )
        )
    if htmls:
        findings.append(
            make_finding(
                "attachment-html",
                "An HTML attachment can show a fake login page when it is opened.",
                evidence=tuple(f"file:{name}" for name in htmls[:8]),
            )
        )
    return tuple(findings)
