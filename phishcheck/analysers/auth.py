"""Read SPF, DKIM, and DMARC results that a receiver already wrote down.

Nothing in this module checks a DKIM signature or walks an SPF record.
``pass`` means the header says pass.
"""

from __future__ import annotations

import re

from phishcheck.models import AuthReport, Finding, ParsedEmail
from phishcheck.rules import make_finding


_RESULT_RE = re.compile(
    r"(?i)\b(spf|dkim|dmarc)\s*=\s*([a-z0-9]+)\b"
)
_SPF_LEAD_RE = re.compile(
    r"(?i)^\s*(pass|fail|hardfail|softfail|neutral|none|temperror|permerror|bestguesspass)\b"
)

_MECHANISMS = ("spf", "dkim", "dmarc")

# Result word -> rule code. hardfail shares the fail code.
_RESULT_CODES: dict[str, dict[str, str]] = {
    "spf": {
        "fail": "auth-spf-fail",
        "hardfail": "auth-spf-fail",
        "softfail": "auth-spf-softfail",
        "neutral": "auth-spf-neutral",
        "permerror": "auth-spf-permerror",
        "temperror": "auth-spf-temperror",
        "none": "auth-spf-none",
    },
    "dkim": {
        "fail": "auth-dkim-fail",
        "hardfail": "auth-dkim-fail",
        "neutral": "auth-dkim-neutral",
        "permerror": "auth-dkim-permerror",
        "temperror": "auth-dkim-temperror",
        "none": "auth-dkim-none",
    },
    "dmarc": {
        "fail": "auth-dmarc-fail",
        "hardfail": "auth-dmarc-fail",
        "neutral": "auth-dmarc-neutral",
        "permerror": "auth-dmarc-permerror",
        "temperror": "auth-dmarc-temperror",
        "none": "auth-dmarc-none",
    },
}

_MISSING = {
    "spf": "auth-spf-missing",
    "dkim": "auth-dkim-missing",
    "dmarc": "auth-dmarc-missing",
}


def parse_auth_results(
    auth_headers: tuple[str, ...] | list[str],
    received_spf: tuple[str, ...] | list[str],
) -> dict[str, str]:
    """Return the first recorded result for spf, dkim, and dmarc."""
    found: dict[str, str] = {}
    for header in auth_headers:
        for match in _RESULT_RE.finditer(header):
            mechanism = match.group(1).lower()
            result = match.group(2).lower()
            found.setdefault(mechanism, result)
    if "spf" not in found:
        for header in received_spf:
            match = _SPF_LEAD_RE.match(header.strip())
            if match:
                found["spf"] = match.group(1).lower()
                break
    return found


def analyse_auth(parsed: ParsedEmail) -> tuple[Finding, ...]:
    found = parse_auth_results(parsed.auth_headers, parsed.received_spf)
    findings: list[Finding] = []
    for mechanism in _MECHANISMS:
        result = found.get(mechanism)
        if result is None:
            findings.append(
                make_finding(
                    _MISSING[mechanism],
                    f"No {mechanism.upper()} result was recorded in the headers. Absence is weak evidence on its own.",
                )
            )
            continue
        code = _RESULT_CODES[mechanism].get(result)
        if code is None:
            # pass, bestguesspass, or an unrecognised token: report it, do not score it.
            continue
        findings.append(
            make_finding(
                code,
                (
                    f"The message headers record {mechanism.upper()}={result}. "
                    "phishcheck is quoting that header. It did not re-check the result."
                ),
                evidence=(f"text:{mechanism}={result}",),
            )
        )
    return tuple(findings)


def auth_report(parsed: ParsedEmail) -> AuthReport:
    found = parse_auth_results(parsed.auth_headers, parsed.received_spf)
    return AuthReport(
        spf=found.get("spf", "missing"),
        dkim=found.get("dkim", "missing"),
        dmarc=found.get("dmarc", "missing"),
    )
