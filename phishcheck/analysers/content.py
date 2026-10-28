"""Body and subject phrases: urgency, payments, gift cards, SA lures, OTP."""

from __future__ import annotations

import re

from phishcheck.models import Finding, ParsedEmail
from phishcheck.rules import make_finding


_GROUPS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "content-urgency",
        "The subject or body pressures the reader to act quickly or threatens the account.",
        (
            r"(?<!not )(?<!never )\burgent(?:ly)?\b",
            r"\bimmediately\b",
            r"\bact now\b",
            r"\bright away\b",
            r"\basap\b",
            r"within 24 hours",
            r"within 48 hours",
            r"account (?:has been |will be |is )?suspended",
            r"final notice",
            r"limited time",
            r"last warning",
            r"failure to (?:respond|comply|verify)",
            r"verify your account",
            r"unusual activity",
            r"unauthori[sz]ed (?:login|access|transaction)",
            r"\bdringend\b",
            r"rekening (?:is |was )?(?:opgeskort|gesluit|geskors)",
        ),
    ),
    (
        "content-payment-change",
        "The message asks for a new or changed bank account or payment detail.",
        (
            r"banking details (?:have|has) changed",
            r"bank details (?:have|has) changed",
            r"new bank account",
            r"change of bank",
            r"account number has changed",
            r"payment details have changed",
            r"update your (?:bank|payment) details",
            r"updated? (?:bank|payment) details",
        ),
    ),
    (
        "content-gift-card",
        "The message asks for gift cards or airtime vouchers.",
        (
            r"gift ?cards?",
            r"google play",
            r"\bitunes\b",
            r"steam cards?",
            r"airtime vouchers?",
        ),
    ),
    (
        "content-sa-lure",
        "The message uses a lure that is common in South African phishing.",
        (
            r"sars refund",
            r"tax refund",
            r"\befiling\b",
            r"e-filing",
            r"belastingterugbetaling",
            r"sassa (?:grant|payment|srd)",
            r"\bnsfas\b",
            r"uif (?:claim|payment)",
            r"delivery fee",
            r"customs fee",
            r"courier fee",
            r"parcel fee",
            r"afleweringskoste",
            r"doeanegelde",
            r"release your (?:parcel|package|shipment)",
        ),
    ),
    (
        "content-otp",
        "The message asks for a PIN, OTP, or one-time password.",
        (
            r"\botp\b",
            r"one[- ]time (?:pin|password|passcode)",
            r"\bpin codes?\b",
            r"enter (?:the |your )?pin\b",
            r"eenmalige (?:pin|wagwoord)",
        ),
    ),
)


def _matches(text: str, pattern: str) -> list[str]:
    return [match.group(0) for match in re.finditer(pattern, text, flags=re.IGNORECASE)]


def analyse_content(parsed: ParsedEmail) -> tuple[Finding, ...]:
    text = parsed.combined_text or ""
    findings: list[Finding] = []
    for code, detail, patterns in _GROUPS:
        evidence: list[str] = []
        seen: set[str] = set()
        for pattern in patterns:
            for hit in _matches(text, pattern):
                key = hit.casefold()
                if key in seen:
                    continue
                seen.add(key)
                evidence.append(hit)
                if len(evidence) >= 5:
                    break
            if len(evidence) >= 5:
                break
        if evidence:
            findings.append(
                make_finding(
                    code,
                    detail,
                    evidence=tuple(f"text:{item}" for item in evidence),
                )
            )
    return tuple(findings)
