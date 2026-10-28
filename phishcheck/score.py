"""Turn findings into a capped score, a verdict, and plain-language advice."""

from __future__ import annotations

from phishcheck.models import Finding
from phishcheck.rules import SCORE_CAP, VERDICT_PHISHING_AT, VERDICT_SUSPICIOUS_AT


def verdict_for(score: int) -> str:
    if score >= VERDICT_PHISHING_AT:
        return "likely phishing"
    if score >= VERDICT_SUSPICIOUS_AT:
        return "suspicious"
    return "likely safe"


def score_findings(findings: tuple[Finding, ...] | list[Finding]) -> tuple[int, int, str]:
    """Return ``(capped score, raw score, verdict)``.

    A repeated code is counted once, using the first finding. Analysers are
    expected to emit each code a single time.
    """
    seen: set[str] = set()
    raw = 0
    for finding in findings:
        if finding.points <= 0 or finding.code in seen:
            continue
        seen.add(finding.code)
        raw += finding.points
    return min(SCORE_CAP, raw), raw, verdict_for(min(SCORE_CAP, raw))


def advice_for(verdict: str, findings: tuple[Finding, ...] | list[Finding]) -> str:
    codes = {finding.code for finding in findings if finding.points > 0}
    parts: list[str] = []
    if verdict == "likely phishing":
        parts.append(
            "Do not reply, click links, or open attachments. Report the message to your mail security team or SOC and delete it."
        )
    elif verdict == "suspicious":
        parts.append(
            "Do not click links or open attachments yet. Verify the sender through a channel you already trust, not by replying to this message."
        )
    else:
        parts.append(
            "No strong phishing signals in this checklist. If you were not expecting the message, still avoid unexpected attachments and confirm any request for money or credentials out of band."
        )
    link_codes = {
        "link-href-mismatch",
        "link-credential",
        "link-data-uri",
        "link-script-uri",
        "link-ip-address",
        "link-shortener",
    }
    if codes & link_codes:
        parts.append(
            "If you need the real service, type the address yourself or use a bookmark. Do not use a link from this message."
        )
    if any(code.startswith("attachment-") for code in codes):
        parts.append(
            "Do not open the attachment. Ask for a clean copy through a known contact if you actually need the document."
        )
    if "content-payment-change" in codes or "content-gift-card" in codes:
        parts.append(
            "Confirm any payment, bank-detail, or gift-card request by phone using a number from a trusted source, not from this email."
        )
    if "content-otp" in codes or "content-sa-lure" in codes:
        parts.append("SARS, banks, and couriers do not ask you to email a PIN or OTP. Do not share one.")
    return " ".join(parts)
