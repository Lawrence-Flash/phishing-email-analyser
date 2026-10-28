"""Point values for the heuristic checklist.

These numbers are a triage aid so a reviewer can see why a message crossed
a line. They are not a probability and they are not a detection rate.
"""

from __future__ import annotations

from dataclasses import dataclass

from phishcheck.models import Finding


@dataclass(frozen=True)
class Rule:
    analyser: str
    code: str
    points: int
    title: str
    summary: str


RULES: tuple[Rule, ...] = (
    Rule("headers", "header-reply-to-mismatch", 15, "Reply-To domain mismatch", "Reply-To domain differs from From"),
    Rule("headers", "header-return-path-mismatch", 10, "Return-Path domain mismatch", "Return-Path domain differs from From"),
    Rule("headers", "header-display-spoof", 20, "Display-name spoof", "Display name mentions a watched brand but the address is not that brand"),
    Rule("headers", "header-display-address", 18, "Display name hides a different address", "Display name contains an email address that is not the real From"),
    Rule("headers", "header-message-id-mismatch", 8, "Message-ID domain mismatch", "Message-ID domain differs from From (weak; relays do this too)"),
    Rule("headers", "header-message-id-missing", 2, "Message-ID missing", "No Message-ID header"),
    Rule("auth", "auth-spf-fail", 15, "SPF failed", "Receiving server recorded SPF fail or hardfail"),
    Rule("auth", "auth-spf-softfail", 8, "SPF softfail", "Receiving server recorded SPF softfail"),
    Rule("auth", "auth-spf-neutral", 4, "SPF neutral", "Receiving server recorded SPF neutral"),
    Rule("auth", "auth-spf-permerror", 6, "SPF permerror", "Receiving server recorded SPF permerror"),
    Rule("auth", "auth-spf-temperror", 4, "SPF temperror", "Receiving server recorded SPF temperror"),
    Rule("auth", "auth-spf-none", 3, "SPF none", "Receiving server recorded SPF none"),
    Rule("auth", "auth-spf-missing", 3, "SPF not reported", "No SPF result in Authentication-Results or Received-SPF"),
    Rule("auth", "auth-dkim-fail", 12, "DKIM failed", "Receiving server recorded DKIM fail or hardfail"),
    Rule("auth", "auth-dkim-neutral", 4, "DKIM neutral", "Receiving server recorded DKIM neutral"),
    Rule("auth", "auth-dkim-permerror", 6, "DKIM permerror", "Receiving server recorded DKIM permerror"),
    Rule("auth", "auth-dkim-temperror", 4, "DKIM temperror", "Receiving server recorded DKIM temperror"),
    Rule("auth", "auth-dkim-none", 3, "DKIM none", "Receiving server recorded DKIM none"),
    Rule("auth", "auth-dkim-missing", 3, "DKIM not reported", "No DKIM result in Authentication-Results"),
    Rule("auth", "auth-dmarc-fail", 18, "DMARC failed", "Receiving server recorded DMARC fail or hardfail"),
    Rule("auth", "auth-dmarc-neutral", 4, "DMARC neutral", "Receiving server recorded DMARC neutral"),
    Rule("auth", "auth-dmarc-permerror", 6, "DMARC permerror", "Receiving server recorded DMARC permerror"),
    Rule("auth", "auth-dmarc-temperror", 4, "DMARC temperror", "Receiving server recorded DMARC temperror"),
    Rule("auth", "auth-dmarc-none", 3, "DMARC none", "Receiving server recorded DMARC none"),
    Rule("auth", "auth-dmarc-missing", 3, "DMARC not reported", "No DMARC result in Authentication-Results"),
    Rule("lookalike", "lookalike-homoglyph", 25, "Homoglyph or punycode lookalike", "Domain uses confusable characters or punycode to imitate a brand"),
    Rule("lookalike", "lookalike-subdomain-trick", 22, "Brand domain used as a subdomain", "A watched domain appears under a different parent"),
    Rule("lookalike", "lookalike-typosquat", 18, "Typosquat (edit distance 1)", "Registrable label is one edit from a brand of 5+ characters"),
    Rule("lookalike", "lookalike-keyword", 16, "Brand keyword in domain", "Domain label contains a brand token (fnb-secure, sars-efiling)"),
    Rule("lookalike", "lookalike-typosquat-weak", 12, "Typosquat (edit distance 2)", "Registrable label is two edits from a brand of 5+ characters"),
    Rule("lookalike", "lookalike-mixed-script", 12, "Mixed-script domain label", "A label mixes Latin with Cyrillic or Greek and is not already a brand homoglyph"),
    Rule("lookalike", "lookalike-suspicious-tld", 10, "Suspicious TLD", "Domain uses a TLD often seen in opportunistic phishing"),
    Rule("links", "link-href-mismatch", 20, "Link text does not match href", "Visible text looks like a different URL or domain than the href"),
    Rule("links", "link-ip-address", 15, "URL uses an IP address", "Link host is an IPv4 or IPv6 address"),
    Rule("links", "link-script-uri", 20, "javascript: link", "href uses the javascript scheme"),
    Rule("links", "link-shortener", 10, "URL shortener", "Link host is a known shortener"),
    Rule("links", "link-credential", 12, "Credential-harvest wording in URL", "Path or query contains login, verify, password, OTP, or similar"),
    Rule("links", "link-data-uri", 25, "data: URI", "href or body contains a data URI"),
    Rule("attachments", "attachment-risky", 25, "Risky attachment type", "Executable, script, disk image, shortcut, or similar extension"),
    Rule("attachments", "attachment-double-ext", 20, "Double extension", "Filename hides a risky, HTML, or macro extension behind another suffix"),
    Rule("attachments", "attachment-macro", 18, "Macro-enabled Office file", "Macro Office extension or macroEnabled content type"),
    Rule("attachments", "attachment-html", 15, "HTML attachment", "HTML file attached (common credential-harvest wrapper)"),
    Rule("content", "content-urgency", 8, "Urgency or threat language", "Urgent, suspended-account, or act-now wording"),
    Rule("content", "content-payment-change", 15, "Payment or bank-detail change", "Asks to use a new or changed bank account"),
    Rule("content", "content-gift-card", 12, "Gift-card request", "Asks for gift cards, store credit, or airtime vouchers"),
    Rule("content", "content-sa-lure", 12, "South African lure", "SARS refund, eFiling, SASSA, NSFAS, or courier fee wording"),
    Rule("content", "content-otp", 15, "PIN or OTP request", "Asks for a PIN, OTP, or one-time password"),
)

RULES_BY_CODE: dict[str, Rule] = {rule.code: rule for rule in RULES}

SCORE_CAP = 100
VERDICT_SUSPICIOUS_AT = 25
VERDICT_PHISHING_AT = 60


def make_finding(code: str, detail: str, evidence: tuple[str, ...] = ()) -> Finding:
    rule = RULES_BY_CODE[code]
    return Finding(
        analyser=rule.analyser,
        code=rule.code,
        title=rule.title,
        detail=detail,
        points=rule.points,
        evidence=evidence,
    )


def render_scoring_table() -> str:
    """Markdown table kept in lockstep with the README."""
    lines = [
        "| Analyser | Code | Points | What it means |",
        "| --- | --- | ---: | --- |",
    ]
    for rule in RULES:
        lines.append(
            f"| {rule.analyser} | `{rule.code}` | {rule.points} | {rule.summary} |"
        )
    return "\n".join(lines)
