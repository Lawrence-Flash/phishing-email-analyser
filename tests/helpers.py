"""Build .eml messages in tests."""

from __future__ import annotations

from email.message import EmailMessage
from email.policy import default as default_policy

from phishcheck.models import ParsedEmail
from phishcheck.parse import parse_bytes


POLICY = default_policy.clone(max_line_length=998)


def message(
    *,
    sender: str = "Alex Example <alex@example.com>",
    to: str = "Sam Example <sam@example.com>",
    subject: str = "Hello",
    body: str = "Hello",
    html: str | None = None,
    extra_headers: list[tuple[str, str]] | None = None,
    attachments: list[tuple[str, str, bytes]] | None = None,
    message_id: str = "<1@example.com>",
    reply_to: str | None = None,
    return_path: str | None = None,
) -> bytes:
    msg = EmailMessage(policy=POLICY)
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = "Wed, 28 Oct 2026 08:15:00 +0200"
    msg["Message-ID"] = message_id
    if reply_to is not None:
        msg["Reply-To"] = reply_to
    if return_path is not None:
        msg["Return-Path"] = return_path
    for name, value in extra_headers or []:
        msg[name] = value
    msg.set_content(body)
    if html is not None:
        msg.add_alternative(html, subtype="html")
    for filename, content_type, payload in attachments or []:
        main, _, sub = content_type.partition("/")
        msg.add_attachment(payload, maintype=main, subtype=sub or "octet-stream", filename=filename)
    return msg.as_bytes()


def parsed(**kwargs) -> ParsedEmail:
    return parse_bytes(message(**kwargs), path="<memory>")


def codes(findings) -> set[str]:
    return {finding.code for finding in findings if finding.points > 0}
