"""Parse an .eml file into the fields the analysers share."""

from __future__ import annotations

import hashlib
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html import unescape
from pathlib import Path

from phishcheck.domains import extract_ips, to_unicode_host
from phishcheck.models import Attachment, Hop, ParsedEmail


_POLICY = policy.default.clone(raise_on_defect=False)


def parse_path(path: str | Path) -> ParsedEmail:
    file_path = Path(path)
    data = file_path.read_bytes()
    return parse_bytes(data, path=str(path))


def parse_bytes(data: bytes, path: str = "<memory>") -> ParsedEmail:
    message = BytesParser(policy=_POLICY).parsebytes(data)
    if not isinstance(message, EmailMessage):
        # compat32 policy would return Message; default policy does not.
        raise TypeError("expected an EmailMessage")
    return _from_message(message, path)


def _addr(value: str) -> str:
    _, address = parseaddr(value or "")
    return address.strip().casefold()


def _domain(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().strip(">").casefold()


def _message_id_domain(value: str) -> str:
    match = re.search(r"@([A-Za-z0-9.-]+)", value or "")
    if not match:
        return ""
    return to_unicode_host(match.group(1))


def _parse_received(value: str, index: int) -> Hop:
    host = ""
    match = re.search(r"(?i)\bfrom\s+(\S+)", value)
    if match:
        host = match.group(1).strip("()<>").rstrip(";").strip()
        if host.startswith("[") and "]" in host:
            host = host[1 : host.index("]")]
    timestamp = ""
    if ";" in value:
        raw_date = value.rsplit(";", 1)[1].strip()
        try:
            timestamp = parsedate_to_datetime(raw_date).isoformat()
        except (TypeError, ValueError, IndexError, OverflowError):
            timestamp = raw_date
    return Hop(index=index, host=host, ips=extract_ips(value), timestamp=timestamp)


def strip_html(html: str) -> str:
    """Drop tags for the phrase scanner. Script and style bodies are removed.

    End tags allow trailing whitespace so ``</script >`` is not left behind.
    """
    text = re.sub(r"(?is)<script\b[^>]*>.*?</script[^>]*>", " ", html)
    text = re.sub(r"(?is)<style\b[^>]*>.*?</style[^>]*>", " ", text)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", unescape(text)).strip()


def _decode_text(part: EmailMessage) -> str:
    if part.get_content_maintype() == "multipart":
        return ""
    if part.get_content_maintype() != "text":
        return ""
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload(decode=False)
        return raw if isinstance(raw, str) else ""
    if isinstance(payload, str):
        return payload
    charset = part.get_content_charset() or "utf-8"
    return bytes(payload).decode(charset, errors="replace")


def _attachment_bytes(part: EmailMessage) -> bytes:
    payload = part.get_payload(decode=True)
    if payload is None:
        return b""
    if isinstance(payload, str):
        return payload.encode("utf-8", errors="replace")
    return bytes(payload)


def _is_attachment(part: EmailMessage) -> bool:
    if part.is_multipart():
        return False
    disposition = (part.get_content_disposition() or "").casefold()
    filename = part.get_filename()
    if disposition == "attachment":
        return True
    if not filename or disposition == "inline":
        return False
    return part.get_content_maintype() not in {"text", "multipart"}


def _from_message(message: EmailMessage, path: str) -> ParsedEmail:
    from_header = str(message.get("From") or "")
    from_name, from_addr = parseaddr(from_header)
    reply_header = str(message.get("Reply-To") or "")
    reply_addrs = tuple(
        addr.casefold() for _, addr in getaddresses([reply_header]) if addr
    )
    return_header = str(message.get("Return-Path") or "")
    return_addr = _addr(return_header)
    received = [str(item) for item in message.get_all("Received") or []]
    hops = tuple(_parse_received(item, index) for index, item in enumerate(received, start=1))

    body_parts: list[str] = []
    plain_parts: list[str] = []
    html_parts: list[str] = []
    scan_parts: list[str] = []
    attachments: list[Attachment] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        text = _decode_text(part)
        attached = _is_attachment(part)
        is_html = part.get_content_type() == "text/html"
        if text and is_html:
            html_parts.append(text)
            visible = strip_html(text)
        else:
            visible = text
            if text and part.get_content_type() == "text/plain":
                plain_parts.append(text)
        if visible and not attached:
            body_parts.append(visible)
        if visible:
            scan_parts.append(visible)
        if attached:
            raw = _attachment_bytes(part)
            filename = part.get_filename() or "(unnamed)"
            attachments.append(
                Attachment(
                    filename=filename,
                    content_type=part.get_content_type(),
                    size=len(raw),
                    sha256=hashlib.sha256(raw).hexdigest(),
                )
            )

    subject = str(message.get("Subject") or "")
    body_text = "\n".join(part.strip() for part in body_parts if part.strip())
    combined = "\n".join(
        piece for piece in [subject, *scan_parts] if piece and piece.strip()
    )
    sample = str(message.get("X-Phishcheck-Sample") or "")
    synthetic = "synthetic" in sample.casefold() or "SYNTHETIC SAMPLE" in combined

    return ParsedEmail(
        path=path,
        subject=subject,
        from_header=from_header,
        from_name=from_name,
        from_addr=from_addr.casefold(),
        reply_to_header=reply_header,
        reply_addrs=reply_addrs,
        return_path_header=return_header,
        return_addr=return_addr,
        message_id=str(message.get("Message-ID") or message.get("Message-Id") or ""),
        date=str(message.get("Date") or ""),
        hops=hops,
        body_text=body_text,
        plain_text="\n".join(part.strip() for part in plain_parts if part.strip()),
        html_text="\n".join(html_parts),
        combined_text=combined,
        links=(),
        attachments=tuple(attachments),
        auth_headers=tuple(str(item) for item in message.get_all("Authentication-Results") or []),
        received_spf=tuple(str(item) for item in message.get_all("Received-SPF") or []),
        synthetic=synthetic,
    )


def domain_of(address: str) -> str:
    return _domain(address)


def message_id_domain(value: str) -> str:
    return _message_id_domain(value)
