"""Optional DNS TXT lookups for published SPF and DMARC records.

Used only when ``--dns`` is set. A published record is not evaluated against
the sending IP, and ``include:`` mechanisms are not followed. DKIM public
keys are not fetched.
"""

from __future__ import annotations

import re
import shutil
import socket
import struct
import subprocess
from pathlib import Path

from phishcheck.domains import is_reserved_domain, registrable_domain, to_ascii_host
from phishcheck.models import Finding


class DnsError(Exception):
    """A TXT lookup could not be completed."""


_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_SERVER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.:-]{0,252}[A-Za-z0-9])?$|^[A-Za-z0-9]$")


def validate_name(name: str) -> str:
    """Reject names that could be read as dig options or are not hostnames."""
    candidate = name.strip().rstrip(".").casefold()
    if not candidate or candidate.startswith("-") or ".." in f".{candidate}.":
        raise DnsError("unsafe DNS name")
    labels = candidate.split(".")
    if any(not _LABEL_RE.fullmatch(label) for label in labels):
        raise DnsError("unsafe DNS name")
    return candidate


def validate_server(server: str) -> str:
    candidate = server.strip()
    if not candidate or candidate.startswith("-") or not _SERVER_RE.fullmatch(candidate):
        raise DnsError("unsafe resolver address")
    return candidate


def system_nameserver(resolv_path: str = "/etc/resolv.conf") -> str:
    """First IPv4 nameserver in resolv.conf, otherwise 1.1.1.1."""
    try:
        text = Path(resolv_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "1.1.1.1"
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2 and parts[0] == "nameserver" and ":" not in parts[1]:
            return parts[1]
    return "1.1.1.1"


def build_query(name: str, tid: int = 0x1234, qtype: int = 16) -> bytes:
    name = validate_name(name)
    header = struct.pack("!HHHHHH", tid & 0xFFFF, 0x0100, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack("!HH", qtype, 1)
    return header + question


def _encode_name(name: str) -> bytes:
    encoded = b""
    for label in name.split("."):
        raw = label.encode("ascii")
        encoded += bytes([len(raw)]) + raw
    return encoded + b"\x00"


def _skip_name(data: bytes, offset: int) -> int:
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DnsError("truncated name pointer")
            return offset + 2
        offset += 1 + length
    raise DnsError("truncated DNS name")


def _decode_txt(rdata: bytes) -> str:
    parts: list[str] = []
    index = 0
    while index < len(rdata):
        length = rdata[index]
        index += 1
        parts.append(rdata[index : index + length].decode("utf-8", errors="replace"))
        index += length
    return "".join(parts)


def parse_txt_response(data: bytes, expected_tid: int | None = None) -> list[str]:
    if len(data) < 12:
        raise DnsError("short DNS response")
    tid, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if expected_tid is not None and tid != (expected_tid & 0xFFFF):
        raise DnsError("DNS transaction id mismatch")
    if flags & 0x0200:
        raise DnsError("truncated UDP response")
    rcode = flags & 0x000F
    if rcode == 3:
        return []
    if rcode != 0:
        raise DnsError(f"DNS rcode {rcode}")
    offset = 12
    for _ in range(qdcount):
        offset = _skip_name(data, offset)
        offset += 4
    texts: list[str] = []
    for _ in range(ancount):
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            raise DnsError("truncated DNS answer")
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlen]
        offset += rdlen
        if rtype == 16:
            texts.append(_decode_txt(rdata))
    return texts


def query_txt_stdlib(
    name: str,
    server: str,
    timeout: float = 3.0,
    tid: int = 0x1234,
    port: int = 53,
) -> list[str]:
    packet = build_query(name, tid=tid)
    server = validate_server(server)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, port))
        data, _addr = sock.recvfrom(4096)
    return parse_txt_response(data, expected_tid=tid)


def parse_dig_output(stdout: str) -> list[str]:
    records: list[str] = []
    for line in stdout.splitlines():
        text = line.strip()
        if not text:
            continue
        if text.startswith('"') and text.endswith('"') and len(text) >= 2:
            text = text[1:-1]
        # dig splits long TXT into adjacent quoted strings.
        text = text.replace('" "', "")
        records.append(text)
    return records


def dig_txt(name: str, server: str, timeout: float = 5.0) -> list[str]:
    name = validate_name(name)
    server = validate_server(server)
    try:
        completed = subprocess.run(
            ["dig", f"@{server}", "+short", "+time=3", "+tries=1", "TXT", name],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DnsError(str(exc)) from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or f"dig exited {completed.returncode}"
        raise DnsError(detail)
    return parse_dig_output(completed.stdout)


def lookup_txt(name: str, server: str, timeout: float = 3.0) -> tuple[list[str], str]:
    """Return ``(records, transport)`` using dig when it is installed."""
    if shutil.which("dig"):
        return dig_txt(name, server, timeout=max(timeout, 5.0)), "dig"
    return query_txt_stdlib(name, server, timeout=timeout), "stdlib"


def _note(code: str, title: str, detail: str) -> Finding:
    return Finding(
        analyser="dns",
        code=code,
        title=title,
        detail=detail,
        points=0,
        evidence=(),
    )


def _spf_record(records: list[str]) -> str:
    for record in records:
        if record.lower().startswith("v=spf1"):
            return record
    return ""


def _dmarc_record(records: list[str]) -> str:
    for record in records:
        if record.lower().startswith("v=dmarc1"):
            return record
    return ""


def _dmarc_policy(record: str) -> str:
    match = re.search(r"(?i)\bp\s*=\s*(none|quarantine|reject)\b", record)
    return match.group(1).lower() if match else ""


def check_published(
    from_domain: str,
    return_domain: str = "",
    *,
    server: str,
    lookup=None,
) -> tuple[Finding, ...]:
    """Fetch SPF and DMARC TXT records for the From domain and, if different, Return-Path."""
    lookup = lookup or lookup_txt
    domains: list[str] = []
    for domain in (from_domain, return_domain):
        ascii_name = to_ascii_host(registrable_domain(domain)) if domain else ""
        if ascii_name and ascii_name not in domains:
            domains.append(ascii_name)
    notes: list[Finding] = []
    for domain in domains:
        reserved = " This name is reserved for documentation." if is_reserved_domain(domain) else ""
        try:
            spf_records, transport = lookup(domain, server)
            spf = _spf_record(spf_records)
        except DnsError as exc:
            notes.append(
                _note(
                    "dns-spf",
                    "SPF TXT lookup failed",
                    f"SPF TXT lookup for {domain} failed ({exc}). No points were added.",
                )
            )
            spf = ""
            transport = ""
        else:
            if spf:
                notes.append(
                    _note(
                        "dns-spf",
                        "Published SPF record",
                        (
                            f"{domain} publishes an SPF record via {transport}. "
                            "The record was fetched and not evaluated against the sending IP, "
                            f"and include: mechanisms were not followed.{reserved}"
                        ),
                    )
                )
            else:
                notes.append(
                    _note(
                        "dns-spf",
                        "No published SPF record",
                        (
                            f"No SPF TXT record was published at {domain} ({transport}). "
                            f"This does not change the score.{reserved}"
                        ),
                    )
                )
        dmarc_name = f"_dmarc.{domain}"
        try:
            dmarc_records, dmarc_transport = lookup(dmarc_name, server)
            dmarc = _dmarc_record(dmarc_records)
        except DnsError as exc:
            notes.append(
                _note(
                    "dns-dmarc",
                    "DMARC TXT lookup failed",
                    f"DMARC TXT lookup for {dmarc_name} failed ({exc}). No points were added.",
                )
            )
            continue
        if dmarc:
            policy = _dmarc_policy(dmarc)
            policy_text = f" Published policy p={policy}." if policy else ""
            notes.append(
                _note(
                    "dns-dmarc",
                    "Published DMARC record",
                    (
                        f"{dmarc_name} publishes a DMARC record via {dmarc_transport}.{policy_text} "
                        "phishcheck did not apply that policy to this message."
                    ),
                )
            )
        else:
            notes.append(
                _note(
                    "dns-dmarc",
                    "No published DMARC record",
                    (
                        f"No DMARC TXT record was published at {dmarc_name} ({dmarc_transport}). "
                        "This does not change the score."
                    ),
                )
            )
    return tuple(notes)
