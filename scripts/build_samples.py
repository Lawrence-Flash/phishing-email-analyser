"""Write the synthetic .eml fixtures. Run from the repo root:

    python3 scripts/build_samples.py
"""

from __future__ import annotations

import base64
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"

BANNER = (
    "SYNTHETIC SAMPLE. Not a real email. Created for the phishcheck demo. "
    "Domains are under .example (RFC 2606) or example.com/net/org, and IP "
    "addresses are in documentation ranges (RFC 5737). Do not treat this file "
    "as a live incident."
)

PDF_BYTES = b"%PDF-1.4\nsynthetic phishcheck fixture\n%%EOF\n"
EXE_BYTES = b"synthetic phishcheck fixture, not a program\n"
MACRO_BYTES = b"synthetic phishcheck macro fixture, not a document\n"
HTML_BYTES = b"<html><body>SYNTHETIC tracking page for a lab only.</body></html>\n"


def b64(payload: bytes) -> str:
    return base64.encodebytes(payload).decode("ascii").rstrip("\n")


def received(host: str, ip: str, by: str) -> str:
    return (
        f"Received: from {host} ({host} [{ip}]) by {by} with ESMTPS id synthetic; "
        "Wed, 28 Oct 2026 08:15:00 +0200"
    )


def auth(spf: str, dkim: str, dmarc: str, mail_from: str, header_from: str) -> str:
    return (
        "Authentication-Results: mx.example.com; "
        f"spf={spf} smtp.mailfrom={mail_from}; "
        f"dkim={dkim} header.d={header_from}; "
        f"dmarc={dmarc} header.from={header_from}"
    )


def single(headers: list[str], body: str) -> str:
    return "\n".join(headers) + "\n\n" + body.rstrip() + "\n"


def alternative(headers: list[str], text: str, html: str, boundary: str) -> str:
    headers = headers + [f'Content-Type: multipart/alternative; boundary="{boundary}"']
    return (
        "\n".join(headers)
        + "\n\n"
        + f"--{boundary}\n"
        + "Content-Type: text/plain; charset=utf-8\n"
        + "Content-Transfer-Encoding: 8bit\n\n"
        + text.rstrip()
        + "\n\n"
        + f"--{boundary}\n"
        + "Content-Type: text/html; charset=utf-8\n"
        + "Content-Transfer-Encoding: 8bit\n\n"
        + html.rstrip()
        + "\n\n"
        + f"--{boundary}--\n"
    )


def mixed(headers: list[str], text: str, parts: list[str], boundary: str) -> str:
    headers = headers + [f'Content-Type: multipart/mixed; boundary="{boundary}"']
    chunks = ["\n".join(headers) + "\n", f"--{boundary}"]
    chunks.append("Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n")
    chunks.append(text.rstrip() + "\n")
    for part in parts:
        chunks.append(f"--{boundary}")
        chunks.append(part.rstrip() + "\n")
    chunks.append(f"--{boundary}--\n")
    return "\n".join(chunks)


def attachment(filename: str, content_type: str, payload: bytes) -> str:
    encoded = b64(payload)
    return (
        f'Content-Type: {content_type}; name="{filename}"\n'
        f'Content-Disposition: attachment; filename="{filename}"\n'
        "Content-Transfer-Encoding: base64\n\n"
        f"{encoded}\n"
    )


def base_headers(**kwargs: str) -> list[str]:
    headers = [
        "X-Phishcheck-Sample: synthetic",
        "X-Phishcheck-Warning: Synthetic fixture. Not a real email.",
        "MIME-Version: 1.0",
        "Date: Wed, 28 Oct 2026 08:15:00 +0200",
    ]
    order = ("From", "To", "Reply-To", "Return-Path", "Message-ID", "Subject")
    for key in order:
        if key in kwargs:
            headers.append(f"{key}: {kwargs[key]}")
    return headers


def build() -> dict[str, str]:
    colleague = single(
        base_headers(
            **{
                "From": "Alex Example <alex@example.com>",
                "To": "Sam Example <sam@example.com>",
                "Reply-To": "Alex Example <alex@example.com>",
                "Return-Path": "<alex@example.com>",
                "Message-ID": "<lunch-20261028@example.com>",
                "Subject": "Lunch on Friday",
            }
        )
        + [received("mail.example.com", "203.0.113.10", "mx.example.net")],
        f"{BANNER}\n\nHi Sam, are you free for lunch on Friday at 12:30? The cafe downstairs is fine.\n",
    )

    newsletter = single(
        base_headers(
            **{
                "From": "Team News <team@news.example>",
                "To": "Alex Example <alex@example.com>",
                "Reply-To": "Team News <team@news.example>",
                "Return-Path": "<bounces@news.example>",
                "Message-ID": "<oct-2026@news.example>",
                "Subject": "October project update",
            }
        )
        + [
            auth("pass", "pass", "pass", "news.example", "news.example"),
            "Received-SPF: pass (example.com: synthetic) client-ip=203.0.113.10;",
            received("mail.news.example", "203.0.113.10", "mx.example.net"),
        ],
        (
            f"{BANNER}\n\n"
            "Hello team, the October note is below. The deploy window is Thursday 10:00 SAST. "
            "Reply on the thread if you want a calendar invite.\n\n"
            "https://news.example/2026/10/team-update\n"
        ),
    )

    invoice = mixed(
        base_headers(
            **{
                "From": "Example Billing <billing@example.net>",
                "To": "Accounts <accounts@example.com>",
                "Reply-To": "Example Billing <billing@example.net>",
                "Return-Path": "<billing@example.net>",
                "Message-ID": "<invoice-1042@example.net>",
                "Subject": "Invoice 1042",
            }
        )
        + [
            auth("pass", "pass", "pass", "example.net", "example.net"),
            received("mail.example.net", "198.51.100.20", "mx.example.com"),
        ],
        (
            f"{BANNER}\n\n"
            "Please find invoice 1042 attached. Payment is due within 30 days on the account you already have on file.\n\n"
            "https://example.net/invoices/1042\n"
        ),
        [attachment("statement.pdf", "application/pdf", PDF_BYTES)],
        "sample-03",
    )

    fnb_text = (
        f"{BANNER}\n\n"
        "Urgent: your FNB account is suspended. Verify your account immediately. "
        "Confirm the new bank account within 24 hours.\n\n"
        "http://fnb-secure.example/login/verify\n"
    )
    fnb_html = (
        "<html><body><p>Urgent: your FNB account is suspended. Verify your account immediately. "
        "Confirm the new bank account within 24 hours.</p>"
        '<p><a href="http://fnb-secure.example/login/verify">https://www.fnb.co.za/online/login</a></p>'
        "</body></html>"
    )
    fnb = alternative(
        base_headers(
            **{
                "From": "FNB Support <alerts@fnb-secure.example>",
                "To": "Customer <customer@example.com>",
                "Reply-To": "FNB Support <helpdesk@example.com>",
                "Return-Path": "<bounce@example.net>",
                "Message-ID": "<alert-1@mail.example>",
                "Subject": "FNB account suspended",
            }
        )
        + [
            auth("fail", "fail", "fail", "fnb-secure.example", "fnb-secure.example"),
            "Received-SPF: fail (example.com: synthetic) client-ip=198.51.100.20;",
            received("mail.fnb-secure.example", "198.51.100.20", "mx.example.com"),
        ],
        fnb_text,
        fnb_html,
        "sample-04",
    )

    sars_text = (
        f"{BANNER}\n\n"
        "Your SARS refund is waiting on eFiling. Enter the OTP within 24 hours or the refund will be cancelled.\n\n"
        "http://xn--srs-6cd.example/efiling/login\n"
    )
    sars_html = (
        "<html><body><p>Your SARS refund is waiting on eFiling. Enter the OTP within 24 hours "
        "or the refund will be cancelled.</p>"
        '<p><a href="http://xn--srs-6cd.example/efiling/login">https://www.sars.gov.za/efiling</a></p>'
        "</body></html>"
    )
    sars = alternative(
        base_headers(
            **{
                "From": "SARS eFiling <refunds@sars-efiling.example>",
                "To": "Taxpayer <taxpayer@example.com>",
                "Reply-To": "SARS eFiling <refunds@sars-efiling.example>",
                "Return-Path": "<bounce@sars-efiling.example>",
                "Message-ID": "<refund-1@sars-efiling.example>",
                "Subject": "SARS refund waiting on eFiling",
            }
        )
        + [
            auth("softfail", "none", "fail", "sars-efiling.example", "sars-efiling.example"),
            "Received-SPF: softfail (example.com: synthetic) client-ip=198.51.100.20;",
            received("mail.sars-efiling.example", "198.51.100.20", "mx.example.com"),
        ],
        sars_text,
        sars_html,
        "sample-05",
    )

    delivery = mixed(
        base_headers(
            **{
                "From": "DHL Express <notices@example.com>",
                "To": "Resident <resident@example.net>",
                "Reply-To": "Fees <fees@example.net>",
                "Return-Path": "<>",
                "Message-ID": "<parcel-1@mail.example>",
                "Subject": "Delivery fee due for your parcel",
            }
        )
        + [received("mail.example.com", "203.0.113.10", "mx.example.net")],
        (
            f"{BANNER}\n\n"
            "Your parcel is held. Pay the delivery fee within 24 hours to release your shipment.\n\n"
            "http://203.0.113.50/parcel/release\n"
        ),
        [attachment("tracking.html", "text/html", HTML_BYTES)],
        "sample-06",
    )

    gift = single(
        base_headers(
            **{
                "From": "Finance Director <director@example.com>",
                "To": "Alex Example <alex@example.com>",
                "Reply-To": "Cards <giftcards@example.net>",
                "Return-Path": "<bounce@example.org>",
                "Message-ID": "<gc-1@mail.example>",
                "Subject": "Need gift cards today",
            }
        )
        + [
            auth("pass", "pass", "pass", "example.com", "example.com"),
            received("mail.example.com", "192.0.2.15", "mx.example.net"),
        ],
        (
            f"{BANNER}\n\n"
            "URGENT: I need you to buy two Google Play gift cards and send me the PIN codes right away. "
            "Do not call me, I am in a meeting.\n"
        ),
    )

    malware = mixed(
        base_headers(
            **{
                "From": "Standard Bank Accounts <billing@standardbnk.example>",
                "To": "Accounts <accounts@example.com>",
                "Reply-To": "Payments <pay@example.com>",
                "Return-Path": "<billing@standardbnk.example>",
                "Message-ID": "<inv-7781@standardbnk.example>",
                "Subject": "Updated banking details for invoice 7781",
            }
        )
        + [
            auth("fail", "fail", "fail", "standardbnk.example", "standardbnk.example"),
            received("mail.standardbnk.example", "198.51.100.20", "mx.example.com"),
        ],
        (
            f"{BANNER}\n\n"
            "Our banking details have changed. Pay this invoice immediately from the new bank account.\n"
        ),
        [
            attachment("invoice.pdf.exe", "application/octet-stream", EXE_BYTES),
            attachment("payment.docm", "application/vnd.ms-word.document.macroEnabled.12", MACRO_BYTES),
        ],
        "sample-08",
    )

    return {
        "01-legit-colleague.eml": colleague,
        "02-legit-newsletter.eml": newsletter,
        "03-legit-invoice-pdf.eml": invoice,
        "04-phish-fnb-display-spoof.eml": fnb,
        "05-phish-sars-refund.eml": sars,
        "06-phish-delivery-fee.eml": delivery,
        "07-phish-giftcard-otp.eml": gift,
        "08-phish-invoice-attachment.eml": malware,
    }


def main() -> None:
    SAMPLES.mkdir(parents=True, exist_ok=True)
    for name, content in build().items():
        path = SAMPLES / name
        path.write_text(content, encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
