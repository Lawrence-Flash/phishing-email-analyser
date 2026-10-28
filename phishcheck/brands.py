"""Watched brands and optional JSON overlays.

Short tokens (fnb, mtn, sars) are matched exactly or as compounds such as
``fnb-secure``. They are not fuzzy-matched, because edit distance on a
three-letter word flags almost everything. ``--brands`` extends this list
unless the file sets ``"replace": true``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from phishcheck.domains import registrable_domain, to_unicode_host


@dataclass(frozen=True)
class Brand:
    name: str
    domains: tuple[str, ...]
    tokens: tuple[str, ...]
    display: tuple[str, ...] | None = None
    allow_exact: bool = True

    def phrases(self) -> tuple[str, ...]:
        if self.display is not None:
            return self.display
        phrases = [self.name]
        for token in self.tokens:
            if token.casefold() != self.name.casefold():
                phrases.append(token)
        return tuple(phrases)


def _brand(
    name: str,
    domains: tuple[str, ...],
    tokens: tuple[str, ...],
    display: tuple[str, ...] | None = None,
    allow_exact: bool = True,
) -> Brand:
    return Brand(
        name=name,
        domains=tuple(domain.casefold() for domain in domains),
        tokens=tuple(token.casefold() for token in tokens),
        display=display,
        allow_exact=allow_exact,
    )


DEFAULT_BRANDS: tuple[Brand, ...] = (
    _brand("FNB", ("fnb.co.za",), ("fnb",)),
    _brand("Standard Bank", ("standardbank.co.za", "standardbank.com"), ("standardbank",)),
    _brand("Absa", ("absa.co.za",), ("absa",)),
    _brand("Nedbank", ("nedbank.co.za",), ("nedbank",)),
    _brand("Capitec", ("capitecbank.co.za",), ("capitec", "capitecbank")),
    _brand("Investec", ("investec.co.za", "investec.com"), ("investec",)),
    _brand("TymeBank", ("tymebank.co.za",), ("tymebank",)),
    _brand("African Bank", ("africanbank.co.za",), ("africanbank",)),
    _brand("Bidvest Bank", ("bidvestbank.co.za",), ("bidvestbank",)),
    _brand("Discovery Bank", ("discovery.bank", "discovery.co.za"), ("discoverybank",)),
    _brand("RMB", ("rmb.co.za",), ("rmb",)),
    _brand(
        "SARS",
        ("sars.gov.za", "sarsefiling.co.za"),
        ("sars", "sarsefiling"),
        display=("sars", "sarsefiling", "south african revenue service"),
    ),
    _brand("SASSA", ("sassa.gov.za",), ("sassa",)),
    _brand("Vodacom", ("vodacom.co.za",), ("vodacom",)),
    _brand("MTN", ("mtn.co.za",), ("mtn",)),
    _brand("Telkom", ("telkom.co.za",), ("telkom",)),
    _brand("Cell C", ("cellc.co.za",), ("cellc",)),
    _brand("Rain", ("rain.co.za",), ("rain",), display=(), allow_exact=False),
    _brand("DHL", ("dhl.com", "dhl.co.za"), ("dhl",)),
    _brand("FedEx", ("fedex.com",), ("fedex",)),
    _brand("UPS", ("ups.com",), ("ups",)),
    _brand("Aramex", ("aramex.com",), ("aramex",)),
    _brand(
        "The Courier Guy",
        ("thecourierguy.co.za", "courierguy.co.za"),
        ("courierguy", "thecourierguy"),
    ),
    _brand("Fastway", ("fastway.co.za",), ("fastway",)),
    _brand("PAXI", ("paxi.co.za",), ("paxi",)),
    _brand("RAM", ("ram.co.za",), ("ram",), display=("ram couriers",), allow_exact=False),
    _brand("Takealot", ("takealot.com",), ("takealot",)),
    _brand(
        "Microsoft",
        (
            "microsoft.com",
            "office.com",
            "office365.com",
            "microsoftonline.com",
            "outlook.com",
            "live.com",
            "hotmail.com",
        ),
        ("microsoft", "office365"),
        display=("microsoft", "office 365", "office365"),
    ),
    _brand("Google", ("google.com", "gmail.com", "googlemail.com"), ("google",)),
    _brand("Apple", ("apple.com", "icloud.com", "me.com"), ("apple",)),
    _brand("Amazon", ("amazon.com", "amazon.co.za"), ("amazon",)),
    _brand("PayPal", ("paypal.com",), ("paypal",)),
    _brand("Netflix", ("netflix.com",), ("netflix",)),
    _brand("LinkedIn", ("linkedin.com",), ("linkedin",)),
    _brand(
        "Meta",
        ("facebook.com", "meta.com", "instagram.com", "whatsapp.com"),
        ("facebook", "instagram", "whatsapp", "meta"),
        display=("meta", "facebook", "instagram", "whatsapp"),
    ),
    _brand("Dropbox", ("dropbox.com",), ("dropbox",)),
    _brand("Adobe", ("adobe.com",), ("adobe",)),
)

FREE_MAIL_DOMAINS = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "msn.com",
        "yahoo.com",
        "yahoo.co.za",
        "ymail.com",
        "icloud.com",
        "me.com",
        "mac.com",
        "aol.com",
        "proton.me",
        "protonmail.com",
        "pm.me",
        "gmx.com",
        "gmx.net",
        "mail.com",
        "zoho.com",
        "yandex.com",
        "yandex.ru",
    }
)


def is_official_host(host: str, brands: tuple[Brand, ...] | None = None) -> bool:
    """True when the host is the brand domain or a subdomain of it."""
    brands = brands if brands is not None else DEFAULT_BRANDS
    uni = to_unicode_host(host)
    if not uni:
        return False
    try:
        ascii_host = uni.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_host = uni
    for brand in brands:
        for domain in brand.domains:
            for candidate in (uni, ascii_host):
                if candidate == domain or candidate.endswith("." + domain):
                    return True
    return False


def is_free_mail(host: str) -> bool:
    reg = registrable_domain(host)
    return reg in FREE_MAIL_DOMAINS or to_unicode_host(host) in FREE_MAIL_DOMAINS


def host_aligns(host: str, brand: Brand) -> bool:
    """True when the address may legitimately display this brand.

    Free mailbox domains never align, including ones the brand owns
    (gmail.com, outlook.com, icloud.com). A "Microsoft" display name on
    outlook.com is still treated as spoofing.
    """
    if not host or is_free_mail(host):
        return False
    uni = to_unicode_host(host)
    try:
        ascii_host = uni.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_host = uni
    for domain in brand.domains:
        for candidate in (uni, ascii_host):
            if candidate == domain or candidate.endswith("." + domain):
                return True
    return False


def load_brands(path: str | None) -> tuple[Brand, ...]:
    """Load brands from JSON. By default the file is added to the built-in list."""
    if not path:
        return DEFAULT_BRANDS
    file_path = Path(path)
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read brands file: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("brands"), list):
        raise ValueError("brands file must be an object with a brands array")
    loaded: list[Brand] = []
    for item in data["brands"]:
        if not isinstance(item, dict) or not item.get("name"):
            raise ValueError("each brand needs a name")
        display = item.get("display")
        loaded.append(
            _brand(
                str(item["name"]),
                tuple(item.get("domains") or ()),
                tuple(item.get("tokens") or ()),
                display=tuple(display) if display is not None else None,
                allow_exact=bool(item.get("allow_exact", True)),
            )
        )
    if not loaded:
        raise ValueError("brand file contained no brands")
    if data.get("replace") is True:
        return tuple(loaded)
    return DEFAULT_BRANDS + tuple(loaded)
