"""From, Reply-To, Return-Path, display name, and Message-ID."""

import unittest

from phishcheck.analysers.headers import analyse_headers
from phishcheck.brands import DEFAULT_BRANDS
from tests.helpers import codes, parsed


class HeaderTests(unittest.TestCase):
    def test_aligned_mail_has_no_header_findings(self) -> None:
        mail = parsed(
            sender="Alex Example <alex@example.com>",
            reply_to="Alex Example <alex@example.com>",
            return_path="<alex@example.com>",
            message_id="<lunch@example.com>",
        )
        self.assertEqual(codes(analyse_headers(mail, DEFAULT_BRANDS)), set())

    def test_subdomain_return_path_matches(self) -> None:
        mail = parsed(
            sender="News <news@example.com>",
            return_path="<bounces@mail.example.com>",
            reply_to="News <news@example.com>",
            message_id="<1@example.com>",
        )
        self.assertNotIn("header-return-path-mismatch", codes(analyse_headers(mail, DEFAULT_BRANDS)))

    def test_reply_to_and_return_path_mismatch(self) -> None:
        mail = parsed(
            sender="FNB Support <alerts@fnb-secure.example>",
            reply_to="Help <help@example.net>",
            return_path="<bounce@example.org>",
            message_id="<1@fnb-secure.example>",
        )
        found = codes(analyse_headers(mail, DEFAULT_BRANDS))
        self.assertIn("header-reply-to-mismatch", found)
        self.assertIn("header-return-path-mismatch", found)
        self.assertIn("header-display-spoof", found)

    def test_empty_return_path_is_not_a_mismatch(self) -> None:
        mail = parsed(return_path="<>", message_id="<1@example.com>")
        self.assertNotIn("header-return-path-mismatch", codes(analyse_headers(mail, DEFAULT_BRANDS)))

    def test_official_brand_display_name_is_clean(self) -> None:
        mail = parsed(
            sender="FNB <statements@fnb.co.za>",
            message_id="<1@fnb.co.za>",
        )
        self.assertNotIn("header-display-spoof", codes(analyse_headers(mail, DEFAULT_BRANDS)))

    def test_free_mailbox_brand_display_is_spoof(self) -> None:
        mail = parsed(
            sender="Microsoft Account <user@outlook.com>",
            message_id="<1@outlook.com>",
        )
        found = analyse_headers(mail, DEFAULT_BRANDS)
        self.assertIn("header-display-spoof", codes(found))
        spoof = next(item for item in found if item.code == "header-display-spoof")
        self.assertIn("free mailbox", spoof.detail)

    def test_microsoft_dot_com_display_aligns(self) -> None:
        mail = parsed(
            sender="Microsoft <account@microsoft.com>",
            message_id="<1@microsoft.com>",
        )
        self.assertNotIn("header-display-spoof", codes(analyse_headers(mail, DEFAULT_BRANDS)))

    def test_display_name_hides_another_address(self) -> None:
        mail = parsed(
            sender='"fnb@fnb.co.za" <attacker@example.com>',
            message_id="<1@example.com>",
        )
        found = codes(analyse_headers(mail, DEFAULT_BRANDS))
        self.assertIn("header-display-address", found)

    def test_message_id_mismatch_and_missing(self) -> None:
        mismatch = parsed(
            sender="Alex <alex@example.com>",
            message_id="<1@mail.example>",
        )
        self.assertIn("header-message-id-mismatch", codes(analyse_headers(mismatch, DEFAULT_BRANDS)))
        missing = parsed(message_id="")
        # EmailMessage may omit an empty Message-ID; set none by parsing raw.
        from phishcheck.parse import parse_bytes

        raw = (
            b"From: Alex <alex@example.com>\r\n"
            b"Subject: Hi\r\n"
            b"Date: Wed, 28 Oct 2026 08:15:00 +0200\r\n"
            b"\r\n"
            b"Hello\r\n"
        )
        mail = parse_bytes(raw)
        self.assertIn("header-message-id-missing", codes(analyse_headers(mail, DEFAULT_BRANDS)))

    def test_rain_in_a_sentence_is_not_display_spoof(self) -> None:
        mail = parsed(
            sender="Rain check <alex@example.com>",
            message_id="<1@example.com>",
        )
        self.assertNotIn("header-display-spoof", codes(analyse_headers(mail, DEFAULT_BRANDS)))


if __name__ == "__main__":
    unittest.main()
