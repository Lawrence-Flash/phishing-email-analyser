"""End-to-end scoring stays offline unless DNS is requested."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from phishcheck.engine import analyse
from phishcheck.rules import RULES
from tests.helpers import codes, message


class EngineTests(unittest.TestCase):
    def test_rule_codes_are_unique(self) -> None:
        seen = [rule.code for rule in RULES]
        self.assertEqual(len(seen), len(set(seen)))

    def test_clean_authenticated_mail_scores_zero(self) -> None:
        raw = message(
            sender="News <team@news.example>",
            reply_to="News <team@news.example>",
            return_path="<bounces@news.example>",
            message_id="<oct@news.example>",
            subject="October project update",
            body="Hello team, the deploy window is Thursday 10:00 SAST. https://news.example/2026/10/team-update",
            extra_headers=[
                (
                    "Authentication-Results",
                    "mx.example.com; spf=pass smtp.mailfrom=news.example; dkim=pass header.d=news.example; dmarc=pass header.from=news.example",
                )
            ],
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "clean.eml"
            path.write_bytes(raw)
            with patch("phishcheck.dns_check.lookup_txt", side_effect=AssertionError("network")):
                result = analyse(path)
        self.assertFalse(result.dns_checked)
        self.assertEqual(result.score, 0)
        self.assertEqual(result.verdict, "likely safe")

    def test_dns_notes_do_not_change_the_score(self) -> None:
        raw = message(subject="Hello", body="Hello")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "note.eml"
            path.write_bytes(raw)

            def fake(name, server):
                return ["v=spf1 -all"], "stdlib"

            offline = analyse(path, dns=False)
            online = analyse(path, dns=True, dns_server="1.1.1.1", dns_lookup=fake)
        self.assertEqual(offline.score, online.score)
        self.assertTrue(online.dns_checked)
        self.assertTrue(online.dns_notes)
        self.assertFalse(offline.dns_notes)

    def test_stacked_signals_cap_at_100(self) -> None:
        raw = message(
            sender="FNB Support <alerts@fnb-secure.example>",
            reply_to="Help <help@example.net>",
            return_path="<bounce@example.org>",
            message_id="<x@mail.example>",
            subject="FNB account suspended",
            body=(
                "Urgent: your account is suspended. Verify your account immediately. "
                "Confirm the new bank account within 24 hours. Enter the OTP. "
                "http://203.0.113.50/login/verify"
            ),
            html='<a href="http://fnb-secure.example/login/verify">https://www.fnb.co.za/login</a>',
            extra_headers=[
                ("Authentication-Results", "mx.example.com; spf=fail; dkim=fail; dmarc=fail"),
            ],
            attachments=[("invoice.pdf.exe", "application/octet-stream", b"synthetic")],
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "stack.eml"
            path.write_bytes(raw)
            result = analyse(path)
        self.assertEqual(result.score, 100)
        self.assertGreater(result.score_raw, 100)
        self.assertEqual(result.verdict, "likely phishing")
        self.assertIn("header-display-spoof", codes(result.findings))
        self.assertTrue(result.advice.startswith("Do not reply"))


if __name__ == "__main__":
    unittest.main()
