"""Urgency, payments, gift cards, South African lures, and OTP requests."""

import unittest

from phishcheck.analysers.content import analyse_content
from tests.helpers import codes, parsed


class ContentTests(unittest.TestCase):
    def test_benign_invoice_language(self) -> None:
        mail = parsed(
            subject="Invoice 1042",
            body="Please find invoice 1042 attached. Payment is due within 30 days on the account you already have on file.",
        )
        self.assertEqual(codes(analyse_content(mail)), set())

    def test_negated_urgency(self) -> None:
        mail = parsed(body="This is not urgent and never urgent.")
        self.assertNotIn("content-urgency", codes(analyse_content(mail)))

    def test_urgency_and_payment_change(self) -> None:
        mail = parsed(
            subject="Account notice",
            body="Urgent: your account is suspended. Confirm the new bank account immediately.",
        )
        self.assertEqual(
            codes(analyse_content(mail)),
            {"content-urgency", "content-payment-change"},
        )

    def test_subject_alone_can_score(self) -> None:
        mail = parsed(subject="Final notice", body="Hello.")
        self.assertIn("content-urgency", codes(analyse_content(mail)))

    def test_gift_card(self) -> None:
        mail = parsed(body="Please buy two Google Play gift cards and reply.")
        self.assertEqual(codes(analyse_content(mail)), {"content-gift-card"})

    def test_sa_lures_and_otp(self) -> None:
        mail = parsed(
            body="Your SARS refund is waiting on eFiling. Enter the OTP within 24 hours.",
        )
        self.assertEqual(
            codes(analyse_content(mail)),
            {"content-sa-lure", "content-otp", "content-urgency"},
        )

    def test_afrikaans_phrases(self) -> None:
        mail = parsed(body="Jou rekening is opgeskort. Dit is dringend. Betaal die afleweringskoste.")
        found = codes(analyse_content(mail))
        self.assertIn("content-urgency", found)
        self.assertIn("content-sa-lure", found)

    def test_sassa_and_pin_code(self) -> None:
        mail = parsed(body="SASSA grant payment ready. Send the PIN code.")
        self.assertEqual(codes(analyse_content(mail)), {"content-sa-lure", "content-otp"})

    def test_word_pin_inside_another_word_does_not_match(self) -> None:
        mail = parsed(body="See the appendix for opinions on the topic.")
        self.assertNotIn("content-otp", codes(analyse_content(mail)))


if __name__ == "__main__":
    unittest.main()
