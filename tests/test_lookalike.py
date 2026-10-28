"""Lookalike domains: official names, typos, punycode, and suspicious TLDs."""

import unittest

from phishcheck.analysers.lookalike import analyse_lookalikes, levenshtein
from phishcheck.brands import DEFAULT_BRANDS
from tests.helpers import codes, parsed


def _codes_for(sender: str, body: str = "Hello", html: str | None = None, message_id: str = "<1@example.com>") -> set[str]:
    mail = parsed(sender=sender, body=body, html=html, message_id=message_id, reply_to=sender)
    from phishcheck.analysers.links import analyse_links

    _findings, links = analyse_links(mail)
    return codes(analyse_lookalikes(mail, links, DEFAULT_BRANDS))


class LookalikeTests(unittest.TestCase):
    def test_official_domains_are_clean(self) -> None:
        self.assertEqual(_codes_for("FNB <statements@fnb.co.za>", message_id="<1@fnb.co.za>"), set())
        self.assertEqual(
            _codes_for("FNB <statements@mail.fnb.co.za>", message_id="<1@fnb.co.za>"),
            set(),
        )

    def test_keyword_compound_and_exact_short_token(self) -> None:
        self.assertIn("lookalike-keyword", _codes_for("A <a@fnb-secure.example>"))
        self.assertIn("lookalike-keyword", _codes_for("A <a@fnb.example>"))

    def test_rain_exact_is_not_fuzzy_and_compound_is(self) -> None:
        self.assertNotIn("lookalike-keyword", _codes_for("A <a@rain.example>"))
        self.assertIn("lookalike-keyword", _codes_for("A <a@rain-secure.example>"))

    def test_typosquat_distance(self) -> None:
        self.assertEqual(levenshtein("standardbnk", "standardbank"), 1)
        self.assertIn("lookalike-typosquat", _codes_for("A <a@standardbnk.example>"))
        self.assertEqual(levenshtein("standrdank", "standardbank"), 2)
        self.assertIn("lookalike-typosquat-weak", _codes_for("A <a@standrdank.example>"))

    def test_punycode_homoglyph(self) -> None:
        found = _codes_for("Absa <alerts@xn--bsa-5cd.example>", message_id="<1@xn--bsa-5cd.example>")
        self.assertIn("lookalike-homoglyph", found)
        self.assertNotIn("lookalike-keyword", found)

    def test_digit_homoglyph(self) -> None:
        self.assertIn("lookalike-homoglyph", _codes_for("A <a@paypa1.example>"))
        self.assertIn("lookalike-homoglyph", _codes_for("A <a@g00gle.example>"))

    def test_subdomain_trick(self) -> None:
        mail = parsed(
            body="https://fnb.co.za.evil.example/login",
            sender="A <a@example.com>",
            message_id="<1@example.com>",
        )
        from phishcheck.analysers.links import analyse_links

        _findings, links = analyse_links(mail)
        found = codes(analyse_lookalikes(mail, links, DEFAULT_BRANDS))
        self.assertIn("lookalike-subdomain-trick", found)

    def test_suspicious_tld_with_and_without_a_brand(self) -> None:
        plain = _codes_for("A <a@notabrand.tk>", message_id="<1@notabrand.tk>")
        self.assertEqual(plain, {"lookalike-suspicious-tld"})
        branded = _codes_for("A <a@fnb-secure.tk>", message_id="<1@fnb-secure.tk>")
        self.assertIn("lookalike-keyword", branded)
        self.assertIn("lookalike-suspicious-tld", branded)

    def test_mixed_script_that_is_not_a_brand(self) -> None:
        unicode_host = "zzz\u0430qqq.example"
        host = unicode_host.encode("idna").decode("ascii")
        found = _codes_for(f"A <a@{host}>", message_id=f"<1@{host}>")
        self.assertIn("lookalike-mixed-script", found)

    def test_negative_personal_domain(self) -> None:
        self.assertEqual(_codes_for("Alex Example <alex@example.com>"), set())


if __name__ == "__main__":
    unittest.main()
