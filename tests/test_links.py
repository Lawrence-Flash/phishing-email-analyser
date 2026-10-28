"""Links: mismatch, IP hosts, shorteners, credential words, data and javascript."""

import unittest

from phishcheck.analysers.links import analyse_links
from phishcheck.engine import analyse
from phishcheck.report import render_json, render_markdown
from tests.helpers import codes, message, parsed


class LinkTests(unittest.TestCase):
    def test_clean_link(self) -> None:
        mail = parsed(body="Read https://news.example/2026/10/team-update today.")
        findings, links = analyse_links(mail)
        self.assertEqual(codes(findings), set())
        self.assertEqual(len(links), 1)

    def test_display_href_mismatch(self) -> None:
        mail = parsed(
            body="Open the portal.",
            html='<a href="http://fnb-secure.example/login/verify">https://www.fnb.co.za/online/login</a>',
        )
        findings, _links = analyse_links(mail)
        found = codes(findings)
        self.assertIn("link-href-mismatch", found)
        self.assertIn("link-credential", found)

    def test_same_site_with_www_is_not_a_mismatch(self) -> None:
        mail = parsed(
            body="Hi",
            html='<a href="https://www.example.com/post">https://example.com/post</a>',
        )
        self.assertNotIn("link-href-mismatch", codes(analyse_links(mail)[0]))

    def test_click_here_is_not_a_mismatch(self) -> None:
        mail = parsed(body="Hi", html='<a href="https://news.example/post">click here</a>')
        self.assertNotIn("link-href-mismatch", codes(analyse_links(mail)[0]))

    def test_ip_shortener_and_negative(self) -> None:
        mail = parsed(
            body="http://203.0.113.50/parcel and https://bit.ly/synthetic",
        )
        found = codes(analyse_links(mail)[0])
        self.assertIn("link-ip-address", found)
        self.assertIn("link-shortener", found)
        self.assertNotIn("link-credential", found)

    def test_dangerous_schemes_omit_payloads_from_the_report(self) -> None:
        mail = parsed(
            body="See data:text/html,DATASECRETTOKEN and javascript:SCRIPTSECRETTOKEN() please.",
        )
        findings, links = analyse_links(mail)
        found = codes(findings)
        self.assertIn("link-data-uri", found)
        self.assertIn("link-script-uri", found)
        self.assertTrue(any(link.url.startswith("data:") for link in links))
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scheme.eml"
            path.write_bytes(message(body=mail.body_text))
            # Rebuild from the same body the parser saw.
            path.write_bytes(
                message(
                    body="See data:text/html,DATASECRETTOKEN and javascript:SCRIPTSECRETTOKEN() please."
                )
            )
            result = analyse(path)
            rendered = render_markdown(result) + render_json(result)
            self.assertNotIn("DATASECRETTOKEN", rendered)
            self.assertNotIn("SCRIPTSECRETTOKEN", rendered)
            self.assertIn("content omitted", rendered)


if __name__ == "__main__":
    unittest.main()
