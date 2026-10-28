"""Defanging keeps pasted output from becoming a live link."""

import unittest

from phishcheck.defang import defang_domain, defang_email, defang_embedded, defang_ip, defang_url, present_evidence


class DefangTests(unittest.TestCase):
    def test_url_schemes_and_host_dots(self) -> None:
        self.assertEqual(
            defang_url("https://evil.example/a.b"),
            "hxxps://evil[.]example/a[.]b",
        )
        self.assertEqual(defang_url("http://evil.example/x"), "hxxp://evil[.]example/x")

    def test_domain_email_and_ip(self) -> None:
        self.assertEqual(defang_domain("fnb-secure.example"), "fnb-secure[.]example")
        self.assertEqual(defang_email("a@fnb-secure.example"), "a@fnb-secure[.]example")
        self.assertEqual(defang_ip("203.0.113.50"), "203[.]0[.]113[.]50")
        self.assertEqual(defang_ip("2001:db8::1"), "2001[:]db8[:][:]1")

    def test_data_and_javascript_payloads_are_omitted(self) -> None:
        self.assertEqual(defang_url("data:text/html,DATASECRETTOKEN"), "data:(content omitted)")
        self.assertEqual(defang_url("javascript:SCRIPTSECRETTOKEN"), "javascript:(content omitted)")

    def test_embedded_prose(self) -> None:
        text = "see https://evil.example/a.b and a@evil.example or 203.0.113.10"
        defanged = defang_embedded(text)
        self.assertNotIn("https://", defanged)
        self.assertNotIn("evil.example", defanged)
        self.assertIn("hxxps://evil[.]example/a[.]b", defanged)
        self.assertIn("a@evil[.]example", defanged)
        self.assertIn("203[.]0[.]113[.]10", defanged)

    def test_present_evidence_types(self) -> None:
        self.assertEqual(present_evidence("url:http://evil.example/a"), "hxxp://evil[.]example/a")
        self.assertEqual(present_evidence("file:invoice.pdf.exe"), "invoice.pdf.exe")
        self.assertIn("[.]", present_evidence("text:go to evil.example"))


if __name__ == "__main__":
    unittest.main()
