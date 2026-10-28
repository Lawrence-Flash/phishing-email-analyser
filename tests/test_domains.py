"""Registrable domains, reserved names, and address extraction."""

import unittest

from phishcheck.domains import (
    different_org,
    extract_ips,
    hostname_of,
    is_documentation_ip,
    is_reserved_domain,
    registrable_domain,
    to_unicode_host,
)


class DomainTests(unittest.TestCase):
    def test_co_za_registrable_domain(self) -> None:
        self.assertEqual(registrable_domain("mail.fnb.co.za"), "fnb.co.za")
        self.assertEqual(registrable_domain("fnb.co.za"), "fnb.co.za")
        self.assertEqual(registrable_domain("news.example"), "news.example")
        self.assertEqual(registrable_domain("mail.example.com"), "example.com")

    def test_same_organisation_ignores_subdomains(self) -> None:
        self.assertFalse(different_org("bounce.example.com", "user@example.com".split("@")[1]))
        self.assertTrue(different_org("example.com", "example.net"))
        self.assertFalse(different_org("", "example.com"))

    def test_punycode_decodes(self) -> None:
        decoded = to_unicode_host("xn--bsa-5cd.example")
        self.assertNotEqual(decoded, "xn--bsa-5cd.example")
        self.assertTrue(decoded.endswith(".example"))
        self.assertEqual(registrable_domain("xn--bsa-5cd.example"), decoded)

    def test_hostname_and_ips(self) -> None:
        self.assertEqual(hostname_of("https://www.example.com/a"), "www.example.com")
        self.assertEqual(hostname_of("http://203.0.113.50/a"), "203.0.113.50")
        self.assertEqual(hostname_of("data:text/html,hi"), "")
        ips = extract_ips(
            "from mail.example (mail.example [203.0.113.10]) by mx; Wed, 28 Oct 2026 08:15:00 +0200"
        )
        self.assertEqual(ips, ("203.0.113.10",))
        self.assertNotIn("08:15:00", " ".join(extract_ips("at 08:15:00")))

    def test_reserved_and_documentation(self) -> None:
        self.assertTrue(is_reserved_domain("fnb-secure.example"))
        self.assertTrue(is_reserved_domain("example.com"))
        self.assertTrue(is_reserved_domain("mail.example.com"))
        self.assertFalse(is_reserved_domain("fnb.co.za"))
        self.assertTrue(is_documentation_ip("203.0.113.50"))
        self.assertTrue(is_documentation_ip("198.51.100.20"))
        self.assertTrue(is_documentation_ip("192.0.2.15"))
        self.assertTrue(is_reserved_domain("2001:db8::1"))
        self.assertFalse(is_documentation_ip("8.8.8.8"))


if __name__ == "__main__":
    unittest.main()
