"""Parser: headers, body, hops, and attachment bytes."""

import hashlib
import unittest

from tests.helpers import parsed


class ParseTests(unittest.TestCase):
    def test_received_hop_timestamp_and_ip(self) -> None:
        mail = parsed(
            extra_headers=[
                (
                    "Received",
                    "from mail.example.com (mail.example.com [203.0.113.10]) "
                    "by mx.example.net; Wed, 28 Oct 2026 08:15:00 +0200",
                )
            ]
        )
        self.assertEqual(len(mail.hops), 1)
        self.assertEqual(mail.hops[0].ips, ("203.0.113.10",))
        self.assertEqual(mail.hops[0].host, "mail.example.com")
        self.assertTrue(mail.hops[0].timestamp.startswith("2026-10-28T08:15:00"))

    def test_plain_and_html_are_kept_apart(self) -> None:
        mail = parsed(
            body="See https://news.example/post",
            html='<a href="http://evil.example/login">https://news.example/post</a>',
        )
        self.assertIn("https://news.example/post", mail.plain_text)
        self.assertIn("evil.example", mail.html_text)
        self.assertNotIn("<a", mail.combined_text)

    def test_attachment_hash_and_size(self) -> None:
        payload = b"synthetic"
        mail = parsed(attachments=[("statement.pdf", "application/pdf", payload)])
        self.assertEqual(len(mail.attachments), 1)
        item = mail.attachments[0]
        self.assertEqual(item.filename, "statement.pdf")
        self.assertEqual(item.size, len(payload))
        self.assertEqual(item.sha256, hashlib.sha256(payload).hexdigest())

    def test_empty_message_does_not_raise(self) -> None:
        from phishcheck.parse import parse_bytes

        mail = parse_bytes(b"", path="<empty>")
        self.assertEqual(mail.subject, "")
        self.assertEqual(mail.attachments, ())


if __name__ == "__main__":
    unittest.main()
