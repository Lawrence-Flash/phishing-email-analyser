"""Attachment extensions, double extensions, macros, and clean files."""

import unittest

from phishcheck.analysers.attachments import analyse_attachments
from tests.helpers import codes, parsed


class AttachmentTests(unittest.TestCase):
    def test_clean_pdf(self) -> None:
        mail = parsed(attachments=[("statement.pdf", "application/pdf", b"%PDF-1.4\n")])
        self.assertEqual(codes(analyse_attachments(mail)), set())

    def test_risky_extensions(self) -> None:
        for name in ("run.exe", "screen.scr", "app.js", "drop.vbs", "disk.iso", "open.lnk"):
            with self.subTest(name=name):
                mail = parsed(attachments=[(name, "application/octet-stream", b"synthetic")])
                self.assertIn("attachment-risky", codes(analyse_attachments(mail)))

    def test_uppercase_double_extension(self) -> None:
        mail = parsed(attachments=[("Invoice.PDF.EXE", "application/octet-stream", b"synthetic")])
        found = codes(analyse_attachments(mail))
        self.assertIn("attachment-risky", found)
        self.assertIn("attachment-double-ext", found)

    def test_html_attachment(self) -> None:
        mail = parsed(attachments=[("tracking.html", "text/html", b"<html>synthetic</html>")])
        found = codes(analyse_attachments(mail))
        self.assertEqual(found, {"attachment-html"})

    def test_macro_extension_and_content_type(self) -> None:
        mail = parsed(
            attachments=[
                (
                    "invoice.docm",
                    "application/vnd.ms-word.document.macroEnabled.12",
                    b"synthetic-macro",
                )
            ]
        )
        self.assertEqual(codes(analyse_attachments(mail)), {"attachment-macro"})
        typed = parsed(
            attachments=[
                (
                    "sheet.bin",
                    "application/vnd.ms-excel.sheet.macroEnabled.12",
                    b"synthetic-macro",
                )
            ]
        )
        self.assertEqual(codes(analyse_attachments(typed)), {"attachment-macro"})

    def test_archive_double_suffix_is_not_flagged(self) -> None:
        mail = parsed(attachments=[("logs.tar.gz", "application/gzip", b"synthetic")])
        self.assertEqual(codes(analyse_attachments(mail)), set())

    def test_jpg_png_is_not_a_double_extension_threat(self) -> None:
        mail = parsed(attachments=[("photo.jpg.png", "image/png", b"synthetic")])
        self.assertEqual(codes(analyse_attachments(mail)), set())


if __name__ == "__main__":
    unittest.main()
