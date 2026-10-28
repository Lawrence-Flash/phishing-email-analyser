"""Synthetic samples stay reserved, and the verdict bands hold."""

import re
import unittest
from pathlib import Path

from phishcheck.brands import DEFAULT_BRANDS, is_official_host
from phishcheck.cli import main
from phishcheck.domains import hostname_of, is_documentation_ip, is_ip, is_reserved_domain
from phishcheck.engine import analyse


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
URL_RE = re.compile(r"https?://[^\s<>'\"]+")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)

EXPECTED = {
    "01-legit-colleague.eml": "likely safe",
    "02-legit-newsletter.eml": "likely safe",
    "03-legit-invoice-pdf.eml": "likely safe",
    "04-phish-fnb-display-spoof.eml": "likely phishing",
    "05-phish-sars-refund.eml": "likely phishing",
    "06-phish-delivery-fee.eml": "likely phishing",
    "07-phish-giftcard-otp.eml": "likely phishing",
    "08-phish-invoice-attachment.eml": "likely phishing",
}


def _official(host: str) -> bool:
    return is_official_host(host, DEFAULT_BRANDS)


class SampleTests(unittest.TestCase):
    def test_demo_and_verdicts(self) -> None:
        from io import StringIO
        from contextlib import redirect_stdout

        stdout = StringIO()
        with redirect_stdout(stdout):
            code = main(["demo", "--samples", str(SAMPLES)])
        self.assertEqual(code, 0, stdout.getvalue())
        for name, verdict in EXPECTED.items():
            result = analyse(SAMPLES / name)
            codes = sorted(item.code for item in result.findings)
            self.assertEqual(result.verdict, verdict, f"{name} scored {result.score}: {codes}")
            if verdict == "likely safe":
                self.assertLess(result.score, 25, codes)
            else:
                self.assertGreaterEqual(result.score, 60, codes)

    def test_colleague_is_only_missing_auth(self) -> None:
        result = analyse(SAMPLES / "01-legit-colleague.eml")
        self.assertEqual(
            {item.code for item in result.findings},
            {"auth-spf-missing", "auth-dkim-missing", "auth-dmarc-missing"},
        )
        self.assertEqual(result.score, 9)

    def test_authenticated_legit_samples_score_zero(self) -> None:
        for name in ("02-legit-newsletter.eml", "03-legit-invoice-pdf.eml"):
            result = analyse(SAMPLES / name)
            self.assertEqual(result.score, 0, [item.code for item in result.findings])
            self.assertEqual(result.attachments[0].filename if name.startswith("03") else "", "statement.pdf" if name.startswith("03") else "")

    def test_gift_card_passes_authentication_and_still_scores(self) -> None:
        result = analyse(SAMPLES / "07-phish-giftcard-otp.eml")
        self.assertEqual((result.auth.spf, result.auth.dkim, result.auth.dmarc), ("pass", "pass", "pass"))
        codes = {item.code for item in result.findings}
        self.assertIn("content-gift-card", codes)
        self.assertIn("content-otp", codes)
        self.assertGreaterEqual(result.score, 60)

    def test_samples_use_reserved_infrastructure(self) -> None:
        self.assertEqual(len(list(SAMPLES.glob("*.eml"))), 8)
        for path in SAMPLES.glob("*.eml"):
            text = path.read_text(encoding="utf-8")
            self.assertIn("SYNTHETIC SAMPLE", text, path.name)
            self.assertIn("X-Phishcheck-Sample: synthetic", text, path.name)
            for match in URL_RE.finditer(text):
                host = hostname_of(match.group(0))
                safe = (host and (_official(host) or is_reserved_domain(host) or (is_ip(host) and is_documentation_ip(host))))
                self.assertTrue(safe, f"{path.name} has live URL {match.group(0)}")
            for match in EMAIL_RE.finditer(text):
                self.assertTrue(is_reserved_domain(match.group(1)), f"{path.name} {match.group(0)}")
            for ip in IPV4_RE.findall(text):
                self.assertTrue(is_documentation_ip(ip), f"{path.name} {ip}")

    def test_readme_quotes_demo_scores(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for name in EXPECTED:
            result = analyse(SAMPLES / name)
            line = f"{name:<44} {result.score:>5}  {result.verdict}"
            self.assertIn(line, readme)


if __name__ == "__main__":
    unittest.main()
