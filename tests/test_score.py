"""Score cap, verdict bands, and duplicate codes."""

import unittest

from phishcheck.models import Finding
from phishcheck.score import advice_for, score_findings, verdict_for


def _finding(code: str, points: int) -> Finding:
    return Finding(analyser="test", code=code, title=code, detail="", points=points)


class ScoreTests(unittest.TestCase):
    def test_verdict_boundaries(self) -> None:
        self.assertEqual(verdict_for(0), "likely safe")
        self.assertEqual(verdict_for(24), "likely safe")
        self.assertEqual(verdict_for(25), "suspicious")
        self.assertEqual(verdict_for(59), "suspicious")
        self.assertEqual(verdict_for(60), "likely phishing")
        self.assertEqual(verdict_for(100), "likely phishing")

    def test_cap(self) -> None:
        findings = [_finding(f"c{i}", 20) for i in range(7)]
        score, raw, verdict = score_findings(findings)
        self.assertEqual((score, raw, verdict), (100, 140, "likely phishing"))

    def test_duplicate_code_counts_once(self) -> None:
        score, raw, _verdict = score_findings([_finding("content-urgency", 8), _finding("content-urgency", 8)])
        self.assertEqual((score, raw), (8, 8))

    def test_zero_point_notes_do_not_score(self) -> None:
        score, raw, verdict = score_findings([_finding("dns-spf", 0)])
        self.assertEqual((score, raw, verdict), (0, 0, "likely safe"))

    def test_advice(self) -> None:
        phishing = advice_for("likely phishing", [_finding("content-otp", 15), _finding("attachment-risky", 25)])
        self.assertTrue(phishing.startswith("Do not reply"))
        self.assertIn("PIN", phishing)
        self.assertIn("attachment", phishing.casefold())
        safe = advice_for("likely safe", [])
        self.assertIn("No strong phishing signals", safe)


if __name__ == "__main__":
    unittest.main()
