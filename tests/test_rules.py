"""Scoring table source of truth."""

import unittest
from pathlib import Path

from phishcheck.rules import RULES, SCORE_CAP, VERDICT_PHISHING_AT, VERDICT_SUSPICIOUS_AT, render_scoring_table


class RulesTests(unittest.TestCase):
    def test_thresholds(self) -> None:
        self.assertEqual((VERDICT_SUSPICIOUS_AT, VERDICT_PHISHING_AT, SCORE_CAP), (25, 60, 100))

    def test_readme_contains_the_generated_table(self) -> None:
        readme = Path("README.md").read_text(encoding="utf-8")
        self.assertIn(render_scoring_table(), readme)
        self.assertIn("0-24: likely safe", readme)
        self.assertIn("25-59: suspicious", readme)
        self.assertIn("60-100: likely phishing", readme)
        for rule in RULES:
            self.assertIn(f"`{rule.code}`", readme)


if __name__ == "__main__":
    unittest.main()
