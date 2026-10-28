"""The checked-in example report stays in step with the renderer."""

import unittest
from pathlib import Path

from phishcheck import __version__
from phishcheck.engine import analyse
from phishcheck.ioc import render_ioc_csv, render_ioc_json
from phishcheck.report import render_markdown


ROOT = Path(__file__).resolve().parents[1]
SOURCE = "samples/05-phish-sars-refund.eml"


class DocsTests(unittest.TestCase):
    def test_example_report_matches_the_tool(self) -> None:
        result = analyse(SOURCE)
        report = (ROOT / "docs/example-report.md").read_text(encoding="utf-8")
        self.assertEqual(report, render_markdown(result))
        self.assertEqual((ROOT / "docs/example-iocs.json").read_text(encoding="utf-8"), render_ioc_json(result))
        self.assertEqual((ROOT / "docs/example-iocs.csv").read_text(encoding="utf-8"), render_ioc_csv(result))
        self.assertNotIn("http://", report)
        self.assertNotIn("https://", report)

    def test_version_matches_pyproject(self) -> None:
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn(f'version = "{__version__}"', text)


if __name__ == "__main__":
    unittest.main()
