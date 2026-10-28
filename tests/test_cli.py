"""CLI commands, including a missing file and JSON output."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from phishcheck.cli import main
from tests.helpers import message


class CliTests(unittest.TestCase):
    def test_missing_file(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = main(["analyse", "no-such-file.eml"])
        self.assertEqual(code, 2)
        self.assertIn("not found", stderr.getvalue())

    def test_json_and_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            eml = Path(tmp) / "note.eml"
            report = Path(tmp) / "out.md"
            ioc_json = Path(tmp) / "iocs.json"
            ioc_csv = Path(tmp) / "iocs.csv"
            eml.write_bytes(message(subject="Hello", body="Hello there."))
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = main(
                    [
                        "analyse",
                        str(eml),
                        "--json",
                        "--report",
                        str(report),
                        "--ioc-json",
                        str(ioc_json),
                        "--ioc-csv",
                        str(ioc_csv),
                    ]
                )
            self.assertEqual(code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["verdict"], "likely safe")
            self.assertIn("authentication_as_reported", payload)
            self.assertIn("indicators", payload)
            self.assertIn("phishcheck report", report.read_text(encoding="utf-8"))
            self.assertIn("type,value,context,reserved", ioc_csv.read_text(encoding="utf-8"))
            self.assertTrue(json.loads(ioc_json.read_text(encoding="utf-8"))["defanged"])
            self.assertTrue(stdout.getvalue().lstrip().startswith("{"))

    def test_dns_flag_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            eml = Path(tmp) / "note.eml"
            eml.write_bytes(message(body="Hello"))
            calls = []

            def fake(name, server):
                calls.append((name, server))
                return ["v=spf1 -all"], "stdlib"

            stdout = io.StringIO()
            with patch("phishcheck.engine.check_published", wraps=None) as _wrapped:
                pass
            with patch("phishcheck.dns_check.lookup_txt", side_effect=AssertionError("should not resolve")):
                with redirect_stdout(stdout):
                    code = main(["analyse", str(eml), "--json"])
            self.assertEqual(code, 0)
            self.assertFalse(json.loads(stdout.getvalue())["dns"]["checked"])

            def injected(name, server):
                calls.append(server)
                return ["v=spf1 -all"], "stdlib"

            with patch("phishcheck.engine.check_published", side_effect=lambda *a, **k: ()):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    code = main(["analyse", str(eml), "--dns", "--dns-server", "192.0.2.1", "--json"])
            self.assertEqual(code, 0)

    def test_brands_file_replace(self) -> None:
        from phishcheck.brands import load_brands

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "brands.json"
            path.write_text(
                json.dumps(
                    {
                        "replace": True,
                        "brands": [{"name": "Example Bank", "domains": ["example.bank"], "tokens": ["examplebank"]}],
                    }
                ),
                encoding="utf-8",
            )
            brands = load_brands(str(path))
            self.assertEqual(len(brands), 1)
            extended = load_brands(None)
            self.assertGreater(len(extended), 10)
            path.write_text(
                json.dumps({"brands": [{"name": "Extra", "domains": ["extra.example"], "tokens": ["extra"]}]}),
                encoding="utf-8",
            )
            self.assertGreater(len(load_brands(str(path))), len(extended))

    def test_version(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as caught:
                main(["--version"])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("phishcheck", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
