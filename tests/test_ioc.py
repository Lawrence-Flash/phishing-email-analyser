"""IOC export omits brand lures and defangs what it keeps."""

import json
import unittest

from phishcheck.brands import DEFAULT_BRANDS
from phishcheck.ioc import build_indicators, render_ioc_csv, render_ioc_json
from phishcheck.report import render_json
from tests.helpers import message, parsed


class IocTests(unittest.TestCase):
    def _result_indicators(self, mail):
        from phishcheck.analysers.links import analyse_links

        _findings, links = analyse_links(mail)
        return build_indicators(mail, links, DEFAULT_BRANDS)

    def test_display_lure_is_not_an_indicator(self) -> None:
        mail = parsed(
            sender="SARS <refunds@sars-efiling.example>",
            message_id="<1@sars-efiling.example>",
            body="See the notice.",
            html='<a href="http://sars-efiling.example/login">https://www.sars.gov.za/efiling</a>',
            extra_headers=[("Received", "from mail.example (mail.example [203.0.113.10]); Wed, 28 Oct 2026 08:15:00 +0200")],
            attachments=[("note.txt", "text/plain", b"synthetic")],
        )
        indicators = self._result_indicators(mail)
        values = [item.value for item in indicators]
        self.assertIn("sars-efiling.example", values)
        self.assertNotIn("sars.gov.za", values)
        self.assertNotIn("www.sars.gov.za", values)
        self.assertTrue(any(item.type == "sha256" and item.context == "attachment:note.txt" for item in indicators))
        self.assertTrue(any(item.type == "ip" and item.value == "203.0.113.10" for item in indicators))

    def test_official_link_target_is_omitted(self) -> None:
        mail = parsed(body="https://www.fnb.co.za/statements")
        values = [item.value for item in self._result_indicators(mail)]
        self.assertFalse(any("fnb.co.za" in value for value in values))

    def test_export_is_defanged(self) -> None:
        mail = parsed(
            sender="A <a@fnb-secure.example>",
            body="http://203.0.113.50/login",
            message_id="<1@fnb-secure.example>",
        )
        from phishcheck.engine import analyse
        from pathlib import Path
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ioc.eml"
            path.write_bytes(
                message(
                    sender="A <a@fnb-secure.example>",
                    body="http://203.0.113.50/login",
                    message_id="<1@fnb-secure.example>",
                )
            )
            result = analyse(path)
        rendered = render_ioc_json(result) + render_ioc_csv(result) + render_json(result)
        self.assertNotIn("http://", rendered)
        self.assertNotIn("fnb-secure.example", rendered)
        self.assertIn("fnb-secure[.]example", rendered)
        self.assertIn("203[.]0[.]113[.]50", rendered)
        payload = json.loads(render_ioc_json(result))
        self.assertTrue(payload["defanged"])
        self.assertIn("blocklist", payload["note"])
        domains = [item for item in payload["indicators"] if item["type"] == "domain"]
        self.assertTrue(domains)
        self.assertTrue(all(item["reserved"] for item in domains))


if __name__ == "__main__":
    unittest.main()
