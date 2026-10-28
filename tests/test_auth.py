"""Authentication-Results and Received-SPF are quoted, not recomputed."""

import unittest

from phishcheck.analysers.auth import analyse_auth, auth_report
from tests.helpers import codes, parsed


PASS = (
    "Authentication-Results",
    "mx.example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com",
)


class AuthTests(unittest.TestCase):
    def test_pass_is_not_scored(self) -> None:
        mail = parsed(extra_headers=[PASS])
        self.assertEqual(codes(analyse_auth(mail)), set())
        report = auth_report(mail)
        self.assertEqual((report.spf, report.dkim, report.dmarc), ("pass", "pass", "pass"))

    def test_fail_softfail_and_none(self) -> None:
        mail = parsed(
            extra_headers=[
                (
                    "Authentication-Results",
                    "mx.example.com; spf=softfail; dkim=none; dmarc=fail header.from=example.com",
                )
            ]
        )
        found = codes(analyse_auth(mail))
        self.assertEqual(found, {"auth-spf-softfail", "auth-dkim-none", "auth-dmarc-fail"})
        fail = next(item for item in analyse_auth(mail) if item.code == "auth-dmarc-fail")
        self.assertIn("did not re-check", fail.detail)

    def test_hardfail_uses_fail_code(self) -> None:
        mail = parsed(extra_headers=[("Authentication-Results", "mx.example.com; spf=hardfail")])
        self.assertIn("auth-spf-fail", codes(analyse_auth(mail)))
        self.assertEqual(auth_report(mail).spf, "hardfail")
        self.assertIn("auth-dkim-missing", codes(analyse_auth(mail)))

    def test_missing_when_no_headers(self) -> None:
        mail = parsed()
        self.assertEqual(
            codes(analyse_auth(mail)),
            {"auth-spf-missing", "auth-dkim-missing", "auth-dmarc-missing"},
        )

    def test_received_spf_fills_only_the_gap(self) -> None:
        mail = parsed(
            extra_headers=[
                ("Received-SPF", "pass (example.com: synthetic) client-ip=203.0.113.10;"),
            ]
        )
        report = auth_report(mail)
        self.assertEqual(report.spf, "pass")
        self.assertNotIn("auth-spf-missing", codes(analyse_auth(mail)))
        self.assertIn("auth-dmarc-missing", codes(analyse_auth(mail)))

    def test_authentication_results_wins_over_received_spf(self) -> None:
        mail = parsed(
            extra_headers=[
                ("Authentication-Results", "mx.example.com; spf=fail"),
                ("Received-SPF", "pass (ignored) client-ip=203.0.113.10;"),
            ]
        )
        self.assertEqual(auth_report(mail).spf, "fail")

    def test_unknown_token_is_not_treated_as_missing(self) -> None:
        mail = parsed(extra_headers=[("Authentication-Results", "mx.example.com; dkim=policy; spf=pass; dmarc=pass")])
        self.assertEqual(auth_report(mail).dkim, "policy")
        self.assertNotIn("auth-dkim-missing", codes(analyse_auth(mail)))

    def test_neutral_and_errors(self) -> None:
        mail = parsed(
            extra_headers=[
                (
                    "Authentication-Results",
                    "mx.example.com; spf=neutral; dkim=temperror; dmarc=permerror",
                )
            ]
        )
        self.assertEqual(
            codes(analyse_auth(mail)),
            {"auth-spf-neutral", "auth-dkim-temperror", "auth-dmarc-permerror"},
        )


if __name__ == "__main__":
    unittest.main()
