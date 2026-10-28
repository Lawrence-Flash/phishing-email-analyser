# phishcheck report

This file is marked synthetic. It is a demo fixture, not a live incident.

- File: samples/05-phish-sars-refund.eml
- Subject: SARS refund waiting on eFiling
- From: SARS eFiling <refunds@sars-efiling[.]example>
- Reply-To: SARS eFiling <refunds@sars-efiling[.]example>
- Return-Path: <bounce@sars-efiling[.]example>
- Message-ID: <refund-1@sars-efiling[.]example>
- Date: Wed, 28 Oct 2026 08:15:00 +0200
- Score: 100/100 (raw 157, capped at 100)
- Verdict: **likely phishing**

## What to do

Do not reply, click links, or open attachments. Report the message to your mail security team or SOC and delete it. If you need the real service, type the address yourself or use a bookmark. Do not use a link from this message. SARS, banks, and couriers do not ask you to email a PIN or OTP. Do not share one.

## Authentication (as recorded in headers)

These values are copied from Authentication-Results and Received-SPF. phishcheck does not re-verify DKIM signatures and does not evaluate SPF against DNS unless you pass `--dns`. Even then it only fetches TXT records.

| Check | Result |
| --- | --- |
| SPF | softfail |
| DKIM | none |
| DMARC | fail |

## Why this score

| Points | Code | Detail |
| ---: | --- | --- |
| 25 | `lookalike-homoglyph` | A domain imitates a watched brand with confusable characters or punycode. Evidence: xn--srs-6cd[.]example (decodes to s\u0430rs[.]example). |
| 20 | `header-display-spoof` | The display name mentions SARS, but the sender domain is not an official domain for that brand. Evidence: SARS eFiling; refunds@sars-efiling[.]example; SARS. |
| 20 | `link-href-mismatch` | At least one link shows a different host in the visible text than the href actually uses. Evidence: hxxps://www[.]sars[.]gov[.]za/efiling -> hxxp://xn--srs-6cd[.]example/efiling/login. |
| 18 | `auth-dmarc-fail` | The message headers record DMARC=fail. phishcheck is quoting that header. It did not re-check the result. Evidence: dmarc=fail. |
| 16 | `lookalike-keyword` | A domain uses a watched brand token in a lookalike name. Evidence: sars-efiling[.]example. |
| 15 | `content-otp` | The message asks for a PIN, OTP, or one-time password. Evidence: OTP. |
| 12 | `content-sa-lure` | The message uses a lure that is common in South African phishing. Evidence: SARS refund; eFiling. |
| 12 | `link-credential` | At least one link path or query uses credential-harvest wording such as login, verify, or password. Evidence: hxxp://xn--srs-6cd[.]example/efiling/login. |
| 8 | `auth-spf-softfail` | The message headers record SPF=softfail. phishcheck is quoting that header. It did not re-check the result. Evidence: spf=softfail. |
| 8 | `content-urgency` | The subject or body pressures the reader to act quickly or threatens the account. Evidence: within 24 hours. |
| 3 | `auth-dkim-none` | The message headers record DKIM=none. phishcheck is quoting that header. It did not re-check the result. Evidence: dkim=none. |

## Received chain

Hop 1 is the first Received header, closest to the recipient.

| Hop | Host | IPs | Time |
| ---: | --- | --- | --- |
| 1 | mail[.]sars-efiling[.]example | 198[.]51[.]100[.]20 | 2026-10-28T08:15:00+02:00 |

## Links

| Source | URL | Display text |
| --- | --- | --- |
| html | hxxp://xn--srs-6cd[.]example/efiling/login | hxxps://www[.]sars[.]gov[.]za/efiling |
| text | hxxp://xn--srs-6cd[.]example/efiling/login |  |

## Attachments

No attachments.

## DNS TXT

Not checked. Re-run with `--dns` to fetch published SPF and DMARC TXT records. That sends the domain name to a resolver. It does not change the score and it does not contact a web reputation service.

## Indicators (defanged)

| Type | Value | Context | Reserved |
| --- | --- | --- | --- |
| domain | sars-efiling[.]example | header:from | yes |
| domain | sars-efiling[.]example | header:reply-to | yes |
| domain | sars-efiling[.]example | header:return-path | yes |
| domain | sars-efiling[.]example | header:message-id | yes |
| domain | xn--srs-6cd[.]example | link:html | yes |
| url | hxxp://xn--srs-6cd[.]example/efiling/login | link:html | yes |
| domain | xn--srs-6cd[.]example | link:text | yes |
| url | hxxp://xn--srs-6cd[.]example/efiling/login | link:text | yes |
| domain | mail[.]sars-efiling[.]example | received | yes |
| ip | 198[.]51[.]100[.]20 | received | yes |

## Limitations

Heuristic checklist only. A quiet phish can score low and an odd legitimate mail can score higher. Not a mail gateway, and not a substitute for the verdict from your mail security product.
