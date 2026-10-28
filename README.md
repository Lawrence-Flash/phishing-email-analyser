# phishing-email-analyser

Offline terminal tool that scores a saved `.eml` file for phishing signals and writes a plain-English report plus defanged indicators. The package is `phishcheck`. It uses the Python standard library only.

I am Lawrence Tshabalala, a junior cybersecurity analyst / DevSecOps in South Africa. This is a portfolio project for the first pass I would make on a user-reported phishing email: open the `.eml`, do not open the attachment, and write down why the message is or is not worth escalating. It is not a mail gateway and it does not claim a detection rate.

## Quick start

Requires Python 3.10 or newer. No install step and no third-party packages. From the repository root:

```bash
python3 -m phishcheck demo
python3 -m phishcheck analyse samples/05-phish-sars-refund.eml
python3 -m phishcheck analyse samples/05-phish-sars-refund.eml --json
python3 -m phishcheck analyse samples/05-phish-sars-refund.eml \
  --report docs/example-report.md \
  --ioc-json docs/example-iocs.json \
  --ioc-csv docs/example-iocs.csv
python3 -m unittest discover -s tests -v
```

`analyse` prints a markdown report. `--json` prints the same analysis as JSON instead. `--report`, `--ioc-json`, and `--ioc-csv` write files. Exit code 0 means the file was analysed. Exit code 2 means the file was missing or the brands file could not be read. A phishing verdict is still exit code 0, so the score is in the output rather than the status code.

The tool is offline unless you pass `--dns`.

## What it checks

- Headers: From against Reply-To and Return-Path, display-name spoofing (for example "FNB Support" on a non-FNB domain), Received hops with timestamps and IPs, Message-ID domain.
- Authentication-Results and Received-SPF: SPF, DKIM, and DMARC as the receiving server recorded them. The report quotes those headers. It does not re-verify DKIM signatures.
- Lookalike domains: Unicode and punycode homoglyphs, typos of longer brand names, brand tokens such as `fnb-secure` or `sars-efiling`, brand domains stuffed in front of another parent, and a list of TLDs often seen in opportunistic phishing.
- Links from the text and HTML parts: visible text versus href, IP-address URLs, known shorteners, credential-harvest words in the path or query, `data:` URIs, and `javascript:` links.
- Attachments: name, content type, size, SHA-256. Flags risky extensions (`.exe`, `.scr`, `.js`, `.vbs`, `.iso`, `.lnk`, and a short list of close cousins), double extensions, macro-enabled Office types, and HTML attachments.
- Content: urgency or threat language, payment or bank-detail changes, gift cards, and South African lures (SARS refund, eFiling, SASSA, NSFAS, courier fees, PIN or OTP requests, plus a few Afrikaans phrases).

The watched brands live in `phishcheck/brands.py`: major South African banks, SARS, SASSA, Vodacom, MTN, Telkom, Cell C, Rain, couriers (DHL, FedEx, UPS, Aramex, The Courier Guy, Fastway, PAXI, RAM), Takealot, and a short global list (Microsoft, Google, Apple, Amazon, PayPal, Netflix, LinkedIn, Meta, Dropbox, Adobe). Add to that list with `--brands file.json`. The file is merged with the built-in list unless it sets `"replace": true`.

```json
{
  "brands": [
    {"name": "Example Bank", "domains": ["example.bank"], "tokens": ["examplebank"]}
  ]
}
```

Short tokens such as `fnb`, `mtn`, and `absa` are matched exactly or as compounds (`fnb-secure`). They are not fuzzy-matched. `rain` as a whole label is not scored, because it is an ordinary word; `rain-secure` still is.

## Example output

This is the demo command against the eight synthetic samples:

```text
phishcheck demo — synthetic samples only. Scores are a heuristic checklist.
Sample                                       Score  Verdict
01-legit-colleague.eml                           9  likely safe
02-legit-newsletter.eml                          0  likely safe
03-legit-invoice-pdf.eml                         0  likely safe
04-phish-fnb-display-spoof.eml                 100  likely phishing
05-phish-sars-refund.eml                       100  likely phishing
06-phish-delivery-fee.eml                      100  likely phishing
07-phish-giftcard-otp.eml                       68  likely phishing
08-phish-invoice-attachment.eml                100  likely phishing
Likely-safe samples should sit under 25. The phishing samples should sit at 60 or above.
```

`02-legit-newsletter.eml` is authenticated and scores 0. These lines are copied from the report:

```text
- Subject: October project update
- From: Team News <team@news[.]example>
- Score: 0/100
- Verdict: **likely safe**
```

```text
| SPF | pass |
| DKIM | pass |
| DMARC | pass |
```

`07-phish-giftcard-otp.eml` is the case I care about in triage. The headers record SPF, DKIM, and DMARC as pass, and the score is still 68 because the body asks for Google Play gift cards and PIN codes while Reply-To and Return-Path point elsewhere:

```text
- Subject: Need gift cards today
- From: Finance Director <director@example[.]com>
- Reply-To: Cards <giftcards@example[.]net>
- Score: 68/100
- Verdict: **likely phishing**
```

```text
| SPF | pass |
| DKIM | pass |
| DMARC | pass |
```

Passing authentication means the receiver accepted the sending domain. It does not mean the display name is the person who wrote the mail.

`08-phish-invoice-attachment.eml` is a typosquat of Standard Bank with two attachments. The tool lists them and hashes the bytes. It does not open them:

```text
| Name | Type | Size | SHA-256 |
| --- | --- | ---: | --- |
| invoice.pdf.exe | application/octet-stream | 44 | `3476beaef492f1824fdcb69bbc1faa717b949a6070d7b21ecf289c2031eb41cf` |
| payment.docm | application/vnd.ms-word.document.macroenabled.12 | 51 | `41f305d7dc2e25a3ac4608bee3f15a69bc48c4bdc857c3f310e13bf1398529f0` |
```

The full report for the SARS refund sample is `docs/example-report.md`, generated by the tool. Opening of that report:

```text
- File: samples/05-phish-sars-refund.eml
- Subject: SARS refund waiting on eFiling
- From: SARS eFiling <refunds@sars-efiling[.]example>
- Score: 100/100 (raw 157, capped at 100)
- Verdict: **likely phishing**
```

The highest single signal in that file is a punycode host, `xn--srs-6cd[.]example`, which decodes to a Cyrillic lookalike of `sars`. The visible link text points at the real SARS eFiling host. The href does not. SPF is recorded as softfail, DKIM as none, DMARC as fail. URLs in the report are defanged (`hxxp`, `[.]`).

Regenerate those files with:

```bash
python3 -m phishcheck analyse samples/05-phish-sars-refund.eml \
  --report docs/example-report.md \
  --ioc-json docs/example-iocs.json \
  --ioc-csv docs/example-iocs.csv
```

## Scoring

Each signal fires at most once. Points add up and the total is capped at 100.

- 0-24: likely safe
- 25-59: suspicious
- 60-100: likely phishing

The numbers are a checklist so a reviewer can see why a message crossed a line. They are not a probability.

| Analyser | Code | Points | What it means |
| --- | --- | ---: | --- |
| headers | `header-reply-to-mismatch` | 15 | Reply-To domain differs from From |
| headers | `header-return-path-mismatch` | 10 | Return-Path domain differs from From |
| headers | `header-display-spoof` | 20 | Display name mentions a watched brand but the address is not that brand |
| headers | `header-display-address` | 18 | Display name contains an email address that is not the real From |
| headers | `header-message-id-mismatch` | 8 | Message-ID domain differs from From (weak; relays do this too) |
| headers | `header-message-id-missing` | 2 | No Message-ID header |
| auth | `auth-spf-fail` | 15 | Receiving server recorded SPF fail or hardfail |
| auth | `auth-spf-softfail` | 8 | Receiving server recorded SPF softfail |
| auth | `auth-spf-neutral` | 4 | Receiving server recorded SPF neutral |
| auth | `auth-spf-permerror` | 6 | Receiving server recorded SPF permerror |
| auth | `auth-spf-temperror` | 4 | Receiving server recorded SPF temperror |
| auth | `auth-spf-none` | 3 | Receiving server recorded SPF none |
| auth | `auth-spf-missing` | 3 | No SPF result in Authentication-Results or Received-SPF |
| auth | `auth-dkim-fail` | 12 | Receiving server recorded DKIM fail or hardfail |
| auth | `auth-dkim-neutral` | 4 | Receiving server recorded DKIM neutral |
| auth | `auth-dkim-permerror` | 6 | Receiving server recorded DKIM permerror |
| auth | `auth-dkim-temperror` | 4 | Receiving server recorded DKIM temperror |
| auth | `auth-dkim-none` | 3 | Receiving server recorded DKIM none |
| auth | `auth-dkim-missing` | 3 | No DKIM result in Authentication-Results |
| auth | `auth-dmarc-fail` | 18 | Receiving server recorded DMARC fail or hardfail |
| auth | `auth-dmarc-neutral` | 4 | Receiving server recorded DMARC neutral |
| auth | `auth-dmarc-permerror` | 6 | Receiving server recorded DMARC permerror |
| auth | `auth-dmarc-temperror` | 4 | Receiving server recorded DMARC temperror |
| auth | `auth-dmarc-none` | 3 | Receiving server recorded DMARC none |
| auth | `auth-dmarc-missing` | 3 | No DMARC result in Authentication-Results |
| lookalike | `lookalike-homoglyph` | 25 | Domain uses confusable characters or punycode to imitate a brand |
| lookalike | `lookalike-subdomain-trick` | 22 | A watched domain appears under a different parent |
| lookalike | `lookalike-typosquat` | 18 | Registrable label is one edit from a brand of 5+ characters |
| lookalike | `lookalike-keyword` | 16 | Domain label contains a brand token (fnb-secure, sars-efiling) |
| lookalike | `lookalike-typosquat-weak` | 12 | Registrable label is two edits from a brand of 5+ characters |
| lookalike | `lookalike-mixed-script` | 12 | A label mixes Latin with Cyrillic or Greek and is not already a brand homoglyph |
| lookalike | `lookalike-suspicious-tld` | 10 | Domain uses a TLD often seen in opportunistic phishing |
| links | `link-href-mismatch` | 20 | Visible text looks like a different URL or domain than the href |
| links | `link-ip-address` | 15 | Link host is an IPv4 or IPv6 address |
| links | `link-script-uri` | 20 | href uses the javascript scheme |
| links | `link-shortener` | 10 | Link host is a known shortener |
| links | `link-credential` | 12 | Path or query contains login, verify, password, OTP, or similar |
| links | `link-data-uri` | 25 | href or body contains a data URI |
| attachments | `attachment-risky` | 25 | Executable, script, disk image, shortcut, or similar extension |
| attachments | `attachment-double-ext` | 20 | Filename hides a risky, HTML, or macro extension behind another suffix |
| attachments | `attachment-macro` | 18 | Macro Office extension or macroEnabled content type |
| attachments | `attachment-html` | 15 | HTML file attached (common credential-harvest wrapper) |
| content | `content-urgency` | 8 | Urgent, suspended-account, or act-now wording |
| content | `content-payment-change` | 15 | Asks to use a new or changed bank account |
| content | `content-gift-card` | 12 | Asks for gift cards, store credit, or airtime vouchers |
| content | `content-sa-lure` | 12 | SARS refund, eFiling, SASSA, NSFAS, or courier fee wording |
| content | `content-otp` | 15 | Asks for a PIN, OTP, or one-time password |

A suspicious TLD on its own is 10 points, so a legitimate mail that links to a `.xyz` domain can move, but not into the phishing band by itself. Missing authentication is 3 points per mechanism. The colleague sample has no Authentication-Results header and scores 9, which stays in "likely safe".

## IOC export

`--ioc-json` and `--ioc-csv` write observed indicators: sender domains, link targets, Received IPs, and attachment SHA-256 hashes. URLs and domains are defanged (`hxxp`, `[.]`). CSV columns are `type,value,context,reserved`.

Official brand domains are left out, including domains that appear only as the visible text of a link. A lure that displays `sars.gov.za` should not become a block rule for SARS. `reserved` is true for RFC 2606 names and RFC 5737 documentation addresses.

Do not load the file into a blocklist without reading it. The copies checked into `docs/example-iocs.json` and `docs/example-iocs.csv` are from the SARS sample, and every indicator in them is reserved.

## Optional DNS

```bash
python3 -m phishcheck analyse message.eml --dns
python3 -m phishcheck analyse message.eml --dns --dns-server 1.1.1.1
```

`--dns` fetches the TXT record at the From domain (and the Return-Path domain when it differs) plus `_dmarc.<domain>`. If `dig` is on `PATH` it is used. Otherwise a small UDP resolver in the standard library sends a TXT query to the first IPv4 nameserver in `/etc/resolv.conf`, or to 1.1.1.1 when that file has none. `--dns-server` overrides that address.

The lookup reports whether an SPF or DMARC record is published, and the DMARC `p=` value when it is present. It does not walk SPF `include:` mechanisms, it does not compare the record to the sending IP, and it does not fetch DKIM keys. It does not change the score. It does send the domain name to the resolver.

## Samples

`samples/` holds eight synthetic messages, marked with `X-Phishcheck-Sample: synthetic` and a banner in the body. Names are under `.example`, `example.com`, `example.net`, or `example.org`. IPs are in the documentation ranges from RFC 5737. The two messages that imitate a real site put that site in the visible link text only. The href stays on a reserved name. `scripts/build_samples.py` rewrites the files.

| File | Role |
| --- | --- |
| `01-legit-colleague.eml` | Ordinary mail, no authentication headers, score 9 |
| `02-legit-newsletter.eml` | Authenticated note, score 0 |
| `03-legit-invoice-pdf.eml` | Invoice with a PDF, score 0 |
| `04-phish-fnb-display-spoof.eml` | FNB display name, lookalike domain, failed auth, mismatched link |
| `05-phish-sars-refund.eml` | SARS refund, punycode host, OTP |
| `06-phish-delivery-fee.eml` | Courier fee, IP URL, HTML attachment |
| `07-phish-giftcard-otp.eml` | Gift cards and PIN codes even though auth headers say pass |
| `08-phish-invoice-attachment.eml` | Typosquat, `invoice.pdf.exe`, macro Office file |

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The tests cover each analyser and the scorer, including cases that should stay quiet (an official `fnb.co.za` address, a normal PDF, "payment is due within 30 days", "not urgent"). DNS tests use a crafted packet and mocks. They do not contact a resolver. One test checks that `analyse` without `--dns` never calls the lookup. Another checks that the committed example report still matches the current renderer.

GitHub Actions runs the tests on Python 3.10, 3.11, and 3.12, then runs `python3 -m phishcheck demo`. CodeQL analyses the Python. Gitleaks scans the git history. Dependabot updates the Actions.

## Limitations

- The score is a heuristic. A careful phish can score low. An odd legitimate mail can score higher. I have not measured a true-positive or false-positive rate, and this README does not invent one.
- Authentication results are whatever the headers say. DKIM signatures are not checked cryptographically. SPF is not evaluated against the connecting IP.
- `--dns` only fetches TXT records. A published record is not the same thing as a pass.
- The homoglyph map is a practical set of Latin, Cyrillic, and Greek lookalikes plus a few digits. It is not the Unicode confusables list (UTS #39).
- The brand list is incomplete. A local company that is not in the file will not be flagged as a lookalike until you add it.
- Message-ID domains are compared with From. Mail that really did come from a different platform can pick up 8 points. That signal alone does not leave the safe band.
- A free mailbox never counts as aligned with a brand, including domains the brand owns (`outlook.com`, `gmail.com`, `icloud.com`). "Microsoft" on an outlook.com address is scored as a display-name spoof.
- Suspicious TLDs are scored even when the name is not a watched brand.
- HTML is not rendered. Tracking pixels, CSS, and attachment detonation are out of scope. `javascript:` links are flagged and the script body is dropped from the report. SVG is not in the risky-extension list.
- There is no Safe Browsing, VirusTotal, or other reputation lookup.
- This is not a secure email gateway and it does not replace the verdict from the mail product in front of the mailbox.

## Safe handling

Analyse `.eml` files. Do not open the attachments, and do not open a suspicious `.eml` in a mail client that renders HTML or follows links. phishcheck hashes attachment bytes and reads headers and body text. It does not execute anything in the message.

The samples are fixtures. They are still email files. Treat them the same way: run the tool, do not double-click the attachments.

Defanged output is for notes and tickets. Putting the dots back and visiting the URL is on you.

## What I learned

I started by wanting the tool to "check DKIM". Reading how DKIM actually works changed that. Re-verifying a signature means reconstructing the signed header set, canonicalising the body, and checking it against a key in DNS. A half implementation would print "pass" for a check I had not done. The report now says the receiving server recorded `dkim=fail` or `dkim=pass`, and it says that is a quote.

Edit distance taught me the same kind of lesson on names. Fuzzy matching `fnb` or `mtn` flags ordinary words. Those brands are matched as tokens and compounds. Longer names such as `standardbank` can take an edit-distance check. `standardbnk.example` is one deletion away and is a sample for that path. `rain` is both an ISP and an English word, so the bare label is not scored.

The South African wording is the part I wanted the checklist to reflect: SARS refunds, eFiling, a SASSA grant, a courier release fee, and a request for a PIN or OTP. I matched phrases rather than the word "payment" or "account", because a real invoice says "payment is due" and should stay at zero. A few Afrikaans cues (`dringend`, `rekening opgeskort`, `afleweringskoste`) sit in the same lists. I am not claiming those phrases are a complete picture of local phishing.

The gift-card sample is the one I would take into a conversation. Authentication headers all say pass, and the score is still 68. That is the difference between "the domain was allowed to send" and "the request is safe".

Defanging and the sample rules are there because I would paste this output into a ticket. `hxxp` and `[.]` make a copied URL inert. `data:` and `javascript:` bodies are omitted so the report does not become a copy of the payload. The samples stay on documentation names and addresses, and a unit test fails if a URL in `samples/` is not reserved or a watched brand's real domain used only as lure text. A portfolio fixture that points at a live lookalike is a liability.

The bands are round on purpose: 0-24, 25-59, 60-100. I can defend a round threshold. I cannot defend a fake percentage.

## License

MIT. See [LICENSE](LICENSE).
