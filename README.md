# redact-pii

**Find personal data with validators that reject lookalikes — so an order number is not a credit card and a date is not a phone number.**

[![CI](https://github.com/aiplusplus360/redact-pii/actions/workflows/ci.yml/badge.svg)](https://github.com/aiplusplus360/redact-pii/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](pyproject.toml)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

```console
$ redact-pii scan app.log
app.log: 4 finding(s)
  card   1
  email  2
  ipv4   1

$ redact-pii redact app.log --stable
user [REDACTED:email:1] paid with [REDACTED:card:1] from [REDACTED:ipv4:1]
user [REDACTED:email:2] upgraded
support replied to [REDACTED:email:1]
```

---

## Why this exists

Redaction tools fail in one of two directions.

**They miss data.** A regex that only knows `\d{16}` misses `4242 4242 4242 4242` and `4242-4242-4242-4242`.

**They over-redact.** A regex that matches any digit run turns every order id, port, timestamp and version string into `[REDACTED]`, and the log becomes worthless — which is the same as deleting it.

The distinction between the two is a **validator**. A card number has a check digit. An IBAN has a mod-97 checksum. An SSN has reserved ranges. An IPv4 address has bounded octets. A phone number is not a date. Every detector here ends in one of those constraints, so a match means something.

## What is detected

| Kind | Validator | Example rejected |
| --- | --- | --- |
| `email` | structural | `a@b` |
| `card` | Luhn, 13–19 digits, not uniform | `1234-5678-9012-3456` |
| `iban` | mod-97, 15–34 chars | wrong check digits |
| `ssn` | reserved areas `000`/`666`/`9xx`, group `00`, serial `0000` | `000-12-3456` |
| `phone` | 7–15 digits, and `+`/separator/leading zero | `transaction 88231904` |
| `ipv4` | octets 0–255, no leading zeros | `10.0.0.256` |
| `ipv6` | at least two colons | `12:30` |
| `jwt` | three base64url segments | — |
| `url_credentials` | `scheme://user:pass@` | — |

## Overlap rules

An earlier version reported `user` and `hunter2` as an email when the text was `https://user:hunter2@db.example.com`. Overlapping detections are resolved longest-first, left to right: a span fully inside an accepted span is dropped, never reported twice. That keeps output byte offsets stable, which matters when the redacted text has to line up with the original.

## Stable tokens

`--stable` gives every distinct value a distinct token, consistently:

```console
$ redact-pii redact log.txt --stable
[REDACTED:email:1] and [REDACTED:email:2] met [REDACTED:email:1]
```

Without it, all emails become `[REDACTED:email]` — fine for sharing, useless for "find the log line where the same address appears twice".

## Install and use

No dependencies. Python 3.9+.

```bash
pip install git+https://github.com/aiplusplus360/redact-pii
```

```bash
redact-pii scan app.log --kinds email,card --json
redact-pii scan app.log --fail-on-found          # exit 1 in CI
redact-pii redact app.log -o app.safe.log
cat app.log | redact-pii redact -
```

Exit codes: `0` clean, `1` findings (with `--fail-on-found`), `2` unreadable input.

## Library use

```python
from redactpii import find_pii, redact, redaction_report

for span in find_pii(text):
    print(span.kind, span.start, span.end, span.value)

safe = redact(text, kinds=["email", "card"], stable=True)
report = redaction_report(text)   # counts and offsets, no values
```

`redaction_report` deliberately omits the matched values: it is safe to log, which is the point.

## Tests

```bash
python -m unittest discover -s tests -v
```

34 unit tests plus 6 CLI tests: every validator against valid and invalid inputs, the false-positive cases that matter (order numbers, dates, version strings), overlap resolution, stable token identity, and the CLI contract.
