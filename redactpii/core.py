"""Detect and redact personal data, with validators to suppress false positives.

The hard part of PII redaction is not finding digit runs. It is *not* finding
them: order numbers are not credit cards, version strings are not IPs, and a
date is not a phone number. Every detector here ends with a checksum or a
structural constraint, so a match means something.

>>> [s.kind for s in find_pii("write to ops@example.com")]
['email']
>>> redact("card 4242 4242 4242 4242 ok")
'card [REDACTED:card] ok'
>>> redact("order 1234-5678-9012-3456 shipped")   # fails the Luhn check
'order 1234-5678-9012-3456 shipped'
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "KINDS",
    "Span",
    "find_pii",
    "redact",
    "luhn_ok",
    "iban_ok",
    "ssn_ok",
    "ipv4_ok",
    "redaction_report",
]

KINDS = ("email", "card", "iban", "ssn", "phone", "ipv4", "ipv6", "jwt", "url_credentials")

_WORD = r"[A-Za-z0-9_]"


@dataclass(frozen=True)
class Span:
    """One detected value and the character range it occupies."""

    kind: str
    start: int
    end: int
    value: str
    confidence: str = "high"

    def __len__(self) -> int:
        return self.end - self.start


def luhn_ok(digits: str) -> bool:
    """Return True when ``digits`` passes the Luhn check.

    >>> luhn_ok("4242424242424242")
    True
    >>> luhn_ok("4242424242424241")
    False
    """
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    if len(set(digits)) == 1:            # 0000000000000000 passes Luhn
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def iban_ok(text: str) -> bool:
    """Return True when ``text`` is a structurally valid IBAN (mod-97).

    >>> iban_ok("GB82WEST12345698765432")
    True
    >>> iban_ok("GB82WEST12345698765431")
    False
    """
    candidate = re.sub(r"\s+", "", text).upper()
    if not 15 <= len(candidate) <= 34:
        return False
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", candidate):
        return False
    rearranged = candidate[4:] + candidate[:4]
    digits = "".join(str(int(ch, 36)) if ch.isalpha() else ch for ch in rearranged)
    return int(digits) % 97 == 1


def ssn_ok(text: str) -> bool:
    """Return True for an SSN in a range the SSA actually issues.

    >>> ssn_ok("123-45-6789"), ssn_ok("000-12-3456"), ssn_ok("666-12-3456")
    (True, False, False)
    """
    match = re.fullmatch(r"(\d{3})-(\d{2})-(\d{4})", text)
    if not match:
        return False
    area, group, serial = match.groups()
    if area == "000" or area == "666" or area.startswith("9"):
        return False
    if group == "00" or serial == "0000":
        return False
    return True


def ipv4_ok(text: str) -> bool:
    """Return True when ``text`` is four octets in range.

    >>> ipv4_ok("10.0.0.1"), ipv4_ok("10.0.0.256")
    (True, False)
    """
    parts = text.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 and str(int(part)) == part
               for part in parts)


_EMAIL = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
_CARD = re.compile(r"(?<![\w.-])(?:\d[ -]?){12,18}\d(?![\w.-])")
_IBAN = re.compile(r"(?<![\w])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}(?![\w])")
_SSN = re.compile(r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])")
_PHONE = re.compile(r"(?<![\w.+])(?:\+\d{1,3}[ -]?)?(?:\(\d{2,4}\)[ -]?)?\d{2,4}(?:[ -]\d{2,4}){1,4}(?![\w.])")
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_JWT = re.compile(r"(?<![\w-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_URL_CRED = re.compile(r"(?P<scheme>https?://)(?P<user>[^/\s:@]+):(?P<pw>[^/\s@]+)@")

_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}/\d{1,2}/\d{2,4}\b")


def _phone_ok(text: str) -> bool:
    digits = re.sub(r"\D", "", text)
    if not 7 <= len(digits) <= 15:
        return False
    if _DATE.fullmatch(text.strip()):
        return False
    # A bare digit run with no separator or international prefix is an id, not
    # a phone number. Requiring one of the two keeps order numbers out.
    return text.strip().startswith("+") or bool(re.search(r"[ ()-]", text.strip())) \
        or text.strip().startswith("0")


def _collect(pattern: re.Pattern, kind: str, text: str, validate=None,
             confidence: str = "high") -> List[Span]:
    spans: List[Span] = []
    for match in pattern.finditer(text):
        value = match.group(0)
        if validate is not None and not validate(value):
            continue
        stripped = value.strip()
        if not stripped:
            continue
        offset = match.start() + (len(value) - len(value.lstrip()))
        spans.append(Span(kind, offset, offset + len(stripped), stripped, confidence))
    return spans


def find_pii(text: str, kinds: Optional[Sequence[str]] = None) -> List[Span]:
    """Return non-overlapping PII spans, longest match first at each position.

    >>> [(s.kind, s.value) for s in find_pii("mail a@b.co or 10.1.2.3")]
    [('email', 'a@b.co'), ('ipv4', '10.1.2.3')]
    """
    wanted = set(kinds) if kinds else set(KINDS)
    candidates: List[Span] = []

    if "email" in wanted:
        candidates += _collect(_EMAIL, "email", text)
    if "card" in wanted:
        candidates += _collect(
            _CARD, "card", text,
            lambda v: luhn_ok(re.sub(r"\D", "", v)))
    if "iban" in wanted:
        candidates += _collect(_IBAN, "iban", text, iban_ok)
    if "ssn" in wanted:
        candidates += _collect(_SSN, "ssn", text, ssn_ok)
    if "jwt" in wanted:
        candidates += _collect(_JWT, "jwt", text)
    if "ipv4" in wanted:
        candidates += _collect(_IPV4, "ipv4", text, ipv4_ok)
    if "ipv6" in wanted:
        candidates += _collect(_IPV6, "ipv6", text,
                               lambda v: v.count(":") >= 2 and len(set(v)) > 2,
                               confidence="medium")
    if "url_credentials" in wanted:
        for match in _URL_CRED.finditer(text):
            candidates.append(Span("url_credentials", match.start(),
                                   match.end(), match.group(0)))
    if "phone" in wanted:
        candidates += _collect(_PHONE, "phone", text, _phone_ok, confidence="medium")

    # Longest span wins at a given position; a span nested inside an accepted
    # one is dropped rather than producing two overlapping redactions.
    candidates.sort(key=lambda s: (s.start, -len(s)))
    accepted: List[Span] = []
    for span in candidates:
        if any(span.start < other.end and other.start < span.end for other in accepted):
            continue
        accepted.append(span)
    return accepted


def redact(text: str, kinds: Optional[Sequence[str]] = None, *,
           stable: bool = False, template: str = "[REDACTED:{kind}]") -> str:
    """Replace every detected span. Identical values get the same token when stable.

    >>> redact("a@b.co and a@b.co", stable=True)
    '[REDACTED:email:1] and [REDACTED:email:1]'
    >>> redact("a@b.co and c@d.co", stable=True)
    '[REDACTED:email:1] and [REDACTED:email:2]'
    """
    spans = find_pii(text, kinds)
    if not spans:
        return text
    tokens: Dict[Tuple[str, str], str] = {}
    counters: Dict[str, int] = {}
    pieces: List[str] = []
    cursor = 0
    for span in spans:
        pieces.append(text[cursor:span.start])
        if stable:
            key = (span.kind, span.value)
            if key not in tokens:
                counters[span.kind] = counters.get(span.kind, 0) + 1
                head = template.format(kind=span.kind)
                if head.endswith("]"):
                    head = head[:-1] + ":%d]" % counters[span.kind]
                else:
                    head = "%s:%d" % (head, counters[span.kind])
                tokens[key] = head
            pieces.append(tokens[key])
        else:
            pieces.append(template.format(kind=span.kind))
        cursor = span.end
    pieces.append(text[cursor:])
    return "".join(pieces)


def redaction_report(text: str, kinds: Optional[Sequence[str]] = None) -> Dict[str, object]:
    """Summarise which kinds were found, by count and by example-free position.

    >>> report = redaction_report("a@b.co, 4242 4242 4242 4242")
    >>> report["total"], sorted(report["counts"])
    (2, ['card', 'email'])
    """
    spans = find_pii(text, kinds)
    counts: Dict[str, int] = {}
    for span in spans:
        counts[span.kind] = counts.get(span.kind, 0) + 1
    return {
        "total": len(spans),
        "counts": counts,
        "spans": [{"kind": s.kind, "offset": s.start, "length": len(s)} for s in spans],
    }
