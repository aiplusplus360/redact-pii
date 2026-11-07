import unittest

from redactpii.core import (
    find_pii,
    iban_ok,
    ipv4_ok,
    luhn_ok,
    redact,
    redaction_report,
    ssn_ok,
)


class LuhnTests(unittest.TestCase):
    def test_accepts_known_valid_numbers(self):
        for number in ("4242424242424242", "4111111111111111", "5555555555554444"):
            self.assertTrue(luhn_ok(number), number)

    def test_rejects_bad_check_digit(self):
        self.assertFalse(luhn_ok("4242424242424241"))

    def test_rejects_uniform_digits(self):
        # all zeros passes the checksum but is not a card
        self.assertFalse(luhn_ok("0000000000000000"))

    def test_rejects_wrong_length(self):
        self.assertFalse(luhn_ok("424242"))
        self.assertFalse(luhn_ok("42424242424242424242"))


class IbanTests(unittest.TestCase):
    def test_valid_ibans(self):
        self.assertTrue(iban_ok("GB82WEST12345698765432"))
        self.assertTrue(iban_ok("DE89370400440532013000"))

    def test_valid_iban_with_spaces(self):
        self.assertTrue(iban_ok("GB82 WEST 1234 5698 7654 32"))

    def test_bad_checksum(self):
        self.assertFalse(iban_ok("GB82WEST12345698765431"))

    def test_too_short(self):
        self.assertFalse(iban_ok("GB82"))


class SsnTests(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(ssn_ok("123-45-6789"))

    def test_reserved_areas(self):
        self.assertFalse(ssn_ok("000-12-3456"))
        self.assertFalse(ssn_ok("666-12-3456"))
        self.assertFalse(ssn_ok("912-12-3456"))

    def test_reserved_group_and_serial(self):
        self.assertFalse(ssn_ok("123-00-6789"))
        self.assertFalse(ssn_ok("123-45-0000"))


class Ipv4Tests(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(ipv4_ok("192.168.1.1"))

    def test_out_of_range(self):
        self.assertFalse(ipv4_ok("256.1.1.1"))

    def test_leading_zero_is_rejected(self):
        self.assertFalse(ipv4_ok("010.0.0.1"))


class FindTests(unittest.TestCase):
    def test_email(self):
        spans = find_pii("contact ops@example.com today")
        self.assertEqual([s.kind for s in spans], ["email"])
        self.assertEqual(spans[0].value, "ops@example.com")

    def test_card_with_separators(self):
        spans = find_pii("pay 4242 4242 4242 4242 now")
        self.assertEqual([s.kind for s in spans], ["card"])

    def test_order_number_is_not_a_card(self):
        self.assertEqual(find_pii("order 1234-5678-9012-3456 shipped"), [])

    def test_date_is_not_a_phone(self):
        self.assertEqual([s.kind for s in find_pii("on 2026-11-08 we shipped")
                          if s.kind == "phone"], [])

    def test_plain_id_is_not_a_phone(self):
        self.assertEqual(find_pii("transaction 88231904 recorded"), [])

    def test_phone_with_country_code(self):
        kinds = [s.kind for s in find_pii("call +44 20 7946 0958")]
        self.assertIn("phone", kinds)

    def test_ipv4_not_matched_inside_version(self):
        self.assertEqual(find_pii("version 1.2.3.4.5 build"), [])

    def test_jwt(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        self.assertEqual([s.kind for s in find_pii(token)], ["jwt"])

    def test_url_credentials(self):
        kinds = [s.kind for s in find_pii("https://user:hunter2@db.example.com/x")]
        self.assertIn("url_credentials", kinds)

    def test_email_inside_url_credentials_is_not_double_reported(self):
        spans = find_pii("https://user:hunter2@db.example.com/x")
        self.assertTrue(all(not (a.start < b.end and b.start < a.end)
                            for i, a in enumerate(spans) for b in spans[i + 1:]))

    def test_kind_filter(self):
        spans = find_pii("a@b.co 10.0.0.1", kinds=["ipv4"])
        self.assertEqual([s.kind for s in spans], ["ipv4"])

    def test_spans_are_sorted(self):
        spans = find_pii("10.0.0.1 then a@b.co")
        self.assertEqual([s.kind for s in spans], ["ipv4", "email"])


class RedactTests(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(redact("a@b.co"), "[REDACTED:email]")

    def test_leaves_clean_text_alone(self):
        text = "nothing sensitive here"
        self.assertIs(redact(text), text)

    def test_stable_tokens_repeat(self):
        out = redact("a@b.co a@b.co c@d.co", stable=True)
        self.assertEqual(out, "[REDACTED:email:1] [REDACTED:email:1] [REDACTED:email:2]")

    def test_custom_template(self):
        self.assertEqual(redact("a@b.co", template="<{kind}>"), "<email>")

    def test_multiple_kinds_in_order(self):
        out = redact("a@b.co 10.0.0.1")
        self.assertEqual(out, "[REDACTED:email] [REDACTED:ipv4]")

    def test_offsets_preserved_for_clean_text(self):
        text = "prefix a@b.co suffix"
        self.assertEqual(redact(text), "prefix [REDACTED:email] suffix")


class ReportTests(unittest.TestCase):
    def test_counts(self):
        report = redaction_report("a@b.co, c@d.co, 10.0.0.1")
        self.assertEqual(report["total"], 3)
        self.assertEqual(report["counts"], {"email": 2, "ipv4": 1})

    def test_offsets_are_indices(self):
        report = redaction_report("x a@b.co")
        self.assertEqual(report["spans"][0]["offset"], 2)


if __name__ == "__main__":
    unittest.main()
