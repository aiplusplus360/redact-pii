import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from redactpii.cli import main


def run(args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "log.txt"
        self.path.write_text("mail a@b.co card 4242 4242 4242 4242\n", encoding="utf-8")

    def test_scan_json(self):
        code, out, _ = run(["scan", str(self.path), "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload[0]["counts"], {"email": 1, "card": 1})

    def test_scan_fail_on_found(self):
        code, _, _ = run(["scan", str(self.path), "--fail-on-found"])
        self.assertEqual(code, 1)

    def test_scan_clean_text_exits_zero(self):
        clean = Path(self.tmp.name) / "clean.txt"
        clean.write_text("nothing here\n", encoding="utf-8")
        code, _, _ = run(["scan", str(clean), "--fail-on-found"])
        self.assertEqual(code, 0)

    def test_redact_stdout(self):
        code, out, _ = run(["redact", str(self.path)])
        self.assertEqual(code, 0)
        self.assertIn("[REDACTED:email]", out)
        self.assertNotIn("a@b.co", out)

    def test_redact_to_file(self):
        target = Path(self.tmp.name) / "out.txt"
        code, _, _ = run(["redact", str(self.path), "-o", str(target)])
        self.assertEqual(code, 0)
        self.assertIn("[REDACTED:card]", target.read_text(encoding="utf-8"))

    def test_kind_filter(self):
        code, out, _ = run(["redact", str(self.path), "--kinds", "email"])
        self.assertEqual(code, 0)
        self.assertIn("[REDACTED:email]", out)
        self.assertIn("4242 4242 4242 4242", out)

    def test_unknown_kind_is_rejected(self):
        with self.assertRaises(SystemExit):
            run(["scan", str(self.path), "--kinds", "nonsense"])


if __name__ == "__main__":
    unittest.main()
