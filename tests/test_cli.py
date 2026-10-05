import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from inventory_lab.cli import main, serialize
from inventory_lab.admission import AdmissionError
from test_model import CASES


class CliTests(unittest.TestCase):
    def setUp(self):
        workspace = Path(__file__).resolve().parents[1]
        temporary = workspace / ".test-work"
        temporary.mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=temporary)
        if not Path(self.directory.name).resolve().is_relative_to(workspace):
            raise RuntimeError("Test temporary directory left workspace")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.fixture = self.root / "synthetic.json"
        self.fixture.write_text(json.dumps(CASES[0]["input"]), encoding="utf-8")

    def run_cli(self, arguments, out=None, err=None):
        out = io.BytesIO() if out is None else out
        err = io.BytesIO() if err is None else err
        return main(arguments, stdout=out, stderr=err), out, err

    def test_frozen_cli_outcomes(self):
        expected_codes = {"invalid": 2, "unsupported": 3, "limit": 4}
        for case in CASES:
            with self.subTest(case=case["id"]):
                self.fixture.write_text(json.dumps(case["input"]), encoding="utf-8")
                status, out, err = self.run_cli([str(self.fixture)])
                expected = case["expected"]
                exit_code = (0 if expected["consistency"] == "consistent" else 1) if expected["status"] == "complete" else expected_codes[expected["status"]]
                self.assertEqual(status, exit_code)
                report = json.loads(out.getvalue())
                self.assertEqual(report["status"], expected["status"])
                self.assertEqual(sorted(item["code"] for item in report["findings"]), sorted(expected["codes"]))
                self.assertEqual(err.getvalue(), b"")

    def test_exclusive_output_and_input_alias(self):
        target = self.root / "report.json"
        code, out, err = self.run_cli([str(self.fixture), "--output", str(target)])
        self.assertEqual(code, 0)
        self.assertEqual(out.getvalue(), b"")
        original = target.read_bytes()
        code, out, err = self.run_cli([str(self.fixture), "--output", str(target)])
        self.assertEqual(code, 5)
        self.assertEqual(target.read_bytes(), original)
        self.assertEqual(out.getvalue(), b"")
        self.assertNotIn(str(target).encode(), err.getvalue())
        original = self.fixture.read_bytes()
        self.assertEqual(self.run_cli([str(self.fixture), "--output", str(self.fixture)])[0], 5)
        self.assertEqual(self.fixture.read_bytes(), original)
        code, out, err = self.run_cli([str(self.fixture), "--output", ""])
        self.assertEqual(code, 5)
        self.assertEqual(out.getvalue(), b"")
        self.assertEqual(json.loads(err.getvalue())["error"]["code"], "output_io")

    def test_short_flush_closed_output_failures(self):
        class Short(io.BytesIO):
            def write(self, data):
                super().write(data[:4])
                return 4
        class Flush(io.BytesIO):
            def flush(self):
                raise OSError("private exception")
        closed = io.BytesIO()
        closed.close()
        for out in (Short(), Flush(), closed):
            with self.subTest(kind=type(out).__name__):
                status, _, err = self.run_cli([str(self.fixture)], out=out)
                self.assertEqual(status, 5)
                self.assertIsNone(json.loads(err.getvalue())["consistency"])
                self.assertNotIn(b"private exception", err.getvalue())
        status, _, _ = self.run_cli([str(self.fixture)], out=closed, err=closed)
        self.assertEqual(status, 5)

    def test_file_close_failure(self):
        class BadClose(io.BytesIO):
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                raise OSError("close failed")
        original_open = open
        def controlled_open(path, mode):
            return BadClose() if mode == "xb" else original_open(path, mode)
        with patch("inventory_lab.cli.open", side_effect=controlled_open):
            status, out, err = self.run_cli([str(self.fixture), "--output", str(self.root / "fresh.json")])
        self.assertEqual(status, 5)
        self.assertEqual(out.getvalue(), b"")
        self.assertEqual(json.loads(err.getvalue())["error"]["code"], "output_io")

    def test_output_limit_seam_before_open(self):
        target = self.root / "report.json"
        with patch("inventory_lab.model.MAX_OUTPUT", 1):
            status, out, err = self.run_cli([str(self.fixture), "--output", str(target)])
        self.assertEqual(status, 4)
        self.assertFalse(target.exists())
        self.assertEqual(out.getvalue(), b"")
        self.assertEqual(json.loads(err.getvalue())["error"]["code"], "output_limit")

    def test_usage_io_limits_escaping_and_path_rejection(self):
        for args in ([], ["--unknown", "\x1bPRIVATE"], ["missing\x1bfile"]):
            status, out, err = self.run_cli(args)
            self.assertIn(status, (2, 5))
            self.assertEqual(out.getvalue(), b"")
            self.assertNotIn(b"\x1b", err.getvalue())
            self.assertNotIn(b"PRIVATE", err.getvalue())
        self.assertEqual(self.run_cli(["//not-a-real-network/fixture"])[0], 5)
        self.fixture.write_bytes(b" " * 65_537)
        status, out, err = self.run_cli([str(self.fixture)])
        self.assertEqual(status, 4)
        self.assertEqual(json.loads(out.getvalue())["error"]["code"], "input_limit")
        self.assertEqual(err.getvalue(), b"")
        raw = serialize({"untrusted_test": "<script>\x1b\n\u202e"})
        self.assertNotIn(b"\x1b", raw)
        self.assertIn(b"\\u001b", raw)
        self.assertIn(b"\\u202e", raw)


if __name__ == "__main__":
    unittest.main()
