"""Owned synthetic fixture transport; errors never imply successful delivery."""

import argparse
import json
import os
import stat
import sys

from . import model
from .admission import AdmissionError, MAX_INPUT

EXIT = {"invalid": 2, "unsupported": 3, "limit": 4}


def serialize(report):
    """Encode fully before delivery; retained text is escaped even for terminals."""
    encoded = (json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if len(encoded) > model.MAX_OUTPUT:
        raise AdmissionError("limit", "output_limit")
    return encoded


def _write(stream, data):
    # A partial write is a failed delivery, not a reason to announce success elsewhere.
    if stream.write(data) != len(data):
        raise OSError("short_write")
    stream.flush()


def _diagnostic(stream, code):
    data = (json.dumps({"status": "delivery_or_input_error", "evaluation": "incomplete",
                        "consistency": None, "error": {"code": code}}, ensure_ascii=True) + "\n").encode("ascii")
    try:
        _write(stream, data)
    except (OSError, ValueError):
        # Both output channels may be closed. Preserve failing exit status.
        return False
    return True


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise AdmissionError("invalid", "usage")


def _local_path(path):
    if path.startswith(("\\\\", "//", "\\?", "\\.")):
        raise OSError("nonlocal_path")
    # No Windows network/device/ADS targets in this owned-file teaching interface.
    if os.name == "nt" and ":" in os.path.splitdrive(path)[1]:
        raise OSError("alternate_stream")
    return path


def main(argv=None, *, stdout=None, stderr=None):
    """Exit status reflects both evaluation and actual report delivery.

    Paths must name owned ordinary synthetic files; no hostile-filesystem boundary.
    """
    out = sys.stdout.buffer if stdout is None else stdout
    err = sys.stderr.buffer if stderr is None else stderr
    parser = _Parser(prog="inventory-lab", description="Check supplied synthetic inventory declarations only.")
    parser.add_argument("input", help="Owned synthetic JSON fixture")
    parser.add_argument("--output", help="Fresh owned report file; exclusive creation")
    try:
        args = parser.parse_args(argv)
    except AdmissionError:
        _diagnostic(err, "usage")
        return 2
    try:
        # Regular-file check is only transport admission, never host inventory collection.
        with open(_local_path(args.input), "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise OSError("regular_file_required")
            raw = stream.read(MAX_INPUT + 1)
    except (OSError, ValueError):
        _diagnostic(err, "input_io")
        return 5
    report = model.evaluate_bytes(raw)
    try:
        payload = serialize(report)
    except AdmissionError:
        _diagnostic(err, "output_limit")
        return 4
    exit_code = (0 if report["consistency"] == "consistent" else 1) if report["status"] == "complete" else EXIT[report["status"]]
    try:
        if args.output is not None:
            with open(_local_path(args.output), "xb") as stream:
                _write(stream, payload)
        else:
            _write(out, payload)
    except (OSError, ValueError):
        _diagnostic(err, "output_io")
        return 5
    return exit_code
