"""Known benign defects in owned isolated copies; never edit the original model."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]


def main():
    source = ROOT / "inventory_lab" / "model.py"
    original = source.read_bytes()
    text = original.decode("utf-8")
    recipes = [
        ("skip_unknown_reference", 'finding("unknown_reference", path, {"id": label})',
         'pass  # deliberate omission of unknown-reference evidence',
         "test_frozen_cases"),
        ("choose_last_duplicate", 'by_id = _groups(data["components"], lambda item: item["id"])',
         'by_id = _groups(data["components"], lambda item: item["id"])\n    by_id = {key: indices[-1:] for key, indices in by_id.items()}',
         "test_no_last_duplicate_selection"),
        ("cycle_inconsistent", 'result["consistency"] = "inconsistent" if findings else "consistent"',
         'result["consistency"] = "inconsistent" if findings or (graph["cycles"] if graph["available"] else None) else "consistent"',
         "test_frozen_cases"),
    ]
    work = ROOT / ".verification-work" / ("mutations-" + uuid.uuid4().hex)
    work.mkdir(parents=True)
    if not work.resolve().is_relative_to(ROOT):
        raise RuntimeError("Mutation workspace escaped project")
    results = []
    for name, old, new, expected_test in recipes:
        if text.count(old) != 1:
            raise RuntimeError("Mutation anchor must be unique")
        destination = work / name
        shutil.copytree(ROOT / "inventory_lab", destination / "inventory_lab", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(ROOT / "tests", destination / "tests", ignore=shutil.ignore_patterns("__pycache__"))
        (destination / "scripts").mkdir()
        shutil.copyfile(ROOT / "scripts" / "run_tests.py", destination / "scripts" / "run_tests.py")
        mutated = text.replace(old, new, 1)
        compile(mutated, "owned_mutant_model.py", "exec")
        (destination / "inventory_lab" / "model.py").write_text(mutated, encoding="utf-8")
        command = [sys.executable, "-I", str(destination / "scripts" / "run_tests.py")]
        process = subprocess.run(command, cwd=destination, capture_output=True, timeout=30, check=False, shell=False)
        output = process.stdout + process.stderr
        (destination / "test-output.txt").write_bytes(output)
        # Intended behavioral assertions must fail, not syntax/import/transport errors.
        caught = (process.returncode == 1 and b"AssertionError" in output and
                  b"FAILED (failures=" in output and b"ERROR:" not in output and
                  (b"FAIL: " + expected_test.encode()) in output)
        results.append({"mutation": name, "caught_by_assertion": caught, "exit": process.returncode,
                        "mutated_sha256": hashlib.sha256(mutated.encode()).hexdigest(), "expected_test": expected_test})
    if source.read_bytes() != original:
        raise RuntimeError("Original source changed during isolated mutations")
    summary = {"results": results, "original_unchanged": True,
               "original_sha256": hashlib.sha256(original).hexdigest(), "work_directory": str(work)}
    (work / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"mutations": len(results), "caught": sum(row["caught_by_assertion"] for row in results),
                      "original_unchanged": True, "results": results,
                      "original_sha256": summary["original_sha256"]}))
    return 0 if all(row["caught_by_assertion"] for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
