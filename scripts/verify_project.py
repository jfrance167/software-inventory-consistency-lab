"""Repeatable owned-project checks with raw private logs and public source receipts.

Usage: python -I scripts/verify_project.py --bandit-python INSTALLED_PYTHON
No install, network, sample/host inventory or publication. Requires installed Bandit.
"""

import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import re
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bandit-python", default=sys.executable)
    args = parser.parse_args()
    work = ROOT / ".verification-work" / ("acceptance-" + uuid.uuid4().hex)
    work.mkdir(parents=True)
    if not work.resolve().is_relative_to(ROOT):
        raise RuntimeError("Verification directory escaped project")
    results = []

    def run(label, command, timeout=90):
        process = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=timeout, check=False, shell=False)
        (work / (label + ".stdout")).write_bytes(process.stdout)
        (work / (label + ".stderr")).write_bytes(process.stderr)
        results.append({"check": label, "exit": process.returncode})
        return process

    normal = run("normal", [sys.executable, "-I", "scripts/run_tests.py"])
    optimized = run("optimized", [sys.executable, "-I", "-O", "scripts/run_tests.py"])
    test_counts = {}
    for name, process in (("normal", normal), ("optimized", optimized)):
        match = re.search(rb"Ran (\d+) tests", process.stderr)
        test_counts[name] = int(match.group(1)) if match else None
    run("compile", [sys.executable, "-I", "-m", "compileall", "-q", "inventory_lab", "lab.py", "scripts", "tests"])
    mutations = run("mutations", [sys.executable, "-I", "scripts/verify_mutations.py"], 120)
    mutation_summary = json.loads(mutations.stdout) if mutations.returncode == 0 else None
    bandit_file = work / "bandit.json"
    run("bandit", [args.bandit_python, "-I", "-m", "bandit", "-r", "inventory_lab", "lab.py", "-f", "json", "-o", str(bandit_file)])
    scanner = json.loads(bandit_file.read_text(encoding="utf-8")) if bandit_file.exists() else None
    if scanner is None or scanner["results"] or scanner["errors"]:
        raise RuntimeError("Production SAST not clean/available")
    cases = json.loads((ROOT / "tests/cases.json").read_text(encoding="utf-8"))["cases"]
    cli_rows = []
    for case in cases:
        fixture = work / (case["id"] + ".json")
        fixture.write_text(json.dumps(case["input"]), encoding="utf-8")
        process = subprocess.run([sys.executable, "-I", "lab.py", str(fixture)], cwd=ROOT,
                                 capture_output=True, timeout=10, check=False, shell=False)
        (work / (case["id"] + ".report.json")).write_bytes(process.stdout)
        (work / (case["id"] + ".stderr")).write_bytes(process.stderr)
        expected = case["expected"]
        expected_exit = ((0 if expected["consistency"] == "consistent" else 1)
                         if expected["status"] == "complete" else {"invalid": 2, "unsupported": 3, "limit": 4}[expected["status"]])
        report = json.loads(process.stdout)
        passed = (process.returncode == expected_exit and not process.stderr and report["status"] == expected["status"] and
                  report["consistency"] == expected["consistency"] and
                  sorted(row["code"] for row in report["findings"]) == sorted(expected["codes"]))
        cli_rows.append({"case": case["id"], "exit": process.returncode, "expected_exit": expected_exit, "pass": passed})
    # Source inspection supports pure model I/O exclusions; it is not an OS sandbox.
    forbidden_imports = {"os", "socket", "subprocess", "pathlib", "requests", "urllib", "importlib", "pickle"}
    pure_files = [ROOT / "inventory_lab" / name for name in ("admission.py", "model.py", "graph.py")]
    for file in pure_files:
        tree = ast.parse(file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            imports = ([alias.name for alias in node.names] if isinstance(node, ast.Import) else
                       [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
            if any(name.split(".")[0] in forbidden_imports for name in imports):
                raise RuntimeError("Forbidden model import")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("open", "eval", "exec", "compile", "__import__"):
                raise RuntimeError("Forbidden model call")
    files = [ROOT / "lab.py", ROOT / "CONTRACT.md", ROOT / "tests/cases.json"]
    files += sorted((ROOT / "inventory_lab").glob("*.py"))
    files += sorted((ROOT / "tests").glob("*.py")) + sorted((ROOT / "scripts").glob("*.py"))
    hashes = [{"path": file.relative_to(ROOT).as_posix(), "bytes": file.stat().st_size,
               "sha256": hashlib.sha256(file.read_bytes()).hexdigest()} for file in files]
    final = {"generated_at_utc": datetime.now(timezone.utc).isoformat(), "runtime": sys.version, "platform": sys.platform,
             "test_counts": test_counts,
             "checks": results, "frozen_cases": len(cases), "cli_cases": cli_rows, "mutations": mutation_summary,
             "graph_oracle": {"nodes": 3, "graphs": 512, "algorithm": "independent boolean transitive closure"},
             "bandit": {"findings": 0, "errors": 0, "scope": "inventory_lab/ and lab.py; installed Bandit 1.9.4"},
             "pure_model_source_gate": "PASS; static import/call inspection, not containment proof",
             "source_sha256": hashes, "hosted": "NOT RUN", "real_inventory_used": False,
             "scope": "custom inventory-lab/1 synthetic declarations only"}
    (work / "receipt.json").write_text(json.dumps(final, indent=2) + "\n", encoding="utf-8")
    passed = all(row["exit"] == 0 for row in results) and all(row["pass"] for row in cli_rows)
    print(json.dumps({"pass": passed, "checks": results, "cli_pass": sum(row["pass"] for row in cli_rows),
                      "receipt": str(work / "receipt.json")}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
