import copy
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch

from inventory_lab.model import evaluate, evaluate_bytes

CASES = json.loads((Path(__file__).parent / "cases.json").read_text(encoding="utf-8"))["cases"]


class ModelTests(unittest.TestCase):
    def check_case(self, case):
        original = copy.deepcopy(case["input"])
        report, expected = evaluate(case["input"]), case["expected"]
        self.assertEqual(case["input"], original)
        for field in ("status", "consistency"):
            self.assertEqual(report[field], expected[field], (case["id"], field))
        self.assertEqual(sorted(item["code"] for item in report["findings"]), sorted(expected["codes"]), case["id"])
        self.assertEqual(set(report["assurances"].values()), {"unknown"})
        self.assertEqual(set(report), {"schema", "input_schema", "status", "evaluation", "consistency",
                                       "assurances", "limits", "counts", "findings", "observations", "error"})
        if report["status"] != "complete":
            self.assertIsNone(report["observations"])
            self.assertIsNone(report["counts"])
            self.assertEqual(report["evaluation"], "incomplete")
            return
        graph = report["observations"]["graph"]
        self.assertEqual(report["evaluation"], "complete")
        self.assertIsNone(report["error"])
        self.assertEqual(graph["available"], expected["graph_available"])
        self.assertEqual(graph["cycles"], expected["cycles"])
        self.assertEqual(graph["reachability"]["status"] if graph["reachability"] else None,
                         expected["reachability"])
        for field in ("reachable", "not_reached"):
            if field in expected:
                self.assertEqual(graph["reachability"][field], expected[field])
        if "declaration_kinds" in expected:
            self.assertEqual([group["kind"] for group in report["observations"]["declaration_groups"]],
                             expected["declaration_kinds"])

    def test_frozen_cases(self):
        for case in CASES:
            with self.subTest(case=case["id"]):
                self.check_case(case)

    def test_no_last_duplicate_selection(self):
        data = copy.deepcopy(next(case["input"] for case in CASES if case["id"] == "duplicate_references"))
        report = evaluate(data)
        self.assertFalse(report["observations"]["graph"]["available"])
        self.assertNotIn("assertion_mismatch", [item["code"] for item in report["findings"]])
        for item in report["findings"]:
            if item["code"] == "ambiguous_reference":
                self.assertEqual(item["evidence"]["component_indices"], [0, 1])
        report["findings"][0]["evidence"].clear()
        self.assertEqual(data, next(case["input"] for case in CASES if case["id"] == "duplicate_references"))

    def test_repaired_negatives(self):
        data = {"schema": "inventory-lab/1", "synthetic": True,
                "components": [{"id": "A", "name": "p", "version": "1", "sha256": None}],
                "edges": [{"source": "A", "target": "X"}], "assertions": [], "roots": []}
        self.assertEqual(evaluate(data)["consistency"], "inconsistent")
        data["components"].append({"id": "X", "name": "q", "version": "1", "sha256": None})
        self.assertEqual(evaluate(data)["consistency"], "consistent")
        data["components"].append(dict(data["components"][0]))
        self.assertFalse(evaluate(data)["observations"]["graph"]["available"])
        data["components"].pop()
        self.assertEqual(evaluate(data)["consistency"], "consistent")
        data["assertions"] = [{"target": "A", "name": "wrong", "version": "1", "sha256": None}]
        self.assertEqual(evaluate(data)["consistency"], "inconsistent")
        data["assertions"][0]["name"] = "p"
        self.assertEqual(evaluate(data)["consistency"], "consistent")

    def test_multiple_sccs_and_observation_only_cycles(self):
        data = {"schema": "inventory-lab/1", "synthetic": True,
                "components": [{"id": name, "name": name, "version": "1", "sha256": None} for name in "ABCDE"],
                "edges": [{"source": s, "target": t} for s, t in (("A", "B"), ("B", "A"), ("B", "C"),
                                                                   ("C", "D"), ("D", "C"), ("E", "E"))],
                "assertions": [], "roots": ["B"]}
        result = evaluate(data)
        self.assertEqual(result["consistency"], "consistent")
        graph = result["observations"]["graph"]
        self.assertEqual(graph["sccs"], [["A", "B"], ["C", "D"], ["E"]])
        self.assertEqual(graph["cycles"], [["A", "B"], ["C", "D"], ["E"]])
        self.assertEqual(graph["reachability"]["reachable"], ["A", "B", "C", "D"])

    def test_permutation_semantics_and_relocated_indices(self):
        data = copy.deepcopy(next(case["input"] for case in CASES if case["id"] == "chain"))
        before = evaluate(data)
        data["components"].reverse()
        data["edges"].reverse()
        after = evaluate(data)
        self.assertEqual(before, after)
        data["assertions"] = [{"target": "A", "name": "bad", "version": "1", "sha256": None}]
        before = evaluate(data)
        data["components"].reverse()
        after = evaluate(data)
        first, second = before["findings"][0], after["findings"][0]
        self.assertEqual(first["code"], second["code"])
        self.assertEqual(first["evidence"]["component_index"], 2)
        self.assertEqual(second["evidence"]["component_index"], 0)
        left, right = dict(first["evidence"]), dict(second["evidence"])
        left.pop("component_index")
        right.pop("component_index")
        self.assertEqual(left, right)

    def test_guard_seam_finding_limit(self):
        case = next(case for case in CASES if case["id"] == "unknown_both")
        with patch("inventory_lab.model.MAX_FINDINGS", 1):
            result = evaluate(case["input"])
        self.assertEqual(result["status"], "limit")
        self.assertIsNone(result["consistency"])
        self.assertEqual(result["findings"], [])

    def test_all_three_node_graphs_against_fixed_point_oracle(self):
        # Independent boolean transitive closure, not the production DFS/SCC algorithm.
        names = ["A", "B", "C"]
        for mask in range(512):
            edges = [(s, t) for i, (s, t) in enumerate((s, t) for s in names for t in names) if mask & (1 << i)]
            reach = [[s == t or (s, t) in edges for t in names] for s in names]
            for k in range(3):
                for i in range(3):
                    for j in range(3):
                        reach[i][j] = reach[i][j] or (reach[i][k] and reach[k][j])
            groups, consumed = [], set()
            for i, name in enumerate(names):
                if name not in consumed:
                    group = [other for j, other in enumerate(names) if reach[i][j] and reach[j][i]]
                    groups.append(group)
                    consumed.update(group)
            expected_cycles = [g for g in groups if len(g) > 1 or (g[0], g[0]) in edges]
            data = {"schema": "inventory-lab/1", "synthetic": True,
                    "components": [{"id": n, "name": n, "version": "1", "sha256": None} for n in names],
                    "edges": [{"source": s, "target": t} for s, t in edges], "assertions": [], "roots": ["A"]}
            result = evaluate(data)
            graph = result["observations"]["graph"]
            self.assertEqual(result["consistency"], "consistent", mask)
            self.assertEqual(graph["sccs"], groups, mask)
            self.assertEqual(graph["cycles"], expected_cycles, mask)
            self.assertEqual(graph["reachability"]["reachable"], [n for j, n in enumerate(names) if reach[0][j]], mask)

    def test_index_free_projection_permutation(self):
        def projection(value):
            if isinstance(value, dict):
                return {key: (re.sub(r"/\d+(?=/|$)", "/#", child) if key == "path" else projection(child))
                        for key, child in value.items() if key not in ("indices", "index", "component_index", "component_indices")}
            if isinstance(value, list):
                return sorted([projection(child) for child in value], key=lambda child: json.dumps(child, sort_keys=True))
            return value
        for case in CASES:
            if case["expected"]["status"] != "complete":
                continue
            data = copy.deepcopy(case["input"])
            before = evaluate(data)
            for field in ("components", "edges", "assertions", "roots"):
                data[field].reverse()
            self.assertEqual(projection(before), projection(evaluate(data)), case["id"])

    def test_maximum_admitted_counts_and_grouped_output(self):
        data = {"schema": "inventory-lab/1", "synthetic": True,
                "components": [{"id": f"C{i}", "name": "pkg", "version": "1", "sha256": None} for i in range(64)],
                "edges": [{"source": f"C{i % 64}", "target": f"C{(i + 1) % 64}"} for i in range(128)],
                "assertions": [{"target": f"C{i}", "name": "pkg", "version": "1", "sha256": None} for i in range(64)],
                "roots": ["C0"] * 16}
        report = evaluate(data)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["counts"]["edges"], 128)
        self.assertEqual(report["counts"]["unique_edges"], 64)
        self.assertEqual(report["counts"]["roots"], 16)
        self.assertEqual(report["counts"]["unique_roots"], 1)
        self.assertEqual(len(report["observations"]["graph"]["cycles"][0]), 64)
        self.assertEqual(len(report["findings"]), 65)

    def test_indices_preserved_in_grouped_findings(self):
        data = copy.deepcopy(next(case["input"] for case in CASES if case["id"] == "duplicate_root"))
        report = evaluate(data)
        self.assertEqual(report["findings"][0]["evidence"]["indices"], [0, 1])
        data = copy.deepcopy(next(case["input"] for case in CASES if case["id"] == "contradictory_assertions"))
        report = evaluate(data)
        group = next(row for row in report["findings"] if row["code"] == "contradictory_assertions")
        self.assertEqual([row["indices"] for row in group["evidence"]["groups"]], [[0], [1]])
        self.assertTrue(report["observations"]["graph"]["available"])

    def test_bytes_determinism_and_admission_no_partial(self):
        for case in CASES:
            if case["id"] == "unknown_schema_bad_late":
                continue  # JSON token rejection and API exact-type failure use different fixed codes.
            raw = json.dumps(case["input"]).encode()
            self.assertEqual(evaluate_bytes(raw), evaluate(case["input"]))
            self.assertEqual(evaluate_bytes(raw), evaluate_bytes(raw))


if __name__ == "__main__":
    unittest.main()
