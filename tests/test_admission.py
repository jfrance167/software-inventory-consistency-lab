import copy
import json
import unittest

from inventory_lab.admission import AdmissionError, decode, preflight, validate


def empty():
    return {"schema": "inventory-lab/1", "synthetic": True,
            "components": [], "edges": [], "assertions": [], "roots": []}


class AdmissionTests(unittest.TestCase):
    def error(self, callback, code, status="invalid"):
        with self.assertRaises(AdmissionError) as caught:
            callback()
        self.assertEqual((caught.exception.code, caught.exception.status), (code, status))

    def test_common_shape_before_unknown_profile(self):
        data = empty()
        data["schema"] = "inventory-lab/2"
        self.assertFalse(validate(data))
        data["components"] = [{"id": "A", "name": "A", "sha256": None}]
        self.error(lambda: validate(data), "object_fields")

    def test_numbers_nonfinite_and_keys(self):
        for token in ("0", "1.5", "1e999", "NaN", "Infinity", "-Infinity"):
            with self.subTest(token=token):
                self.error(lambda: decode(token.encode()), "numeric_token")
        self.error(lambda: decode(b'{"x":true,"x":false}'), "duplicate_json_key")

    def test_raw_and_depth_bounds(self):
        self.error(lambda: decode(b" " * 65_537), "input_limit", "limit")
        self.assertEqual(decode(b"[]" + b" " * 65_534), [])
        self.assertEqual(decode(b"[" * 8 + b"]" * 8), [[[[[[[[]]]]]]]])
        self.error(lambda: decode(b"[" * 9 + b"]" * 9), "depth_limit", "limit")
        self.error(lambda: decode(b"\xff"), "utf8_required")
        self.error(lambda: decode(b"\xef\xbb\xbf{}"), "json_syntax")
        self.assertEqual(decode(b'"[{\\\"}]"'), '[{"}]')

    def test_exact_types_and_native_cycles(self):
        class Exotic(dict):
            def items(self):
                raise RuntimeError("must not execute")
        for item in (Exotic(), (), 1, object(), {1: True}):
            with self.subTest(kind=type(item).__name__):
                with self.assertRaises(AdmissionError):
                    preflight(item)
        cycle = []
        cycle.append(cycle)
        self.error(lambda: preflight(cycle), "container_cycle")
        shared = []
        preflight([shared, shared])
        self.error(lambda: preflight("\ud800"), "unicode_scalar_required")

    def test_field_boundaries_and_no_mutation(self):
        data = empty()
        data["components"] = [{"id": "a" * 64, "name": "p", "version": "1", "sha256": "b" * 64}]
        original = copy.deepcopy(data)
        self.assertTrue(validate(data))
        self.assertEqual(data, original)
        data["components"][0]["id"] += "a"
        self.error(lambda: validate(data), "label_grammar")
        for field, cap in (("components", 64), ("edges", 128), ("assertions", 64), ("roots", 16)):
            data = empty()
            record = ({"id": "A", "name": "p", "version": "1", "sha256": None} if field == "components" else
                      {"source": "A", "target": "A"} if field == "edges" else
                      {"target": "A", "name": "p", "version": "1", "sha256": None} if field == "assertions" else "A")
            data[field] = [record] * cap
            self.assertTrue(validate(data))
            data[field].append(record)
            self.error(lambda: validate(data), "record_limit", "limit")

    def test_boolean_and_bad_late_fields(self):
        for changed in (False, None, "true"):
            data = empty()
            data["synthetic"] = changed
            self.error(lambda: validate(data), "synthetic_true_required")
        data = empty()
        data["roots"] = ["A", "has space"]
        self.error(lambda: validate(data), "label_grammar")
        self.error(lambda: decode(bytearray(b"{}")), "bytes_required")
        self.error(lambda: preflight("a" * 257), "text_limit", "limit")
        self.error(lambda: preflight([None] * 257), "container_limit", "limit")

    def test_tree_budget_guards(self):
        self.error(lambda: preflight([[None] * 256 for _ in range(16)]), "node_limit", "limit")
        self.error(lambda: preflight(["é" * 256] * 129), "text_total_limit", "limit")
        nested = []
        for _ in range(7):
            nested = [nested]
        preflight(nested)
        self.error(lambda: preflight([nested]), "depth_limit", "limit")


if __name__ == "__main__":
    unittest.main()
