"""Evaluate declared identity/reference consistency, never artifact truth."""

from collections import defaultdict

from .admission import AdmissionError, COUNTS, MAX_DEPTH, MAX_INPUT, PROFILE, decode, validate
from .graph import observe

MAX_FINDINGS = 1_024
MAX_OUTPUT = 1_048_576


def report_base(status="complete", input_schema=None, error=None):
    return {"schema": "inventory-report/1", "input_schema": input_schema, "status": status,
            "evaluation": "complete" if status == "complete" else "incomplete", "consistency": None,
            "assurances": {key: "unknown" for key in (
                "completeness", "authenticity", "vulnerability_absence", "license_compliance")},
            "limits": {"input_bytes": MAX_INPUT, "depth": MAX_DEPTH, **COUNTS,
                       "findings": MAX_FINDINGS, "output_bytes": MAX_OUTPUT},
            "counts": None, "findings": [], "observations": None, "error": error}


def failure(error, input_schema=None):
    return report_base(error.status, input_schema, {"code": error.code, "path": error.path})


def _groups(records, key):
    groups = defaultdict(list)
    for index, record in enumerate(records):
        groups[key(record)].append(index)
    return groups


def _metadata(record):
    return (record["name"], record["version"], record["sha256"])


def _declaration(values):
    return dict(zip(("name", "version", "sha256"), values))


def _analyze(data):
    result = report_base(input_schema=PROFILE)
    findings, graph_reasons = result["findings"], set()
    by_id = _groups(data["components"], lambda item: item["id"])
    edges = _groups(data["edges"], lambda item: (item["source"], item["target"]))
    assertions = _groups(data["assertions"], lambda item: (item["target"], *_metadata(item)))
    roots = _groups(data["roots"], lambda item: item)

    def finding(code, path, evidence):
        if len(findings) >= MAX_FINDINGS:
            raise AdmissionError("limit", "finding_limit")
        findings.append({"code": code, "path": path, "evidence": evidence})

    def resolve(label, path, affects_graph=False):
        occurrences = by_id.get(label, [])
        if not occurrences:
            finding("unknown_reference", path, {"id": label})
            if affects_graph:
                graph_reasons.add("unknown_reference")
        elif len(occurrences) > 1:
            finding("ambiguous_reference", path, {"id": label, "component_indices": occurrences[:]})
            if affects_graph:
                graph_reasons.add("ambiguous_reference")
        else:
            return occurrences[0]
        return None

    for label, indices in by_id.items():
        if len(indices) > 1:
            graph_reasons.add("duplicate_component_id")
            finding("duplicate_component_id", "/components", {
                "id": label, "indices": indices[:],
                "declarations": [dict(data["components"][index]) for index in indices]})
    for field, groups, code in (("edges", edges, "duplicate_edge"),
                               ("roots", roots, "duplicate_root"),
                               ("assertions", assertions, "duplicate_assertion")):
        for indices in groups.values():
            if len(indices) > 1:
                declaration = data[field][indices[0]]
                finding(code, "/" + field, {"indices": indices[:],
                        "declaration": dict(declaration) if type(declaration) is dict else declaration})
    for index, edge in enumerate(data["edges"]):
        for endpoint in ("source", "target"):
            resolve(edge[endpoint], f"/edges/{index}/{endpoint}", True)
    for index, root in enumerate(data["roots"]):
        resolve(root, f"/roots/{index}", True)
    by_target = _groups(data["assertions"], lambda item: item["target"])
    for target, indices in by_target.items():
        declarations = _groups(indices, lambda index: _metadata(data["assertions"][index]))
        if len(declarations) > 1:
            finding("contradictory_assertions", "/assertions", {
                "target": target, "groups": [
                    {"declaration": _declaration(values), "indices": [indices[i] for i in offsets]}
                    for values, offsets in declarations.items()]})
    for index, claim in enumerate(data["assertions"]):
        component_index = resolve(claim["target"], f"/assertions/{index}/target")
        if component_index is None:
            continue
        actual = data["components"][component_index]
        differences = [key for key in ("name", "version", "sha256") if claim[key] != actual[key]]
        if differences:
            finding("assertion_mismatch", f"/assertions/{index}", {
                "target": claim["target"], "component_index": component_index,
                "fields": differences, "asserted": _declaration(_metadata(claim)),
                "component": _declaration(_metadata(actual))})

    labels = _groups(data["components"], lambda item: (item["name"], item["version"]))
    declaration_groups = []
    for (name, version), indices in sorted(labels.items()):
        if len(indices) < 2:
            continue
        hashes = {data["components"][index]["sha256"] for index in indices}
        declaration_groups.append({"name": name, "version": version,
            "kind": "equal_supplied_declarations" if len(hashes) == 1 else "different_supplied_declarations",
            "meaning": "comparison of declarations only; null means no hash declaration",
            "occurrences": sorted([{"index": index, "id": data["components"][index]["id"],
                                     "sha256": data["components"][index]["sha256"]} for index in indices],
                                    key=lambda item: (item["id"], item["index"]))})
    graph = ({"available": False, "reasons": sorted(graph_reasons), "sccs": None,
              "cycles": None, "reachability": None} if graph_reasons else
             observe(by_id, edges, roots))
    result["counts"] = {"components": len(data["components"]), "unique_component_ids": len(by_id),
                        "edges": len(data["edges"]), "unique_edges": len(edges),
                        "assertions": len(data["assertions"]), "unique_assertions": len(assertions),
                        "roots": len(data["roots"]), "unique_roots": len(roots)}
    result["observations"] = {"declaration_groups": declaration_groups, "graph": graph}
    findings.sort(key=lambda item: (item["code"], tuple(
        part.zfill(8) if part.isdigit() else part for part in item["path"].split("/"))))
    result["consistency"] = "inconsistent" if findings else "consistent"
    return result


def evaluate(value):
    """Return a complete or explicit incomplete report from exact ordinary values.

    No input mutation, I/O, coercion, first/last duplicate selection or discovery.
    """
    try:
        if not validate(value):
            return failure(AdmissionError("unsupported", "unknown_schema", "/schema"), value["schema"])
        return _analyze(value)
    except AdmissionError as error:
        return failure(error)


def evaluate_bytes(raw):
    """Admit exact bounded UTF-8 bytes, then evaluate supplied declarations."""
    try:
        return evaluate(decode(raw))
    except AdmissionError as error:
        return failure(error)
