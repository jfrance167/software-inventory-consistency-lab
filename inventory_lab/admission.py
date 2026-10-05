"""Bounded admission of ordinary values; no coercion or semantic repair."""

import json
import re

PROFILE = "inventory-lab/1"
MAX_INPUT = 65_536
MAX_DEPTH = 8
MAX_NODES = 4_096
COUNTS = {"components": 64, "edges": 128, "assertions": 64, "roots": 16}
LABEL = re.compile(r"[A-Za-z0-9._+-]{1,64}", re.ASCII)
SCHEMA_LABEL = re.compile(r"[A-Za-z0-9._+/-]{1,64}", re.ASCII)
HASH = re.compile(r"[a-f0-9]{64}", re.ASCII)


class AdmissionError(ValueError):
    """Fixed machine code and structural path, with no input/exception echo."""

    def __init__(self, status, code, path=""):
        super().__init__(code)
        self.status, self.code, self.path = status, code, path


def reject(code, path="", status="invalid"):
    raise AdmissionError(status, code, path)


def _check_depth(text):
    stack, quoted, escaped = [], False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            stack.append(char)
            if len(stack) > MAX_DEPTH:
                reject("depth_limit", status="limit")
        elif char in "]}":
            if not stack or stack.pop() != ({"]": "[", "}": "{"}[char]):
                reject("json_syntax")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            reject("duplicate_json_key")
        result[key] = value
    return result


def _number(_text):
    reject("numeric_token")


def decode(raw):
    """Return decoded values only after raw byte/depth/token admission."""
    if type(raw) is not bytes:
        reject("bytes_required")
    if len(raw) > MAX_INPUT:
        reject("input_limit", status="limit")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        reject("utf8_required")
    _check_depth(text)
    try:
        return json.loads(text, object_pairs_hook=_pairs, parse_int=_number,
                          parse_float=_number, parse_constant=_number)
    except (json.JSONDecodeError, RecursionError):
        reject("json_syntax")


def preflight(value):
    """Iterative exact-type walk, detecting ancestor cycles, not shared values."""
    active, nodes, text_bytes = set(), 0, 0
    stack = [(value, "", 0, False)]
    while stack:
        obj, path, depth, leaving = stack.pop()
        if leaving:
            active.remove(id(obj))
            continue
        nodes += 1
        if nodes > MAX_NODES:
            reject("node_limit", path, "limit")
        kind = type(obj)
        if kind is str:
            if len(obj) > 256:
                reject("text_limit", path, "limit")
            try:
                text_bytes += len(obj.encode("utf-8"))
            except UnicodeError:
                reject("unicode_scalar_required", path)
            if text_bytes > MAX_INPUT:
                reject("text_total_limit", path, "limit")
        elif kind in (dict, list):
            if id(obj) in active:
                reject("container_cycle", path)
            if depth + 1 > MAX_DEPTH:
                reject("depth_limit", path, "limit")
            if len(obj) > 256:
                reject("container_limit", path, "limit")
            active.add(id(obj))
            stack.append((obj, path, depth, True))
            if kind is list:
                for index in range(len(obj) - 1, -1, -1):
                    stack.append((obj[index], f"{path}/{index}", depth + 1, False))
            else:
                # Validate keys without coercion or inserting their text into paths.
                for index, (key, child) in reversed(list(enumerate(obj.items()))):
                    if type(key) is not str:
                        reject("string_key_required", path)
                    stack.append((child, f"{path}/value-{index}", depth + 1, False))
                    stack.append((key, f"{path}/key-{index}", depth + 1, False))
        elif kind not in (bool, type(None)):
            reject("ordinary_type_required", path)


def _object(value, keys, path):
    if type(value) is not dict or set(value) != set(keys):
        reject("object_fields", path)


def _label(value, path, pattern=LABEL):
    if type(value) is not str or pattern.fullmatch(value) is None:
        reject("label_grammar", path)


def validate(value):
    """Validate every common record before deciding whether profile is supported."""
    preflight(value)
    _object(value, ("schema", "synthetic", *COUNTS), "")
    _label(value["schema"], "/schema", SCHEMA_LABEL)
    if value["synthetic"] is not True:
        reject("synthetic_true_required", "/synthetic")
    for field, maximum in COUNTS.items():
        records = value[field]
        if type(records) is not list:
            reject("array_required", "/" + field)
        if len(records) > maximum:
            reject("record_limit", "/" + field, "limit")
        for index, record in enumerate(records):
            path = f"/{field}/{index}"
            if field == "roots":
                _label(record, path)
                continue
            labels = ("source", "target") if field == "edges" else (
                "id" if field == "components" else "target", "name", "version")
            _object(record, labels if field == "edges" else (*labels, "sha256"), path)
            for key in labels:
                _label(record[key], f"{path}/{key}")
            if field != "edges" and record["sha256"] is not None:
                if type(record["sha256"]) is not str or HASH.fullmatch(record["sha256"]) is None:
                    reject("hash_grammar", path + "/sha256")
    return value["schema"] == PROFILE
