"""Generic mutations over templated variables and JSON object paths.

Every mutator implements ``apply(variables, body, rng)`` and returns a triple of
``(variables, body, MutationRecord)``. The returned ``body`` is final: either a
JSON-serialisable object that the engine serialises, raw ``bytes`` that the
engine sends verbatim, or ``None`` for a body-less request. Deterministic
mutators ignore ``rng``; generative mutators draw every decision from it so a
fixed seed reproduces the exact sequence.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
import json
import random
from typing import Mapping

from .http import MAX_CAPTURED_BODY_BYTES
from .workflows import MutationRecord


# --- shared JSON navigation ---------------------------------------------------

Path = tuple[object, ...]


def _object_path(value: object, selector: str) -> tuple[dict[str, object], str]:
    if not selector.startswith("$.") or not selector[2:]:
        raise ValueError("JSON selector must use $.field syntax")
    parts = selector[2:].split(".")
    if any(not part or not part.replace("_", "a").isalnum() for part in parts):
        raise ValueError("JSON selector is invalid")
    current = value
    for part in parts[:-1]:
        if not isinstance(current, dict) or part not in current:
            raise ValueError("JSON selector was not found")
        current = current[part]
    if not isinstance(current, dict) or parts[-1] not in current:
        raise ValueError("JSON selector was not found")
    return current, parts[-1]


def _all_paths(node: object, prefix: Path = ()) -> list[Path]:
    paths: list[Path] = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = prefix + (key,)
            paths.append(here)
            paths.extend(_all_paths(value, here))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            here = prefix + (index,)
            paths.append(here)
            paths.extend(_all_paths(value, here))
    return paths


def _get_at(node: object, path: Path) -> object:
    current = node
    for segment in path:
        current = current[segment]  # type: ignore[index]
    return current


def _set_at(node: object, path: Path, value: object) -> None:
    current = node
    for segment in path[:-1]:
        current = current[segment]  # type: ignore[index]
    current[path[-1]] = value  # type: ignore[index]


def _del_at(node: object, path: Path) -> None:
    current = node
    for segment in path[:-1]:
        current = current[segment]  # type: ignore[index]
    last = path[-1]
    if isinstance(current, dict):
        current.pop(last, None)
    elif isinstance(current, list) and isinstance(last, int) and 0 <= last < len(current):
        current.pop(last)


def _path_str(path: Path) -> str:
    return "$." + ".".join(str(segment) for segment in path) if path else "$"


def _short(value: object) -> str:
    return repr(value)[:120]


# --- generative vocabulary ----------------------------------------------------

BAD_VALUES: tuple[object, ...] = (
    None,
    True,
    False,
    0,
    -1,
    2**63,
    "",
    "A" * 1025,
    [],
    {},
    [None, None, None],
    {"": ""},
    "../../etc/passwd",
    "\x00",
    "\U0001d518\U0001d52b\U0001d526",
)


def _type_swap(value: object, rng: random.Random) -> object:
    if isinstance(value, bool):
        return not value
    if isinstance(value, str):
        return rng.choice((123, [], {}, None, True))
    if isinstance(value, (int, float)):
        return rng.choice(("not-a-number", [], {}, None))
    if value is None:
        return rng.choice(("null-was-here", 0, []))
    if isinstance(value, list):
        return rng.choice(({}, "not-a-list", None))
    if isinstance(value, dict):
        return rng.choice(([], "not-an-object", None))
    return None


# --- deterministic, hand-authored mutators ------------------------------------


@dataclass(frozen=True)
class TemplateValueMutation:
    name: str
    variable: str
    replacement: str
    alternative: str | None = None

    def apply(self, variables: Mapping[str, object], body: object | None, rng: random.Random):
        if self.variable not in variables or not isinstance(variables[self.variable], str):
            raise ValueError(f"template variable {self.variable} is unavailable for mutation")
        updated = dict(variables)
        original = variables[self.variable]
        replacement = self.replacement if self.replacement != original else (self.alternative or "_")
        updated[self.variable] = replacement
        return updated, body, MutationRecord(self.name, self.variable, original, replacement)


@dataclass(frozen=True)
class JsonFieldMutation:
    name: str
    selector: str
    delimiter: str | None = None
    segment_index: int | None = None

    def apply(self, variables: Mapping[str, object], body: object | None, rng: random.Random):
        if body is None:
            raise ValueError("JSON field mutation requires a JSON body")
        updated_body = copy.deepcopy(body)
        container, key = _object_path(updated_body, self.selector)
        original = container[key]
        if not isinstance(original, str) or not original:
            raise ValueError("JSON field mutation requires a non-empty string")
        if self.delimiter is None:
            mutated = _flip_character(original)
        else:
            if self.segment_index is None:
                raise ValueError("delimited JSON mutation requires a segment index")
            segments = original.split(self.delimiter)
            if self.segment_index < 0 or self.segment_index >= len(segments) or not segments[self.segment_index]:
                raise ValueError("JSON mutation segment is unavailable")
            segments[self.segment_index] = _flip_character(segments[self.segment_index])
            mutated = self.delimiter.join(segments)
        container[key] = mutated
        return dict(variables), updated_body, MutationRecord(self.name, self.selector, original, mutated)


def _flip_character(value: str) -> str:
    return ("A" if value[0] != "A" else "B") + value[1:]


# --- generative mutators ------------------------------------------------------


@dataclass(frozen=True)
class StructuredMutation:
    """Schema-level corruption: delete a field, swap its type, or inject a bad value."""

    name: str = "structured-invalid"

    def apply(self, variables: Mapping[str, object], body: object | None, rng: random.Random):
        if body is None:
            raise ValueError("structured mutation requires a JSON body")
        mutated = copy.deepcopy(body)
        paths = _all_paths(mutated)
        if not paths:
            replacement = copy.deepcopy(rng.choice(BAD_VALUES))
            return dict(variables), replacement, MutationRecord(self.name, "$", _short(body), _short(replacement))
        path = rng.choice(paths)
        original = _get_at(mutated, path)
        roll = rng.random()
        if roll < 0.34:
            _del_at(mutated, path)
            change = "<deleted>"
        elif roll < 0.67:
            swapped = _type_swap(original, rng)
            _set_at(mutated, path, swapped)
            change = _short(swapped)
        else:
            bad = copy.deepcopy(rng.choice(BAD_VALUES))
            _set_at(mutated, path, bad)
            change = _short(bad)
        return dict(variables), mutated, MutationRecord(self.name, _path_str(path), _short(original), change)


@dataclass(frozen=True)
class RawBodyMutation:
    """Byte-level corruption of the serialised body: parser-layer input."""

    name: str = "raw-invalid"

    def apply(self, variables: Mapping[str, object], body: object | None, rng: random.Random):
        if body is None:
            raise ValueError("raw mutation requires a body")
        data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        operation = rng.choice(("truncate", "bitflip", "nullbyte", "dupkey", "invalid-utf8", "append", "repeat"))
        mutated = _corrupt(data, operation, rng)
        return (
            dict(variables),
            mutated,
            MutationRecord(f"{self.name}:{operation}", "$body", _short(data[:120]), _short(mutated[:120])),
        )


@dataclass(frozen=True)
class DeserStressMutation:
    """Payloads that stress a deserializer: depth, size, duplication, type and numeric edges.

    Aimed at the real deserialization risk in a data-only stack (resource
    exhaustion, panics, type confusion) rather than gadget-chain RCE, which does
    not exist in that model. Paired with the no-server-error and latency oracles.
    """

    name: str = "deser-stress"
    OPERATIONS: tuple[str, ...] = (
        "deep-nest",
        "wide-array",
        "huge-string",
        "huge-number",
        "duplicate-key",
        "type-cascade",
        "unknown-flood",
        "numeric-edge",
    )

    def apply(self, variables: Mapping[str, object], body: object | None, rng: random.Random):
        if body is None:
            raise ValueError("deser stress mutation requires a body")
        operation = rng.choice(self.OPERATIONS)
        payload = _bounded_deser_payload(_deser_payload(body, operation, rng), operation)
        return dict(variables), payload, MutationRecord(f"{self.name}:{operation}", "$body", _short(body), _short(payload)[:120])


_DEEP_NEST_DEPTH = 400
_WIDE_ARRAY_ITEMS = 4000
_HUGE_STRING_LEN = 40000
_UNKNOWN_FIELDS = 2000
_NUMERIC_EDGES = (
    9223372036854775807,        # i64::MAX
    -9223372036854775808,       # i64::MIN
    18446744073709551615,       # u64::MAX
    18446744073709551616,       # u64::MAX + 1
    10**300,                    # far beyond any fixed-width integer
)


def _deser_payload(body: object, operation: str, rng: random.Random) -> object:
    if operation == "deep-nest":
        nested: object = body
        for _ in range(_DEEP_NEST_DEPTH):
            nested = {"n": nested}
        return nested
    if operation == "wide-array":
        return _augment(body, "_wide", [0] * _WIDE_ARRAY_ITEMS)
    if operation == "huge-string":
        return _augment(body, "_huge", "A" * _HUGE_STRING_LEN)
    if operation == "huge-number":
        return _augment(body, "_num", 10**400)
    if operation == "duplicate-key":
        data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if data.startswith(b"{") and len(data) > 1:
            return b"{" + b'"_d":0,' * 200 + data[1:]
        return data
    if operation == "type-cascade":
        mutated = copy.deepcopy(body)
        # swap only leaf values: keeping containers intact keeps every path resolvable.
        for path in _all_paths(mutated):
            value = _get_at(mutated, path)
            if not isinstance(value, (dict, list)):
                _set_at(mutated, path, _type_swap(value, rng))
        return mutated
    if operation == "unknown-flood":
        return _augment(body, None, {f"_u{index}": index for index in range(_UNKNOWN_FIELDS)})
    return _augment(body, "_edge", rng.choice(_NUMERIC_EDGES))


def _encoded_payload_size(payload: object) -> int:
    if isinstance(payload, bytes):
        return len(payload)
    return len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def _bounded_deser_payload(payload: object, operation: str) -> object:
    """Keep stress cases inside the transport cap, even for a near-limit seed.

    Most cases preserve the valid body and add stress data. If that would exceed
    the cap, use an operation-specific standalone payload so the server still
    receives deserialization stress rather than Nadir rejecting it locally.
    """

    if _encoded_payload_size(payload) <= MAX_CAPTURED_BODY_BYTES:
        return payload
    fallback = _deser_fallback(operation)
    if _encoded_payload_size(fallback) > MAX_CAPTURED_BODY_BYTES:
        raise ValueError("deser stress fallback exceeds the transport cap")
    return fallback


def _deser_fallback(operation: str) -> object:
    if operation == "deep-nest":
        nested: object = None
        for _ in range(_DEEP_NEST_DEPTH):
            nested = {"n": nested}
        return nested
    if operation == "wide-array":
        return {"_wide": [0] * _WIDE_ARRAY_ITEMS}
    if operation == "huge-string":
        return {"_huge": "A" * _HUGE_STRING_LEN}
    if operation == "huge-number":
        return {"_num": 10**400}
    if operation == "duplicate-key":
        return b"{" + b'"_d":0,' * 200 + b'"_d":0}'
    if operation == "type-cascade":
        return {"_type": [None, {}, [], True, 0]}
    if operation == "unknown-flood":
        return {f"_u{index}": index for index in range(_UNKNOWN_FIELDS)}
    return {"_edge": 10**300}


def _augment(body: object, key: str | None, value: object) -> object:
    """Attach stress data to a dict body, or fall back to a wrapper object."""

    if isinstance(body, dict):
        mutated = copy.deepcopy(body)
        if key is None and isinstance(value, dict):
            mutated.update(value)
        else:
            mutated[key or "_x"] = value
        return mutated
    return {"_stress": value, "_body": body}


def _corrupt(data: bytes, operation: str, rng: random.Random) -> bytes:
    if operation == "truncate":
        return data[: rng.randrange(len(data))] if len(data) > 1 else b""
    if operation == "bitflip":
        buffer = bytearray(data)
        index = rng.randrange(len(buffer))
        buffer[index] ^= 1 << rng.randrange(8)
        return bytes(buffer)
    if operation == "nullbyte":
        index = rng.randrange(len(data) + 1)
        return data[:index] + b"\x00" + data[index:]
    if operation == "dupkey":
        if data.startswith(b"{") and len(data) > 1:
            return b'{"nadir_dup":"nadir_dup",' + data[1:]
        return data + b',"nadir_dup":"nadir_dup"'
    if operation == "invalid-utf8":
        return data + b"\xff\xfe"
    if operation == "append":
        return data + rng.choice((b"}}}", b"]]]", b",,,", b"\x00\x00"))
    return data * rng.randint(2, 4)
