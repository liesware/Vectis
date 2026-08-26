"""Load declarative fuzz targets from a YAML file into engine dataclasses.

The YAML describes the request shape, the mutations to apply, and the expected
outcome. Generic outcomes (status class, JSON-error shape, no leaked secret) are
built in; a deep semantic property is referenced by name and resolved against a
project-supplied ``invariants`` registry of pure Python oracle functions. The
engine never sees YAML: this module is the only translation layer, and it holds
no project knowledge of its own.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Callable, Mapping

import yaml

from .mutations import JsonFieldMutation, TemplateValueMutation, VariableValueMutation
from .workflows import (
    AllOf,
    Capture,
    DEFAULT_MALFORMED_EXPECTATION,
    ExpectJsonError,
    ExpectAuthorizationMatrix,
    ExpectNoServerCrash,
    ExpectNoServerError,
    ExpectStatus,
    FlowStep,
    FlowTarget,
    HttpStep,
    NoDeclaredSecrets,
    ProducerConsumerTarget,
    ProjectRacePredicate,
    RaceTarget,
    ProjectPredicate,
    RequestMutation,
    RequestTarget,
    ResponseExpectation,
    Target,
)

_PLACEHOLDER = re.compile(r"\{([a-zA-Z][a-zA-Z0-9_]*)\}")
_STATUS_CLASS = {"2xx": (200, 300), "3xx": (300, 400), "4xx": (400, 500), "5xx": (500, 600)}

Invariants = Mapping[str, Callable]
Mutators = Mapping[str, tuple[RequestMutation, ...]]


def load_targets(source: str | Path, *, invariants: Invariants, mutators: Mutators = {}) -> tuple[Target, ...]:
    text = Path(source).read_text(encoding="utf-8") if isinstance(source, Path) else source
    document = yaml.safe_load(text)
    if not isinstance(document, dict) or not isinstance(document.get("targets"), list):
        raise ValueError("target file must be a mapping with a 'targets' list")
    return tuple(_target(entry, invariants, mutators) for entry in document["targets"])


# --- placeholders -------------------------------------------------------------


def _placeholders(value: object) -> set[str]:
    if isinstance(value, str):
        return set(_PLACEHOLDER.findall(value))
    if isinstance(value, dict):
        return set().union(*(_placeholders(item) for item in value.values())) if value else set()
    if isinstance(value, list):
        return set().union(*(_placeholders(item) for item in value)) if value else set()
    return set()


# --- request steps ------------------------------------------------------------


def _step(name: str, block: Mapping[str, object], expectation: ResponseExpectation) -> HttpStep:
    path = block.get("path")
    method = block.get("method")
    if not isinstance(path, str) or not path.startswith("/") or not isinstance(method, str):
        raise ValueError(f"step {name} requires a method and an absolute path")
    auth = block.get("auth")
    if isinstance(auth, str):
        if not auth:
            raise ValueError(f"step {name} auth variable is invalid")
        headers: tuple[tuple[str, str], ...] = (("X-API-Key", "{" + auth + "}"),)
    elif auth:
        headers = (("X-API-Key", "{api_key}"),)
    else:
        headers = ()
    return HttpStep(
        name=name,
        method=method.upper(),
        url_template="{base_url}" + path,
        headers_template=headers,
        json_body_template=block.get("body"),
        url_encoded_variables=frozenset(_placeholders(path)),
        expectation=expectation,
        replayable=bool(block.get("replayable", True)),
    )


def _step_variables(block: Mapping[str, object]) -> set[str]:
    used = _placeholders(block.get("path", "")) | _placeholders(block.get("body"))
    auth = block.get("auth")
    if isinstance(auth, str):
        used.add(auth)
    elif auth:
        used.add("api_key")
    used.add("base_url")
    return used


def _extra_required(entry: Mapping[str, object]) -> frozenset[str]:
    """Variables a named invariant reads but no request template references.

    Without this, an invariant that compares against an environment value (e.g. a
    masking oracle reading ``mask_expected``) would not fail setup when that value
    is missing; it would instead fail the control with a misleading message.
    """

    extra = entry.get("requires", [])
    if not isinstance(extra, list) or not all(isinstance(name, str) for name in extra):
        raise ValueError("'requires' must be a list of variable names")
    return frozenset(extra)


# --- oracles ------------------------------------------------------------------


def _status_set(status: object) -> frozenset[int]:
    if isinstance(status, str):
        if status not in _STATUS_CLASS:
            raise ValueError(f"unknown status class {status!r}")
        start, stop = _STATUS_CLASS[status]
        return frozenset(range(start, stop))
    if isinstance(status, list) and all(isinstance(code, int) for code in status):
        return frozenset(status)
    raise ValueError("status must be a list of integers or a class like '4xx'")


def _oracle(spec: Mapping[str, object] | None, invariants: Invariants) -> ResponseExpectation:
    spec = spec or {}
    clauses: list[ResponseExpectation] = []
    if "status" in spec:
        clauses.append(ExpectStatus(_status_set(spec["status"])))
    if spec.get("json_error"):
        clauses.append(ExpectJsonError())
    if spec.get("no_server_error"):
        # For a mutated path that legitimately accepts (2xx) or rejects (4xx) but
        # must never crash: guards 5xx without pinning an exact status class.
        clauses.append(ExpectNoServerError())
    if spec.get("no_server_crash"):
        # Complements no_server_error for a well-formed mutation whose only failure
        # mode of interest is a crash: a server-side connection reset is a finding.
        clauses.append(ExpectNoServerCrash())
    if spec.get("authorization_matrix"):
        clauses.append(ExpectAuthorizationMatrix())
    clauses.append(NoDeclaredSecrets())  # secrets are always guarded, never opt-in
    invariant = spec.get("invariant")
    if invariant is not None:
        if invariant not in invariants:
            raise ValueError(f"unknown invariant {invariant!r}")
        clauses.append(ProjectPredicate(str(invariant), invariants[invariant]))
    return AllOf(tuple(clauses))


# --- mutators -----------------------------------------------------------------


def _mutation_required_variables(items: object) -> set[str]:
    if not isinstance(items, list):
        return set()
    return {
        item["from_variable"]
        for item in items
        if isinstance(item, dict) and isinstance(item.get("from_variable"), str)
    }


def _mutations(items: object, mutators: Mutators) -> tuple[RequestMutation, ...]:
    if not isinstance(items, list) or not items:
        raise ValueError("a target must declare a non-empty 'mutate' list")
    built: list[RequestMutation] = []
    for item in items:
        if isinstance(item, str):
            if item not in mutators:
                raise ValueError(f"unknown mutator group {item!r}")
            built.extend(mutators[item])
        elif isinstance(item, dict) and "variable" in item:
            variable = item["variable"]
            values = item.get("values")
            source_variable = item.get("from_variable")
            prefix = str(item.get("name", variable))
            expected_status = item.get("expected_status")
            if not isinstance(variable, str):
                raise ValueError("a 'variable' mutator needs a variable name")
            if expected_status is not None and not isinstance(expected_status, int):
                raise ValueError("'expected_status' must be an integer")
            if source_variable is not None:
                if not isinstance(source_variable, str) or values is not None:
                    raise ValueError("a 'from_variable' mutator needs one source variable and no values")
                built.append(VariableValueMutation(prefix, variable, source_variable, expected_status))
            else:
                if not isinstance(values, list) or not values:
                    raise ValueError("a 'variable' mutator needs a name and a non-empty 'values' list")
                built.extend(TemplateValueMutation(f"{prefix}-{index}", variable, str(value), expected_status=expected_status) for index, value in enumerate(values))
        elif isinstance(item, dict) and "json_field" in item:
            selector = item["json_field"]
            delimiter = item.get("delimiter")
            segments = item.get("segments")
            alphabet = item.get("alphabet")
            # A name-coupled invariant (one that keys on which mutation ran) needs
            # the mutation names to match; `name:` lets the YAML control that prefix.
            prefix = str(item.get("name", "field"))
            if not isinstance(selector, str):
                raise ValueError("a 'json_field' mutator needs a selector string")
            # An `alphabet` keeps the flip inside a restricted domain (hex digest,
            # format-preserving ciphertext) so it changes value, not just shape.
            if alphabet is not None and (not isinstance(alphabet, str) or len(alphabet) < 2):
                raise ValueError("'alphabet' must be a string of at least two characters")
            if segments is None:
                built.append(JsonFieldMutation(prefix, selector, alphabet=alphabet))
            else:
                if not isinstance(segments, list) or not all(isinstance(index, int) for index in segments):
                    raise ValueError("'segments' must be a list of integers")
                built.extend(
                    JsonFieldMutation(f"{prefix}-{index}", selector, delimiter=str(delimiter), segment_index=index, alphabet=alphabet)
                    for index in segments
                )
        else:
            raise ValueError(f"unrecognised mutator entry: {item!r}")
    return tuple(built)


# --- target assembly ----------------------------------------------------------


def _flow_target(entry: Mapping[str, object], invariants: Invariants, mutators: Mutators) -> FlowTarget:
    name = entry["name"]
    raw_steps = entry.get("flow")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ValueError(f"flow {name} needs a non-empty 'flow' list")
    steps: list[FlowStep] = []
    required: set[str] = set()
    captured: set[str] = set()
    fuzz_seen = 0
    mutations: tuple[RequestMutation, ...] = ()
    mutation_expectation: ResponseExpectation = DEFAULT_MALFORMED_EXPECTATION
    for raw in raw_steps:
        if not isinstance(raw, dict) or not isinstance(raw.get("request"), dict):
            raise ValueError(f"flow {name} step needs a 'request' mapping")
        block = raw["request"]
        control_step = _step(str(raw.get("step", "step")), block, _oracle(raw.get("expect"), invariants))
        capture_spec = raw.get("capture") or {}
        if not isinstance(capture_spec, dict):
            raise ValueError(f"flow {name} step 'capture' must be a mapping")
        captures = tuple(Capture(str(cap), str(selector)) for cap, selector in capture_spec.items())
        captured.update(capture_spec.keys())
        required.update(_step_variables(block))
        is_fuzz = bool(raw.get("fuzz"))
        if is_fuzz:
            fuzz_seen += 1
            mutations = _mutations(raw.get("mutate"), mutators)
            mutation_expectation = _oracle(raw["fuzz_expect"], invariants) if raw.get("fuzz_expect") else DEFAULT_MALFORMED_EXPECTATION
            required.update(_mutation_required_variables(raw.get("mutate")))
        steps.append(FlowStep(control_step, captures, is_fuzz, bool(raw.get("continue_on_rejection"))))
    if fuzz_seen != 1:
        raise ValueError(f"flow {name} must mark exactly one step with fuzz: true")
    return FlowTarget(
        name=name,
        required_variables=frozenset(required - captured) | _extra_required(entry),
        steps=tuple(steps),
        mutations=mutations,
        mutation_expectation=mutation_expectation,
        run_control=bool(entry.get("control", True)),
        include_generative=bool(entry.get("generative", True)),
    )


def _race_target(entry: Mapping[str, object], invariants: Invariants) -> RaceTarget:
    name = entry["name"]
    block = entry.get("race")
    if not isinstance(block, dict) or not isinstance(block.get("producer"), dict):
        raise ValueError(f"race {name} requires a producer")
    contenders = block.get("contenders")
    if not isinstance(contenders, list) or len(contenders) < 2:
        raise ValueError(f"race {name} requires at least two contenders")
    capture_spec = block.get("capture")
    if not isinstance(capture_spec, dict) or not capture_spec:
        raise ValueError(f"race {name} requires captures")
    producer = block["producer"]
    producer_expect = _oracle(block.get("producer_expect") or {"status": [200]}, invariants)
    captured = set(capture_spec)
    required = _step_variables(producer)
    built: list[HttpStep] = []
    for item in contenders:
        if not isinstance(item, dict) or not isinstance(item.get("request"), dict):
            raise ValueError(f"race {name} contender requires a request")
        request = item["request"]
        built.append(_step(str(item.get("step", "contender")), request, _oracle(item.get("expect") or {"status": [200, 404]}, invariants)))
        required.update(_step_variables(request))
    expectation = block.get("expect")
    if not isinstance(expectation, dict) or not isinstance(expectation.get("race_invariant"), str):
        raise ValueError(f"race {name} requires a race_invariant")
    invariant_name = expectation["race_invariant"]
    if invariant_name not in invariants:
        raise ValueError(f"unknown invariant {invariant_name!r}")
    return RaceTarget(
        name=name,
        required_variables=frozenset(required - captured) | _extra_required(entry),
        producer=_step("producer", producer, producer_expect),
        captures=tuple(Capture(str(key), str(value)) for key, value in capture_spec.items()),
        contenders=tuple(built),
        race_expectation=ProjectRacePredicate(invariant_name, invariants[invariant_name]),
    )


def _target(entry: Mapping[str, object], invariants: Invariants, mutators: Mutators) -> Target:
    if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
        raise ValueError("each target needs a name")
    name = entry["name"]
    if "flow" in entry:
        return _flow_target(entry, invariants, mutators)
    if "race" in entry:
        return _race_target(entry, invariants)
    expect = entry.get("expect")
    if not isinstance(expect, dict):
        raise ValueError(f"target {name} needs an 'expect' block")
    mutations = _mutations(entry.get("mutate"), mutators)
    control_oracle = _oracle(expect.get("control"), invariants)
    mutated_oracle = _oracle(expect.get("mutated"), invariants)

    if "request" in entry:
        block = entry["request"]
        if not isinstance(block, dict):
            raise ValueError(f"target {name} 'request' must be a mapping")
        required = frozenset(_step_variables(block) | _mutation_required_variables(entry.get("mutate"))) | _extra_required(entry)
        return RequestTarget(
            name=name,
            required_variables=required,
            control=_step("request", block, control_oracle),
            mutations=mutations,
            mutation_expectation=mutated_oracle,
        )

    producer_block, consumer_block = entry.get("producer"), entry.get("consumer")
    if not isinstance(producer_block, dict) or not isinstance(consumer_block, dict):
        raise ValueError(f"target {name} must define either 'request' or both 'producer' and 'consumer'")
    capture_spec = entry.get("capture")
    if not isinstance(capture_spec, dict) or not capture_spec:
        raise ValueError(f"target {name} producer/consumer flow requires a 'capture' block")
    captures = tuple(Capture(str(cap_name), str(selector)) for cap_name, selector in capture_spec.items())
    captured_names = {cap_name for cap_name, _ in capture_spec.items()}
    required = frozenset(
        (_step_variables(producer_block) | _step_variables(consumer_block) | _mutation_required_variables(entry.get("mutate")))
        - captured_names
    ) | _extra_required(entry)
    producer_oracle = _oracle(entry.get("producer_expect") or {"status": [200]}, invariants)
    return ProducerConsumerTarget(
        name=name,
        required_variables=required,
        producer=_step("producer", producer_block, producer_oracle),
        captures=captures,
        consumer=_step("consumer", consumer_block, mutated_oracle),
        mutations=mutations,
        control_expectation=control_oracle,
        mutation_expectation=mutated_oracle,
    )
