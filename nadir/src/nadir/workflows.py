"""Declarative workflow types shared by the engine and project integrations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Mapping, Protocol

from .http import HttpRequest, HttpResult, is_client_side_failure


@dataclass(frozen=True)
class Finding:
    code: str
    message: str
    severity: str = "high"


@dataclass(frozen=True)
class MutationRecord:
    name: str
    location: str
    original: str
    mutated: str


@dataclass(frozen=True)
class EvaluationContext:
    target: str
    step: str
    mutation: MutationRecord | None
    declared_secrets: tuple[bytes, ...]
    variables: Mapping[str, object] = field(default_factory=dict)


class ResponseExpectation(Protocol):
    def evaluate(self, result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]: ...


@dataclass(frozen=True)
class ExpectStatus:
    allowed: frozenset[int]

    def evaluate(self, result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
        if result.failure is not None:
            # A mutation that yields input the client itself refuses to send tells us
            # nothing about the server, so it is not a finding. The same failure on an
            # unmutated request (control/preamble) is a real config problem: still reported.
            if context.mutation is not None and is_client_side_failure(result.failure):
                return ()
            return (Finding("transport-failure", result.failure.public_message),)
        if result.status not in self.allowed:
            return (Finding("unexpected-status", f"{context.step} received HTTP {result.status}", "medium"),)
        return ()


@dataclass(frozen=True)
class ExpectJsonError:
    def evaluate(self, result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
        import json

        try:
            body = json.loads(result.body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return (Finding("invalid-json-error", f"{context.step} rejection is not valid JSON", "medium"),)
        if not isinstance(body, dict) or not isinstance(body.get("error"), str):
            return (Finding("invalid-json-error", f"{context.step} rejection lacks an error string", "medium"),)
        return ()


@dataclass(frozen=True)
class ExpectJsonShape:
    required_fields: frozenset[str]

    def evaluate(self, result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
        import json

        try:
            body = json.loads(result.body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return (Finding("invalid-json-shape", f"{context.step} response is not valid JSON"),)
        if not isinstance(body, dict) or not self.required_fields.issubset(body):
            return (Finding("invalid-json-shape", f"{context.step} response lacks required fields"),)
        return ()


@dataclass(frozen=True)
class NoDeclaredSecrets:
    def evaluate(self, result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
        for secret in context.declared_secrets:
            if secret and secret in result.body:
                return (Finding("response-leaks-declared-secret", f"{context.step} response contains a declared secret"),)
        return ()


@dataclass(frozen=True)
class ExpectNoServerError:
    """Generic oracle for malformed input: only a 5xx is a finding.

    A transport failure (timeout/reset) is treated as infrastructure noise, not a
    vulnerability, and a 4xx rejection or a 2xx accept of a benign structural change
    are both valid outcomes. This keeps generative structured/raw cases from raising
    false findings while still catching a crash.
    """

    def evaluate(self, result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
        if result.failure is not None:
            return ()
        if result.status is not None and 500 <= result.status < 600:
            return (Finding("server-error", f"{context.step} returned HTTP {result.status}"),)
        return ()


@dataclass(frozen=True)
class ExpectNoServerCrash:
    """A server-side connection drop signals a crash, and is a finding.

    Where ExpectNoServerError only sees a status code, this catches the case where
    a well-formed but adversarial request makes the service panic and drop the
    connection (RST) or return a malformed HTTP response. A client-side failure (our
    own request was un-sendable) and a plain timeout (network noise) are left to
    other classification so this never fires on those.
    """

    def evaluate(self, result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
        failure = result.failure
        if failure is None or is_client_side_failure(failure):
            return ()
        if failure.kind in {"reset", "protocol"}:
            return (Finding("server-crash", f"{context.step} triggered a server-side {failure.kind}"),)
        return ()


@dataclass(frozen=True)
class ExpectUnderLatency:
    """Catch algorithmic-complexity DoS: a completed response that took too long.

    A malformed payload that makes the server spend seconds parsing (deep nesting,
    huge allocations, quadratic work) is a finding even when it eventually returns.
    A transport timeout is left to transport classification, not flagged here, to
    avoid flaky findings from ordinary network variance.
    """

    max_ms: int

    def evaluate(self, result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
        if result.failure is not None:
            return ()
        if result.elapsed_ms > self.max_ms:
            return (Finding("slow-response", f"{context.step} took {result.elapsed_ms}ms (over {self.max_ms}ms)"),)
        return ()


@dataclass(frozen=True)
class ProjectPredicate:
    name: str
    predicate: Callable[[HttpResult, EvaluationContext], tuple[Finding, ...]]

    def evaluate(self, result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
        return self.predicate(result, context)


@dataclass(frozen=True)
class AllOf:
    expectations: tuple[ResponseExpectation, ...]

    def evaluate(self, result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
        return tuple(finding for expectation in self.expectations for finding in expectation.evaluate(result, context))


@dataclass(frozen=True)
class HttpStep:
    name: str
    method: str
    url_template: str
    headers_template: tuple[tuple[str, str], ...] = ()
    json_body_template: object | None = None
    url_encoded_variables: frozenset[str] = frozenset()
    expectation: ResponseExpectation = ExpectStatus(frozenset({200}))
    replayable: bool = True


@dataclass(frozen=True)
class Capture:
    name: str
    selector: str


class RequestMutation(Protocol):
    name: str

    def apply(self, variables: Mapping[str, object], body: object | None) -> tuple[dict[str, object], object | None, MutationRecord]: ...


@dataclass(frozen=True)
class CaseWeights:
    """Relative weights for generative case classes past the curated semantic set."""

    semantic: int = 3
    structured: int = 3
    raw: int = 2
    deser: int = 2


# Latency budget for generative input. A local test instance answers in
# milliseconds; a response over this took pathologically long — an algorithmic DoS.
DEFAULT_LATENCY_MS = 2000

# Generic "must be safely rejected" oracle for generative structured/raw/deser input:
# a crash (5xx), a pathologically slow response, or a leaked secret is a finding;
# a 4xx or a benign 2xx is not.
DEFAULT_MALFORMED_EXPECTATION: ResponseExpectation = AllOf(
    (ExpectNoServerError(), ExpectUnderLatency(DEFAULT_LATENCY_MS), NoDeclaredSecrets())
)


@dataclass(frozen=True)
class RequestTarget:
    name: str
    required_variables: frozenset[str]
    control: HttpStep
    mutations: tuple[RequestMutation, ...]
    mutation_expectation: ResponseExpectation
    weights: CaseWeights = CaseWeights()
    malformed_expectation: ResponseExpectation = DEFAULT_MALFORMED_EXPECTATION

    def __post_init__(self) -> None:
        if not self.mutations:
            raise ValueError(f"target {self.name} must declare at least one mutation")


@dataclass(frozen=True)
class ProducerConsumerTarget:
    name: str
    required_variables: frozenset[str]
    producer: HttpStep
    captures: tuple[Capture, ...]
    consumer: HttpStep
    mutations: tuple[RequestMutation, ...]
    control_expectation: ResponseExpectation
    mutation_expectation: ResponseExpectation
    weights: CaseWeights = CaseWeights()
    malformed_expectation: ResponseExpectation = DEFAULT_MALFORMED_EXPECTATION

    def __post_init__(self) -> None:
        if not self.mutations:
            raise ValueError(f"target {self.name} must declare at least one mutation")


@dataclass(frozen=True)
class FlowStep:
    """One step of a multi-step flow. `fuzz` marks the step the mutation breaks."""

    request: HttpStep
    captures: tuple[Capture, ...] = ()
    fuzz: bool = False


@dataclass(frozen=True)
class FlowTarget:
    """A hacker-style flow: build valid state across steps, break one step, observe.

    Steps before the fuzz step run valid and establish state (captured values thread
    forward). The fuzz step is mutated. If it is wrongly accepted, the flow continues
    so a downstream step's oracle can catch propagated corruption.
    """

    name: str
    required_variables: frozenset[str]
    steps: tuple[FlowStep, ...]
    mutations: tuple[RequestMutation, ...]
    mutation_expectation: ResponseExpectation
    weights: CaseWeights = CaseWeights()
    malformed_expectation: ResponseExpectation = DEFAULT_MALFORMED_EXPECTATION

    def __post_init__(self) -> None:
        if not self.mutations:
            raise ValueError(f"flow {self.name} must declare at least one mutation")
        fuzz_steps = [index for index, step in enumerate(self.steps) if step.fuzz]
        if len(fuzz_steps) != 1:
            raise ValueError(f"flow {self.name} must mark exactly one step with fuzz: true")


Target = RequestTarget | ProducerConsumerTarget | FlowTarget


@dataclass(frozen=True)
class StepExecution:
    name: str
    request: HttpRequest
    result: HttpResult
    captures: tuple[tuple[str, object], ...] = ()
    replayable: bool = True


@dataclass(frozen=True)
class WorkflowCase:
    target: str
    iteration: int
    mutation: MutationRecord | None
    steps: tuple[StepExecution, ...]
