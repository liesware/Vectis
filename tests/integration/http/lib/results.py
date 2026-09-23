"""Ordered case execution and stable suite summaries."""

from dataclasses import dataclass

from .client import WorkflowError


@dataclass(frozen=True)
class CaseResult:
    passed: int = 1


@dataclass(frozen=True)
class Case:
    name: str
    run: object
    weight: int = 1


def run_cases(context, cases, require_result=False, on_case_complete=None):
    passed = 0
    for case in cases:
        context.current_case = case.name
        result = case.run(context)
        # A case may return an explicit CaseResult (aggregated workflows that count
        # many sub-checks) or nothing, in which case one successful case is worth its
        # declared weight (default 1, preserving the historical totals).
        if isinstance(result, CaseResult):
            case_passed = result.passed
        elif require_result and case.weight != 0:
            # Positive cases carry their count in the returned CaseResult; without
            # this guard a forgotten `return CaseResult(...)` would silently fall
            # back to weight=1 and undercount the suite instead of failing.
            raise WorkflowError(
                f"positive case {case.name!r} must return CaseResult(passed=N)"
            )
        else:
            case_passed = case.weight
        passed += case_passed
        if on_case_complete is not None:
            on_case_complete(case, case_passed, passed)
    return passed
