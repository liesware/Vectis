
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
        if isinstance(result, CaseResult):
            case_passed = result.passed
        elif require_result and case.weight != 0:
            raise WorkflowError(
                f"positive case {case.name!r} must return CaseResult(passed=N)"
            )
        else:
            case_passed = case.weight
        passed += case_passed
        if on_case_complete is not None:
            on_case_complete(case, case_passed, passed)
    return passed
