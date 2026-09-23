"""Decorator-based case registration.

A case module declares one ``CaseSet`` and decorates plain functions with it::

    from lib.casekit import CaseSet

    cases = CaseSet()

    @cases("token decode rejects unknown profile")
    def _(ctx):
        status, _ = ctx.post("/token/decode", {...})
        ctx.expect(status, 400)

    CASES = cases.tuple()

Registration happens in definition order (deterministic), so a new case is just a
new decorated function -- no manual tuple, no run_case, no registry edit for the
case itself. Each case counts its ``weight`` toward the suite total (default 1);
positive cases that assert several rows in one function pass ``weight=N`` to keep
the historical SUMMARY numbers stable.
"""

from lib.results import Case


class CaseSet:
    def __init__(self):
        self._cases = []

    def __call__(self, name, weight=1):
        def register(func):
            self._cases.append(Case(name, func, weight))
            return func

        return register

    def tuple(self):
        return tuple(self._cases)
