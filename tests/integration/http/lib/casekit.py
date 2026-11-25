
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
