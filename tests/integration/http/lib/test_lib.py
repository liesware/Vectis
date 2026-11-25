import ast
import tempfile
import unittest
from pathlib import Path

from lib.client import WorkflowError
from lib.config import ConfigTransaction
from lib.results import Case, CaseResult, run_cases

CASES_DIR = Path(__file__).resolve().parents[2] / "http" / "cases"
HTTP_DIR = CASES_DIR.parent
INTEGRATION_DIR = HTTP_DIR.parent
SUPPORT_DIR = INTEGRATION_DIR / "support"
TESTS_DIR = INTEGRATION_DIR.parent
PRIVATE_SUITE_PREFIXES = {
    "cli": ("tests.integration.http", "tests.security.fuzz", "tests.security.openapi", "tests.manual"),
    "http": ("tests.integration.cli", "tests.security.fuzz", "tests.security.openapi", "tests.manual"),
    "fuzz": ("tests.integration.cli", "tests.integration.http", "tests.security.openapi", "tests.manual"),
    "openapi": ("tests.integration.cli", "tests.integration.http", "tests.security.fuzz", "tests.manual"),
    "manual": ("tests.integration.cli", "tests.integration.http", "tests.security.fuzz", "tests.security.openapi"),
}
NON_CASE_FILES = {"registry.py", "negative_support.py", "__init__.py"}


def _module_declares_cases(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return any(
        isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "CASES" for t in node.targets)
        for node in tree.body
    )


def _registry_composed_modules():
    tree = ast.parse((CASES_DIR / "registry.py").read_text(encoding="utf-8"))
    modules = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "CASES"
            and isinstance(node.value, ast.Name)
        ):
            modules.add(node.value.id)
    return modules


class ResultsTests(unittest.TestCase):
    def test_runs_cases_in_declared_order_and_uses_explicit_counts(self):
        calls = []

        class Context:
            current_case = None

        def first(_context):
            calls.append("first")
            return CaseResult(passed=3)

        def second(_context):
            calls.append("second")

        self.assertEqual(
            run_cases(Context(), (Case("first", first), Case("second", second))),
            4,
        )
        self.assertEqual(calls, ["first", "second"])

    def test_reports_each_completed_case_with_its_cumulative_count(self):
        completed = []

        class Context:
            current_case = None

        cases = (
            Case("first", lambda _context: CaseResult(passed=2)),
            Case("second", lambda _context: None, weight=3),
        )

        total = run_cases(
            Context(),
            cases,
            on_case_complete=lambda case, case_passed, passed: completed.append(
                (case.name, case_passed, passed)
            ),
        )

        self.assertEqual(total, 5)
        self.assertEqual(completed, [("first", 2, 2), ("second", 3, 5)])

    def test_require_result_rejects_a_positive_case_without_a_caseresult(self):
        class Context:
            current_case = None

        def forgot(_context):
            return None

        with self.assertRaises(WorkflowError):
            run_cases(Context(), (Case("positive.forgot", forgot),), require_result=True)

    def test_require_result_allows_weight_zero_setup_without_a_caseresult(self):
        class Context:
            current_case = None

        def setup(_context):
            return None

        self.assertEqual(
            run_cases(Context(), (Case("positive.setup", setup, weight=0),), require_result=True),
            0,
        )


class ConfigTransactionTests(unittest.TestCase):
    def test_restores_both_config_files_from_a_single_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.json"
            signature = root / "config_sign.json"
            config.write_text('{"version":"v1"}', encoding="utf-8")
            signature.write_text('{"signature":"original"}', encoding="utf-8")

            transaction = ConfigTransaction(config, signature)
            transaction.capture()
            config.write_text('{"version":"changed"}', encoding="utf-8")
            signature.unlink()
            transaction.restore_files()

            self.assertEqual(config.read_text(encoding="utf-8"), '{"version":"v1"}')
            self.assertEqual(
                signature.read_text(encoding="utf-8"), '{"signature":"original"}'
            )
            transaction.close()


class StructuralGuardTests(unittest.TestCase):

    def test_no_monolithic_workflow_module_reappears(self):
        offenders = sorted(p.name for p in CASES_DIR.glob("*_workflow.py"))
        self.assertEqual(
            offenders,
            [],
            f"monolithic *_workflow.py case modules must not exist: {offenders}",
        )

    def test_every_case_file_uses_a_capability_prefix(self):
        offenders = [
            p.name
            for p in sorted(CASES_DIR.glob("*.py"))
            if p.name not in NON_CASE_FILES
            and not (p.name.startswith("positive_") or p.name.startswith("negative_"))
        ]
        self.assertEqual(
            offenders,
            [],
            f"case-directory modules must start with positive_ or negative_: {offenders}",
        )

    def test_no_case_module_uses_the_retired_global_patterns(self):
        forbidden = ("global config", "bind_config", "run_case(", "import *")
        offenders = {}
        for path in sorted(CASES_DIR.glob("*.py")):
            if path.name in NON_CASE_FILES:
                continue
            text = path.read_text(encoding="utf-8")
            hits = [pattern for pattern in forbidden if pattern in text]
            if hits:
                offenders[path.name] = hits
        self.assertEqual(
            offenders,
            {},
            f"case modules must use @cases + ctx, not the retired global patterns: {offenders}",
        )

    def test_every_declared_case_module_is_composed_by_the_registry(self):
        composed = _registry_composed_modules()
        orphans = [
            path.stem
            for path in sorted(CASES_DIR.glob("*.py"))
            if path.name not in NON_CASE_FILES
            and _module_declares_cases(path)
            and path.stem not in composed
        ]
        self.assertEqual(
            orphans,
            [],
            f"these modules declare CASES but the registry never composes them: {orphans}",
        )

    def test_integration_shared_support_package_does_not_exist(self):
        self.assertFalse(
            SUPPORT_DIR.exists(),
            "integration fixtures must remain suite-private; only tests/support/vectis.py is shared",
        )

    def test_test_suites_only_share_binary_resolution(self):
        shared_module = "support"
        offenders = [
            str(path.relative_to(TESTS_DIR))
            for path in sorted(TESTS_DIR.rglob("*.py"))
            if any(
                isinstance(node, (ast.Import, ast.ImportFrom))
                and (
                    (isinstance(node, ast.ImportFrom) and node.module == shared_module)
                    or (
                        isinstance(node, ast.ImportFrom)
                        and node.module is not None
                        and node.module.startswith(f"{shared_module}.")
                        and node.module != "support.vectis"
                    )
                    or (
                        isinstance(node, ast.Import)
                        and any(
                            alias.name == shared_module
                            or (alias.name.startswith(f"{shared_module}.") and alias.name != "support.vectis")
                            for alias in node.names
                        )
                    )
                )
                for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
            )
        ]
        self.assertEqual(
            offenders,
            [],
            f"test suites may share only support.vectis, not fixtures or assertions: {offenders}",
        )

    def test_suites_do_not_import_another_suite_private_package(self):
        suites = {
            "cli": INTEGRATION_DIR / "cli",
            "http": HTTP_DIR,
            "fuzz": TESTS_DIR / "security" / "fuzz",
            "openapi": TESTS_DIR / "security" / "openapi",
            "manual": TESTS_DIR / "manual",
        }
        offenders = []
        for suite, directory in suites.items():
            forbidden = PRIVATE_SUITE_PREFIXES[suite]
            for path in sorted(directory.rglob("*.py")):
                modules = [
                    node.module
                    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
                    if isinstance(node, ast.ImportFrom) and node.module is not None
                ]
                imports = [
                    alias.name
                    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
                    if isinstance(node, ast.Import)
                    for alias in node.names
                ]
                if any(
                    module == prefix or module.startswith(f"{prefix}.")
                    for module in [*modules, *imports]
                    for prefix in forbidden
                ):
                    offenders.append(str(path.relative_to(TESTS_DIR)))
        self.assertEqual(
            offenders,
            [],
            f"test suites must not import private packages from another suite: {offenders}",
        )
