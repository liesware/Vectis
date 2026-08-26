import ast
from pathlib import Path
import unittest


class ArchitectureTests(unittest.TestCase):
    def test_generic_package_does_not_import_vectis_project(self):
        package = Path(__file__).resolve().parents[1] / "src" / "nadir"
        for path in package.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                else:
                    continue
                self.assertTrue(
                    all("vectis" not in name and "projects" not in name for name in names),
                    f"generic Nadir module imports project knowledge: {path}",
                )

