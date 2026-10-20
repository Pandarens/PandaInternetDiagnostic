"""The exe bundles only stdlib modules imported by launcher.py; the app code is a zip PyInstaller never sees.
If panda_diag starts importing a module the launcher doesn't, hot updates would crash inside old exes —
add it to launcher.py and bump LAUNCHER_VERSION / MIN_LAUNCHER."""
import ast
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPTIONAL = {"tplinkrouterc6u", "huawei_lte_api"}  # third-party, imported lazily inside try/except


def imports(path):
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            out |= {a.name for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
            out.add(n.module)
    return out


class LauncherDeps(unittest.TestCase):
    def test_all_app_imports_bundled(self):
        launcher = imports(os.path.join(ROOT, "launcher.py"))
        needed = set()
        for dp, _, files in os.walk(os.path.join(ROOT, "panda_diag")):
            for f in files:
                if f.endswith(".py"):
                    needed |= imports(os.path.join(dp, f))
        needed = {m for m in needed if m.split(".")[0] not in OPTIONAL and not m.startswith("panda_diag")}
        missing = sorted(m for m in needed if m not in launcher and m.split(".")[0] in sys.stdlib_module_names
                         and m.split(".")[0] not in sys.builtin_module_names
                         and not any(x == m or x.startswith(m + ".") for x in launcher))
        self.assertEqual(missing, [], f"add to launcher.py imports: {missing}")

    def test_bundle_version_matches(self):
        sys.path.insert(0, ROOT)
        import launcher
        import panda_diag
        self.assertGreaterEqual(launcher._ver(launcher.LAUNCHER_VERSION), launcher._ver(panda_diag.MIN_LAUNCHER))


if __name__ == "__main__":
    unittest.main()
