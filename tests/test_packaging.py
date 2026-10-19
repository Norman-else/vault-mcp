import pathlib
import shutil
import subprocess
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


@unittest.skipIf(shutil.which("uv") is None, "uv not installed")
class PackagingTests(unittest.TestCase):
    def test_wheel_has_console_script_and_ui(self):
        """Infra Desktop runs `uvx ... vault-mcp-web-ui`, so the wheel needs the script and the built UI."""
        with tempfile.TemporaryDirectory() as out:
            subprocess.run(["uv", "build", "--wheel", "-o", out, str(ROOT)], check=True, capture_output=True)
            wheel = next(pathlib.Path(out).glob("*.whl"))
            with zipfile.ZipFile(wheel) as zf:
                names = zf.namelist()
                entry_points = zf.read(next(n for n in names if n.endswith("entry_points.txt"))).decode()
        self.assertIn("vault-mcp-web-ui = vault_mcp.web_ui:main", entry_points)
        self.assertIn("vault_mcp/static/ui/index.html", names)


if __name__ == "__main__":
    unittest.main()
