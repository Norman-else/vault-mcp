"""Verify the packaged React UI without initializing Vault or AWS clients."""
import importlib.util
from pathlib import Path
import re
from types import SimpleNamespace
import unittest


def load_web_ui():
    path = Path(__file__).resolve().parents[1] / 'src' / 'vault_mcp' / 'web_ui.py'
    spec = importlib.util.spec_from_file_location('frontend_asset_web_ui', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.VaultWebUI


class FrontendAssetsTests(unittest.TestCase):
    def setUp(self):
        server = SimpleNamespace(current_env=None, environments={'dev': {}},
                                 _ensure_authenticated=lambda: False)
        self.ui = load_web_ui()(server)
        self.client = self.ui.app.test_client()

    def test_index_and_bundled_assets_are_served(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn('<div id="root"></div>', html)
        assets = re.findall(r'(?:src|href)="(/static/ui/[^\"]+)"', html)
        self.assertGreaterEqual(len(assets), 2)
        for asset in assets:
            result = self.client.get(asset)
            self.assertEqual(result.status_code, 200, asset)
            self.assertTrue(result.data)
            result.close()

    def test_legacy_ui_is_not_packaged(self):
        package = Path(__file__).resolve().parents[1] / 'src' / 'vault_mcp'
        self.assertFalse((package / 'templates' / 'vault_ui.html').exists())

    def test_static_assets_do_not_extend_idle_timeout(self):
        self.ui.last_access_time = 123
        self.client.get('/static/ui/index.html').close()
        self.assertEqual(self.ui.last_access_time, 123)

    def test_asset_path_traversal_is_rejected(self):
        response = self.client.get('/static/ui/../../web_ui.py')
        self.assertEqual(response.status_code, 404)


if __name__ == '__main__':
    unittest.main()
