import unittest
from types import SimpleNamespace

from vault_mcp.web_ui import VaultWebUI


class InvalidPath(Exception):
    pass


def client(data=None, error=None):
    def read_secret_version(path, mount_point):
        if error:
            raise error
        return {'data': {'data': data}}
    return SimpleNamespace(secrets=SimpleNamespace(kv=SimpleNamespace(v2=SimpleNamespace(
        read_secret_version=read_secret_version))))


class TestSecretCompare(unittest.TestCase):
    def test_reports_each_environment_without_values(self):
        server = SimpleNamespace(
            current_env='dev',
            environments={'dev': {}, 'sat': {}, 'prod': {}, 'local': {}},
            vault_client=client({'a': 'x', 'b': {'n': 1, 'm': 2}}),
            env_clients={'sat': client({'a': 'x', 'b': {'m': 2, 'n': 1}, 'c': 1}),
                         'prod': client(error=RuntimeError('{"errors":[]}'))},
            _ensure_authenticated=lambda: True,
        )
        body = VaultWebUI(server).app.test_client().get(
            '/api/secrets/compare?path=app&mount_point=secret').json
        envs = {item['environment']: item for item in body['environments']}
        self.assertEqual(envs['dev']['keys']['a'], envs['sat']['keys']['a'])
        # nested key order does not count as a difference
        self.assertEqual(envs['dev']['keys']['b'], envs['sat']['keys']['b'])
        self.assertIn('c', envs['sat']['keys'])
        self.assertEqual(envs['prod']['status'], 'missing')
        self.assertEqual(envs['local']['status'], 'signed_out')
        self.assertNotIn('x', str(body))

    def test_permission_errors_are_not_reported_as_missing(self):
        server = SimpleNamespace(
            current_env='dev', environments={'dev': {}}, env_clients={},
            vault_client=client(error=RuntimeError('permission denied')),
            _ensure_authenticated=lambda: True,
        )
        body = VaultWebUI(server).app.test_client().get('/api/secrets/compare?path=app').json
        self.assertEqual(body['environments'][0]['status'], 'error')
        hvac_missing = SimpleNamespace(**{**server.__dict__, 'vault_client': client(error=InvalidPath())})
        body = VaultWebUI(hvac_missing).app.test_client().get('/api/secrets/compare?path=app').json
        self.assertEqual(body['environments'][0]['status'], 'missing')


if __name__ == '__main__':
    unittest.main()
