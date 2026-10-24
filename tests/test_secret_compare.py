import os
import socket
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from werkzeug.serving import make_server

from vault_mcp.web_ui import VaultWebUI, parse_peers


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


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class TestPeerCompare(unittest.TestCase):
    def test_peers_are_loopback_only(self):
        self.assertEqual(parse_peers('sat=http://127.0.0.1:9292/, prod=http://10.0.0.5:9293,bad'),
                         {'sat': 'http://127.0.0.1:9292'})

    def test_locked_ui_compares_with_running_peers(self):
        def server(env, data):
            return SimpleNamespace(current_env=env, environments={'dev': {}, 'sat': {}, 'prod': {}},
                                   vault_client=client(data), env_clients={},
                                   _ensure_authenticated=lambda: True)
        peer = make_server('127.0.0.1', 0, VaultWebUI(server('sat', {'a': 'x', 'b': 2}), locked_env='sat').app)
        threading.Thread(target=peer.serve_forever, daemon=True).start()
        self.addCleanup(peer.shutdown)
        peers = f'sat=http://127.0.0.1:{peer.server_port},prod=http://127.0.0.1:{free_port()}'
        # an HTTP proxy in the environment must not be used for local peers
        with patch.dict(os.environ, {'VAULT_MCP_PEERS': peers, 'HTTP_PROXY': 'http://127.0.0.1:1'}):
            ui = VaultWebUI(server('dev', {'a': 'x'}), locked_env='dev').app.test_client()
            self.assertTrue(ui.get('/api/environment').json['can_compare'])
            body = ui.get('/api/secrets/compare?path=app').json
        envs = {item['environment']: item for item in body['environments']}
        self.assertEqual([item['environment'] for item in body['environments']], ['dev', 'sat', 'prod'])
        self.assertEqual(envs['dev']['keys']['a'], envs['sat']['keys']['a'])
        self.assertIn('b', envs['sat']['keys'])
        self.assertEqual(envs['prod']['status'], 'not_running')

    def test_locked_ui_without_peers_cannot_compare(self):
        server = SimpleNamespace(current_env='dev', environments={'dev': {}, 'sat': {}},
                                 _ensure_authenticated=lambda: True)
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('VAULT_MCP_PEERS', None)
            body = VaultWebUI(server, locked_env='dev').app.test_client().get('/api/environment').json
        self.assertFalse(body['can_compare'])


if __name__ == '__main__':
    unittest.main()
