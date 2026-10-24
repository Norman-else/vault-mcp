import os
import unittest
from unittest.mock import patch

from vault_mcp.server import VaultMCPServer


class TestVaultTransport(unittest.TestCase):
    def server(self):
        return VaultMCPServer.__new__(VaultMCPServer)

    def test_desktop_mode_uses_hvac_keep_alive(self):
        with patch.dict(os.environ, {'VAULT_MCP_AWS_CREDENTIALS': 'ambient'}):
            os.environ.pop('VAULT_TRANSPORT', None)
            self.assertEqual(self.server()._preferred_vault_transport(), 'hvac')

    def test_mcp_mode_keeps_curl(self):
        with patch.dict(os.environ, {}, clear=False), patch('shutil.which', return_value='/usr/bin/curl'):
            os.environ.pop('VAULT_MCP_AWS_CREDENTIALS', None)
            os.environ.pop('VAULT_TRANSPORT', None)
            self.assertEqual(self.server()._preferred_vault_transport(), 'curl')

    def test_no_proxy_host_skips_explicit_proxy(self):
        env = {'VAULT_TRANSPORT': 'hvac', 'HTTPS_PROXY': 'http://127.0.0.1:7897',
               'NO_PROXY': 'vault.internal.example', 'no_proxy': 'vault.internal.example'}
        with patch.dict(os.environ, env), patch('vault_mcp.server.hvac.Client') as client:
            self.server()._create_vault_client('https://vault.internal.example', token='t')
            self.assertNotIn('proxies', client.call_args.kwargs)
            self.server()._create_vault_client('https://vault.elsewhere.example', token='t')
            self.assertEqual(client.call_args.kwargs['proxies']['https'], 'http://127.0.0.1:7897')


if __name__ == '__main__':
    unittest.main()
