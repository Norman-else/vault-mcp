import asyncio
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from vault_mcp.server import VaultMCPServer


class SyncPostgresMcpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config_path = os.path.join(self.tmp.name, "environments.json")
        self._write({
            "default_environment": "dev-data",
            "environments": {
                "dev-data": {
                    "description": "keep me",
                    "database": {"host": "h", "port": 5432, "database": "data_service",
                                 "user": "old", "password": "old"},
                }
            },
        })
        patcher = patch.object(
            VaultMCPServer, "get_mcp_config_path", staticmethod(lambda: self.config_path)
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _write(self, config):
        with open(self.config_path, "w") as f:
            json.dump(config, f)

    def _read(self):
        with open(self.config_path) as f:
            return json.load(f)

    def _server(self):
        server = VaultMCPServer()
        server.current_env = "dev"
        server.vault_client = MagicMock()
        server._ensure_authenticated = lambda: True
        server.vault_client.read.return_value = {
            "data": {"username": "v-user", "password": "v-s3cret"},
            "lease_duration": 3600,
        }
        server.vault_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"host.db_server": "db.internal"}}
        }
        return server

    def _sync(self, server, service):
        raw = asyncio.run(server.vault_sync_db_creds_to_postgres_mcp(service=service))
        return raw, json.loads(raw)

    def test_updates_existing_environment_without_leaking_credentials(self):
        server = self._server()
        raw, result = self._sync(server, "database/creds/data-service")

        server.vault_client.read.assert_called_once_with("database/creds/data-service")
        self.assertTrue(result["success"])
        self.assertEqual(result["environment"], "dev-data")
        self.assertEqual(result["action"], "updated")
        self.assertNotIn("v-s3cret", raw)
        self.assertNotIn("v-user", raw)

        env = self._read()["environments"]["dev-data"]
        self.assertEqual(env["database"]["user"], "v-user")
        self.assertEqual(env["database"]["password"], "v-s3cret")
        self.assertEqual(env["database"]["host"], "h")
        self.assertEqual(env["description"], "keep me")

    def test_creates_new_environment_from_application_secret(self):
        server = self._server()
        _, result = self._sync(server, "item-management-service")

        self.assertEqual(result["action"], "created")
        self.assertEqual(result["environment"], "dev-item-management")
        db = self._read()["environments"]["dev-item-management"]["database"]
        self.assertEqual(db["host"], "db.internal")
        self.assertEqual(db["database"], "item_management_service")
        self.assertEqual(db["user"], "v-user")

    def test_requires_authentication(self):
        server = self._server()
        server._ensure_authenticated = lambda: False
        _, result = self._sync(server, "data-service")

        self.assertFalse(result["success"])
        server.vault_client.read.assert_not_called()
        self.assertEqual(self._read()["environments"]["dev-data"]["database"]["user"], "old")

    def test_missing_config_file_is_an_error(self):
        os.remove(self.config_path)
        _, result = self._sync(self._server(), "data-service")

        self.assertFalse(result["success"])
        self.assertIn("not found", result["error"])
        self.assertFalse(os.path.exists(self.config_path))


if __name__ == "__main__":
    unittest.main()
