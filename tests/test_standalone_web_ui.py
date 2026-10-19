import contextlib
import io
import json
import os
import socket
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from vault_mcp import web_ui
from vault_mcp.web_ui import VaultWebUI


def _server(authenticated=True, expires_in=None):
    return SimpleNamespace(
        current_env="dev",
        environments={"dev": {}, "sat": {}, "prod": {}},
        _ensure_authenticated=lambda: authenticated,
        vault_token_expires_at=None if expires_in is None else time.time() + expires_in,
        login_sync=mock.Mock(return_value=json.dumps({"success": True, "environment": "dev"})),
    )


class HealthAndLockTests(unittest.TestCase):
    def _client(self, server, locked_env="dev"):
        return VaultWebUI(server, host="127.0.0.1", port=0, timeout_minutes=0, locked_env=locked_env).app.test_client()

    def test_health_reports_authenticated(self):
        body = self._client(_server(True, expires_in=1800)).get("/api/health").get_json()
        self.assertEqual(body["vault"], "authenticated")
        self.assertEqual(body["environment"], "dev")
        self.assertIsInstance(body["token_ttl"], int)
        self.assertFalse({k for k in body if "token" in k or "secret" in k} - {"token_ttl"})

    def test_health_reports_unauthenticated(self):
        body = self._client(_server(False)).get("/api/health").get_json()
        self.assertEqual(body["vault"], "unauthenticated")

    def test_locked_environment_is_reported(self):
        body = self._client(_server()).get("/api/environment").get_json()
        self.assertTrue(body["locked"])
        self.assertEqual(body["available_environments"], ["dev"])

    def test_login_for_another_env_is_rejected_when_locked(self):
        server = _server()
        response = self._client(server).post("/api/login", json={"environment": "prod"})
        self.assertEqual(response.status_code, 400)
        server.login_sync.assert_not_called()

    def test_login_for_the_locked_env_re_authenticates(self):
        server = _server()
        response = self._client(server).post("/api/login", json={"environment": "dev"})
        self.assertEqual(response.status_code, 200)
        server.login_sync.assert_called_once_with("dev", from_web_ui=True)


class TimeoutTests(unittest.TestCase):
    def test_timeout_reports_disabled_in_standalone_mode(self):
        ui = VaultWebUI(_server(), host="127.0.0.1", port=0, timeout_minutes=0, locked_env="dev")
        body = ui.app.test_client().get("/api/timeout").get_json()
        self.assertTrue(body["disabled"])
        self.assertIsNone(body["remaining_seconds"])


class RefreshTests(unittest.TestCase):
    def _ui(self, server):
        return VaultWebUI(server, host="127.0.0.1", port=0, timeout_minutes=0, locked_env="dev")

    def test_refresh_logs_in_again_near_token_expiry(self):
        with mock.patch.dict(os.environ, {"VAULT_MCP_AWS_CREDENTIALS": "ambient"}):
            soon = _server(expires_in=120)
            self._ui(soon).refresh_login_if_needed()
            soon.login_sync.assert_called_once_with("dev", from_web_ui=True)
            later = _server(expires_in=3600)
            self._ui(later).refresh_login_if_needed()
            later.login_sync.assert_not_called()


class MainTests(unittest.TestCase):
    def test_version_flag_prints_the_capability_line(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = web_ui.main(["--version"])
        self.assertEqual(code, 0)
        self.assertEqual(out.getvalue().strip(), "vault-mcp-web-ui standalone 1")

    def test_busy_port_exits_with_code_2(self):
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        port = blocker.getsockname()[1]
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err), mock.patch.object(web_ui, "_make_vault_server", return_value=_server()):
                code = web_ui.main(["--env", "dev", "--port", str(port)])
        finally:
            blocker.close()
        self.assertEqual(code, 2)
        self.assertIn(f"Port {port} is already in use", err.getvalue())


if __name__ == "__main__":
    unittest.main()
