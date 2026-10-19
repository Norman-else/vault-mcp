import json
import os
import time
import types
import unittest
from types import SimpleNamespace
from unittest import mock

from test_awsvault_web_ui_login import _load_server_module

AMBIENT = {"VAULT_MCP_AWS_CREDENTIALS": "ambient"}


def _frozen(access="AK", secret="SK", token="TOK"):
    return SimpleNamespace(access_key=access, secret_key=secret, token=token)


def _session_returning(creds, method="container-role"):
    """boto3.Session stand-in whose get_credentials() yields `creds` (None = no credentials)."""
    credentials = None if creds is None else SimpleNamespace(get_frozen_credentials=lambda: creds, method=method)
    return mock.Mock(return_value=SimpleNamespace(get_credentials=lambda: credentials))


class AmbientLoginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = _load_server_module()

    def setUp(self):
        self.server = self.module.VaultMCPServer()
        self.iam_login = mock.Mock(return_value={"auth": {"client_token": "vault-token", "lease_duration": 3600}})
        self.client = SimpleNamespace(auth=SimpleNamespace(aws=SimpleNamespace(iam_login=self.iam_login)))
        patches = [
            mock.patch.object(self.server, "_create_vault_client", return_value=self.client),
            mock.patch.object(self.server, "_init_vault_client"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _login(self, env, session):
        with mock.patch.dict(os.environ, env, clear=False), \
             mock.patch.object(self.module.boto3, "Session", session, create=True), \
             mock.patch.object(self.server, "_switch_k8s_context", return_value=True) as switch, \
             mock.patch.object(self.server, "_get_aws_credentials_via_awsvault", return_value=None) as awsvault:
            if "VAULT_MCP_AWS_CREDENTIALS" not in env:
                os.environ.pop("VAULT_MCP_AWS_CREDENTIALS", None)
            result = json.loads(self.server.login_sync("dev", from_web_ui=True))
        return result, switch, awsvault

    def test_ambient_login_uses_boto3_credentials_and_not_aws_vault(self):
        result, _switch, awsvault = self._login(AMBIENT, _session_returning(_frozen()))
        self.assertTrue(result["success"], result)
        awsvault.assert_not_called()
        kwargs = self.iam_login.call_args.kwargs
        self.assertEqual((kwargs["access_key"], kwargs["secret_key"], kwargs["session_token"]), ("AK", "SK", "TOK"))

    def test_ambient_login_does_not_switch_kubectl_context(self):
        _result, switch, _awsvault = self._login(AMBIENT, _session_returning(_frozen()))
        switch.assert_not_called()

    def test_ambient_login_without_credentials_reports_an_error(self):
        result, _switch, awsvault = self._login(AMBIENT, _session_returning(None))
        self.assertFalse(result["success"])
        self.assertIn("No AWS credentials available", result["message"])
        awsvault.assert_not_called()

    def test_ambient_login_refuses_long_lived_shared_credentials(self):
        result, _switch, awsvault = self._login(AMBIENT, _session_returning(_frozen(), method="shared-credentials-file"))
        self.assertFalse(result["success"])
        self.assertIn("only accepts credentials provided by the caller", result["message"])
        self.iam_login.assert_not_called()
        awsvault.assert_not_called()

    def test_ambient_login_accepts_env_credentials(self):
        result, _switch, _awsvault = self._login(AMBIENT, _session_returning(_frozen(), method="env"))
        self.assertTrue(result["success"], result)

    def test_default_mode_still_uses_aws_vault(self):
        _result, _switch, awsvault = self._login({}, _session_returning(_frozen()))
        awsvault.assert_called_once()

    def test_token_expiry_is_recorded(self):
        self._login(AMBIENT, _session_returning(_frozen()))
        self.assertAlmostEqual(self.server.vault_token_expires_at, time.time() + 3600, delta=5)


class AmbientKubectlTests(unittest.TestCase):
    def test_kubectl_in_ambient_mode_inherits_credentials(self):
        from vault_mcp.web_ui import VaultWebUI

        awsvault = mock.Mock(return_value={"AWS_ACCESS_KEY_ID": "from-aws-vault"})
        server = SimpleNamespace(
            current_env="dev",
            environments={"dev": {"k8s_context": "acme-dev", "aws_profile": "dev", "aws_region": "us-west-2"}},
            _get_aws_credentials_via_awsvault=awsvault,
        )
        client = VaultWebUI(server).app.test_client()
        done = types.SimpleNamespace(returncode=0, stdout=json.dumps({"items": []}), stderr="")
        env = {**AMBIENT, "AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://127.0.0.1:1/creds/dev"}
        with mock.patch.dict(os.environ, env, clear=False), \
             mock.patch("vault_mcp.web_ui.subprocess.run", return_value=done) as run:
            os.environ.pop("AWS_PROFILE", None)
            response = client.get("/api/k8s/deployments")
        self.assertEqual(response.status_code, 200)
        run_env = run.call_args.kwargs["env"]
        self.assertFalse("AWS_PROFILE" in run_env, "kubectl env must not set AWS_PROFILE in ambient mode")
        self.assertEqual(run_env["AWS_CONTAINER_CREDENTIALS_FULL_URI"], "http://127.0.0.1:1/creds/dev")
        awsvault.assert_not_called()


if __name__ == "__main__":
    unittest.main()
