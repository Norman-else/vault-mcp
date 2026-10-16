import json
import types
import unittest
from unittest import mock

from vault_mcp.server import VaultMCPServer


class AwsVaultMfaWaitTests(unittest.TestCase):
    """The Web UI login path must not cap how long aws-vault may take: the user
    has to find and answer the MFA prompt first. The MCP path is capped at 180s,
    and on macOS it must use the osascript dialog because stdio has no terminal."""

    def _login(self, from_web_ui):
        server = VaultMCPServer()
        completed = types.SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "AccessKeyId": "access-key",
                    "SecretAccessKey": "secret-key",
                    "SessionToken": "session-token",
                }
            ),
            stderr="",
        )

        with mock.patch.object(
            server, "_find_aws_vault_path", return_value="/usr/local/bin/aws-vault"
        ), mock.patch("platform.system", return_value="Darwin"), mock.patch(
            "vault_mcp.server.subprocess.run", return_value=completed
        ) as run_mock:
            credentials = server._get_aws_credentials_via_awsvault(
                "dev",
                from_web_ui=from_web_ui,
            )

        return credentials, run_mock

    def test_web_ui_macos_awsvault_waits_without_timeout_limit(self):
        credentials, run_mock = self._login(from_web_ui=True)

        run_mock.assert_called_once()
        args, kwargs = run_mock.call_args
        self.assertEqual(
            args[0],
            [
                "/usr/local/bin/aws-vault",
                "exec",
                "dev",
                "--json",
                "--prompt=osascript",
            ],
        )
        self.assertNotIn("timeout", kwargs)
        self.assertEqual(
            credentials,
            {
                "AWS_ACCESS_KEY_ID": "access-key",
                "AWS_SECRET_ACCESS_KEY": "secret-key",
                "AWS_SESSION_TOKEN": "session-token",
            },
        )

    def test_mcp_login_uses_osascript_prompt_with_180s_timeout(self):
        _, run_mock = self._login(from_web_ui=False)

        args, kwargs = run_mock.call_args
        self.assertIn("--prompt=osascript", args[0])
        self.assertEqual(kwargs["timeout"], 180)


if __name__ == "__main__":
    unittest.main()
