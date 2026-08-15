import json
import types
import unittest
from unittest import mock

from vault_mcp.server import VaultMCPServer


class AwsVaultMfaWaitTests(unittest.TestCase):
    """The Web UI login path must not cap how long aws-vault may take: the user
    has to find and answer the MFA prompt first. The CLI path keeps its 30s cap,
    because there the prompt appears in the terminal they are already looking at."""

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

    def test_cli_login_keeps_its_timeout(self):
        _, run_mock = self._login(from_web_ui=False)

        _, kwargs = run_mock.call_args
        self.assertEqual(kwargs["timeout"], 30)


if __name__ == "__main__":
    unittest.main()
