import json
import threading
import types
import unittest
from unittest import mock

from vault_mcp.server import VaultMCPServer


class AwsVaultPromptRaiserTests(unittest.TestCase):
    """aws-vault's wincredui MFA dialog is spawned from this server process, which
    owns no window and therefore has no foreground rights, so Windows opens the
    dialog behind the browser showing the Web UI. The Web UI login path must run a
    watcher that lifts the dialog into view while it blocks on the subprocess."""

    def _login(self, system):
        server = VaultMCPServer()
        completed = types.SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "AccessKeyId": "AKIA_TEST",
                    "SecretAccessKey": "secret",
                    "SessionToken": "token",
                }
            ),
            stderr="",
        )
        raiser_started = threading.Event()

        def fake_raiser(stop_event):
            raiser_started.set()
            stop_event.wait(5)

        with mock.patch.object(
            server, "_find_aws_vault_path", return_value="C:/aws-vault.exe"
        ), mock.patch("platform.system", return_value=system), mock.patch.object(
            server, "_raise_awsvault_mfa_prompt", side_effect=fake_raiser
        ), mock.patch(
            "vault_mcp.server.subprocess.run", return_value=completed
        ):
            credentials = server._get_aws_credentials_via_awsvault(
                "dev", from_web_ui=True
            )

        return credentials, raiser_started

    def test_windows_web_ui_login_lifts_mfa_prompt(self):
        credentials, raiser_started = self._login("Windows")

        self.assertEqual(credentials["AWS_ACCESS_KEY_ID"], "AKIA_TEST")
        self.assertTrue(
            raiser_started.wait(2), "MFA prompt raiser was never started on Windows"
        )

    def test_macos_web_ui_login_does_not_lift_mfa_prompt(self):
        credentials, raiser_started = self._login("Darwin")

        self.assertEqual(credentials["AWS_ACCESS_KEY_ID"], "AKIA_TEST")
        self.assertFalse(
            raiser_started.is_set(),
            "MFA prompt raiser should be Windows-only; osascript prompts come to front",
        )

    def test_cli_login_does_not_lift_mfa_prompt(self):
        server = VaultMCPServer()
        completed = types.SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "AccessKeyId": "AKIA_TEST",
                    "SecretAccessKey": "secret",
                    "SessionToken": "token",
                }
            ),
            stderr="",
        )
        raiser_started = threading.Event()

        with mock.patch.object(
            server, "_find_aws_vault_path", return_value="C:/aws-vault.exe"
        ), mock.patch("platform.system", return_value="Windows"), mock.patch.object(
            server,
            "_raise_awsvault_mfa_prompt",
            side_effect=lambda stop_event: raiser_started.set(),
        ), mock.patch(
            "vault_mcp.server.subprocess.run", return_value=completed
        ):
            server._get_aws_credentials_via_awsvault("dev", from_web_ui=False)

        self.assertFalse(raiser_started.is_set())


if __name__ == "__main__":
    unittest.main()
