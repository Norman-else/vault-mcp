import json
import unittest
from unittest.mock import MagicMock, patch

from vault_mcp.server import VaultMCPServer


class AwsVaultMfaWaitTests(unittest.TestCase):
    def test_web_ui_macos_awsvault_waits_without_timeout_limit(self):
        server = VaultMCPServer()

        process = MagicMock()
        process.communicate.return_value = (
            json.dumps(
                {
                    "AccessKeyId": "access-key",
                    "SecretAccessKey": "secret-key",
                    "SessionToken": "session-token",
                }
            ),
            "",
        )
        process.returncode = 0

        with (
            patch.object(server, "_find_aws_vault_path", return_value="/usr/local/bin/aws-vault"),
            patch("platform.system", return_value="Darwin"),
            patch("vault_mcp.server.subprocess.Popen", return_value=process),
        ):
            credentials = server._get_aws_credentials_via_awsvault(
                "dev",
                from_web_ui=True,
            )

        process.communicate.assert_called_once_with()
        self.assertEqual(
            credentials,
            {
                "AWS_ACCESS_KEY_ID": "access-key",
                "AWS_SECRET_ACCESS_KEY": "secret-key",
                "AWS_SESSION_TOKEN": "session-token",
            },
        )


if __name__ == "__main__":
    unittest.main()
