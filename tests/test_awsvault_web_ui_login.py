import importlib.util
import json
import pathlib
import sys
import types
import unittest
from unittest import mock


def _stub_module(name: str, **attrs):
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    sys.modules[name] = module
    return module


def _load_server_module():
    if "vault_mcp.server" in sys.modules:
        return sys.modules["vault_mcp.server"]

    _stub_module("hvac", Client=object)
    _stub_module("boto3")
    _stub_module("mcp")
    _stub_module(
        "mcp.types",
        Tool=object,
        TextContent=object,
        CallToolRequestParams=object,
        CallToolResult=object,
        ListResourcesResult=object,
        ListToolsResult=object,
        PaginatedRequestParams=object,
    )

    class _FakeServer:
        def __init__(self, *_args, **_kwargs):
            pass

    _stub_module("mcp.server", Server=_FakeServer, ServerRequestContext=object)
    _stub_module("mcp.server.stdio", stdio_server=lambda: None)

    package = types.ModuleType("vault_mcp")
    package.__path__ = []
    sys.modules["vault_mcp"] = package
    _stub_module("vault_mcp.web_ui", VaultWebUI=object)

    server_path = pathlib.Path(__file__).resolve().parents[1] / "src" / "vault_mcp" / "server.py"
    spec = importlib.util.spec_from_file_location("vault_mcp.server", server_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["vault_mcp.server"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class AwsVaultWebUiLoginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_module = _load_server_module()

    def setUp(self):
        self.server = self.server_module.VaultMCPServer()

    def test_windows_web_ui_login_uses_interactive_exec_prompt(self):
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

        with mock.patch.object(self.server, "_find_aws_vault_path", return_value="C:/aws-vault.exe"), \
             mock.patch("platform.system", return_value="Windows"), \
             mock.patch("vault_mcp.server.subprocess.run", return_value=completed) as run_mock:
            creds = self.server._get_aws_credentials_via_awsvault("prod", from_web_ui=True)

        self.assertEqual(
            creds,
            {
                "AWS_ACCESS_KEY_ID": "AKIA_TEST",
                "AWS_SECRET_ACCESS_KEY": "secret",
                "AWS_SESSION_TOKEN": "token",
            },
        )
        run_mock.assert_called_once()
        args, kwargs = run_mock.call_args
        self.assertEqual(
            args[0],
            [
                "C:/aws-vault.exe",
                "exec",
                "prod",
                "--json",
                "--prompt=wincredui",
            ],
        )
        self.assertEqual(kwargs["capture_output"], True)
        self.assertEqual(kwargs["text"], True)
        self.assertEqual(kwargs["creationflags"], 0x08000000)
        self.assertNotIn("timeout", kwargs)

    def test_login_sync_preserves_awsvault_failure_reason_when_env_is_empty(self):
        env_config = self.server.environments["prod"]

        def fake_awsvault(*_args, **_kwargs):
            self.server._last_awsvault_error = "aws-vault prompt was dismissed"
            return None

        with mock.patch.object(self.server, "_switch_k8s_context", return_value=True), \
             mock.patch.object(self.server, "_create_vault_client", return_value=object()), \
             mock.patch.object(
                 self.server,
                 "_get_aws_credentials_via_awsvault",
                 side_effect=fake_awsvault,
             ), \
             mock.patch.dict(
                 "vault_mcp.server.os.environ",
                 {},
                 clear=True,
             ):
            result = json.loads(self.server.login_sync("prod", from_web_ui=True))

        self.assertEqual(result["success"], False)
        self.assertIn("No AWS credentials found", result["message"])
        self.assertIn("aws-vault prompt was dismissed", result["message"])
        self.assertIn("PROD", result["message"])


if __name__ == "__main__":
    unittest.main()
