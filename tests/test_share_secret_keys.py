import asyncio
import json
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

from vault_mcp.server import VaultMCPServer


SECRET_DATA = {
    "DB_HOST": "db.example.com",
    "DB_PORT": "5432",
    "DB_PASSWORD": "s3cret",
    "API_TOKEN": "tok-123",
}


class ShareSecretKeysTests(unittest.TestCase):
    def _server(self):
        server = VaultMCPServer()
        server.current_env = "dev"
        server.slack_user_id = "OPERATOR"
        server.slack_client = MagicMock()
        server.vault_client = MagicMock()
        server._ensure_authenticated = lambda: True
        server._find_slack_users = lambda q: [
            {"id": "UALICE", "real_name": "Alice", "display_name": "alice"}
        ]
        server._get_slack_user_real_name = lambda uid: "Operator"
        server.vault_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": dict(SECRET_DATA)}
        }
        return server

    def _share(self, server, **kwargs):
        with patch("vault_mcp.server.SLACK_AVAILABLE", True):
            return json.loads(
                asyncio.run(
                    server.vault_share_secret(
                        path="item-management-service",
                        slack_user="alice",
                        **kwargs,
                    )
                )
            )

    def _dm_call(self, server):
        """Return the chat_postMessage call that targeted the recipient DM."""
        calls = [
            c
            for c in server.slack_client.chat_postMessage.call_args_list
            if c.kwargs.get("channel") == "UALICE"
        ]
        self.assertEqual(len(calls), 1)
        return calls[0]

    def _audit_call(self, server):
        """Return the chat_postMessage call that targeted the audit channel."""
        calls = [
            c
            for c in server.slack_client.chat_postMessage.call_args_list
            if c.kwargs.get("channel") != "UALICE"
        ]
        self.assertEqual(len(calls), 1)
        return calls[0]

    def test_full_share_without_keys_sends_everything_and_audits(self):
        server = self._server()
        result = self._share(server)

        self.assertTrue(result["success"])
        self.assertNotIn("shared_keys", result)

        dm_text = json.dumps(self._dm_call(server).kwargs["blocks"])
        for key in SECRET_DATA:
            self.assertIn(key, dm_text)

        audit = self._audit_call(server)
        audit_text = json.dumps(audit.kwargs["blocks"])
        self.assertIn("Vault Secret Sent", audit_text)
        self.assertIn("secret/item-management-service", audit_text)
        self.assertIn("s3cret", audit_text)
        # Must never look like a db-credentials notification.
        self.assertNotIn("New Database Credentials Sent", audit_text)
        self.assertNotIn("New credentials sent", audit.kwargs["text"])

    def test_keys_filter_sends_only_requested_keys(self):
        server = self._server()
        result = self._share(server, keys=["DB_HOST", "DB_PORT"])

        self.assertTrue(result["success"])
        self.assertEqual(result["shared_keys"], ["DB_HOST", "DB_PORT"])
        self.assertNotIn("missing_keys", result)

        dm_text = json.dumps(self._dm_call(server).kwargs["blocks"])
        self.assertIn("DB_HOST", dm_text)
        self.assertIn("DB_PORT", dm_text)
        self.assertNotIn("s3cret", dm_text)
        self.assertNotIn("tok-123", dm_text)
        self.assertIn("partial share", dm_text)

        # Audit contains only the filtered subset too.
        audit_text = json.dumps(self._audit_call(server).kwargs["blocks"])
        self.assertIn("db.example.com", audit_text)
        self.assertNotIn("s3cret", audit_text)

    def test_missing_keys_sends_subset_with_warning(self):
        server = self._server()
        result = self._share(server, keys=["DB_HOST", "NO_SUCH_KEY"])

        self.assertTrue(result["success"])
        self.assertEqual(result["shared_keys"], ["DB_HOST"])
        self.assertEqual(result["missing_keys"], ["NO_SUCH_KEY"])
        self.assertIn("NO_SUCH_KEY", result["warning"])

        dm_text = json.dumps(self._dm_call(server).kwargs["blocks"])
        self.assertIn("db.example.com", dm_text)
        self.assertNotIn("NO_SUCH_KEY", dm_text)

    def test_all_keys_missing_sends_nothing(self):
        server = self._server()
        result = self._share(server, keys=["NOPE_A", "NOPE_B"])

        self.assertFalse(result["success"])
        self.assertEqual(sorted(result["available_keys"]), sorted(SECRET_DATA))
        server.slack_client.chat_postMessage.assert_not_called()

    def test_empty_keys_list_rejected(self):
        server = self._server()
        result = self._share(server, keys=[])

        self.assertFalse(result["success"])
        self.assertIn("non-empty", result["error"])
        server.slack_client.chat_postMessage.assert_not_called()

    def test_keys_with_db_type_rejected(self):
        server = self._server()
        result = self._share(
            server, secret_type="db", keys=["username"]
        )

        self.assertFalse(result["success"])
        self.assertIn("only supported for kv", result["error"])
        server.slack_client.chat_postMessage.assert_not_called()

    def test_audit_failure_does_not_fail_share(self):
        server = self._server()

        def _post(channel=None, **kwargs):
            if channel != "UALICE":
                raise RuntimeError("audit channel gone")
            return {"ok": True}

        server.slack_client.chat_postMessage.side_effect = _post
        result = self._share(server, keys=["DB_HOST"])

        self.assertTrue(result["success"])
        self.assertEqual(result["shared_keys"], ["DB_HOST"])


class AuditTimestampTests(unittest.TestCase):
    """The audit timestamp used to be built with strftime's "%-d"/"%-I", a glibc
    extension that makes strftime raise "Invalid format string" on Windows and
    took every secret share down with it. These assertions hold on any platform."""

    def test_day_and_hour_are_not_zero_padded(self):
        formatted = VaultMCPServer._format_audit_timestamp(
            datetime(2026, 8, 5, 21, 7, 3)
        )

        self.assertIn(" 5, 2026, ", formatted)
        self.assertNotIn(" 05, ", formatted)
        self.assertIn("9:07:03", formatted)
        self.assertNotIn("09:07:03", formatted)
        self.assertTrue(formatted.startswith(datetime(2026, 8, 5).strftime("%b")))

    def test_midnight_and_noon_render_as_twelve(self):
        self.assertIn(
            "12:00:00",
            VaultMCPServer._format_audit_timestamp(datetime(2026, 8, 5, 0, 0, 0)),
        )
        self.assertIn(
            "12:00:00",
            VaultMCPServer._format_audit_timestamp(datetime(2026, 8, 5, 12, 0, 0)),
        )


if __name__ == "__main__":
    unittest.main()
