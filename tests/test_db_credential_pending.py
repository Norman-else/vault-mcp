import json
import time
import unittest
from unittest.mock import MagicMock, call, patch

from vault_mcp.server import VaultMCPServer


def _request_message(ts, recipient_id, recipient_name, database, environment):
    """Build a Slack workflow request message directed at the operator."""
    return {
        "ts": ts,
        "text": (
            f"<@OPERATOR> Please provide the DB credential to "
            f"<@{recipient_id}|{recipient_name}>\n"
            f"Database: {database}\nEnvironment: {environment}"
        ),
    }


def _audit_message(ts, recipient_name, environment, service=None, sender_name="Operator"):
    """Build a Vault 'New Database Credentials Sent' audit notification."""
    service_line = f"Service: {service}\n" if service else ""
    return {
        "ts": ts,
        "text": (
            f"New Database Credentials Sent\nEnv: {environment}\n{service_line}"
            f"> username: x\n> password: y\n"
            f"and sent to {recipient_name} at some-time by {sender_name}."
        ),
    }


class PendingDbRequestTests(unittest.TestCase):
    _NAMES = {"UALICE": "Alice", "UBOB": "Bob", "OPERATOR": "Operator"}

    def _server(self):
        server = VaultMCPServer()
        server.slack_client = MagicMock()
        # Map ids to human names so audit-notification name matching works.
        server._get_slack_user_profile_summary = lambda uid: {
            "id": uid,
            "name": self._NAMES.get(uid, uid),
            "real_name": self._NAMES.get(uid, uid),
            "display_name": self._NAMES.get(uid, uid),
        }
        server._get_slack_operator_user_id = lambda: "OPERATOR"
        server._resolve_db_request_channel_id = lambda channel_id=None: "C123"
        return server

    def _history(self, messages):
        def _conversations_history(**kwargs):
            return {"messages": messages, "response_metadata": {"next_cursor": ""}}
        return _conversations_history

    def test_multiple_distinct_services_all_returned(self):
        server = self._server()
        now = time.time()
        msgs = [
            _request_message(f"{now-10:.6f}", "UALICE", "Alice", "service-a", "dev"),
            _request_message(f"{now-20:.6f}", "UALICE", "Alice", "service-b", "dev"),
        ]
        server.slack_client.conversations_history.side_effect = self._history(msgs)
        server.slack_client.conversations_replies.return_value = {"messages": []}

        with patch("vault_mcp.server.SLACK_AVAILABLE", True):
            result = json.loads(
                __import__("asyncio").run(
                    server.vault_get_pending_db_credential_requests()
                )
            )

        self.assertTrue(result["success"])
        self.assertEqual(result["counts"]["pending"], 2)
        services = {r["database"] for r in result["pending_requests"]}
        self.assertEqual(services, {"service-a", "service-b"})

    def test_same_service_same_recipient_deduped(self):
        server = self._server()
        now = time.time()
        msgs = [
            _request_message(f"{now-10:.6f}", "UALICE", "Alice", "service-a", "dev"),
            _request_message(f"{now-30:.6f}", "UALICE", "Alice", "service-a", "dev"),
            _request_message(f"{now-50:.6f}", "UALICE", "Alice", "service-a", "dev"),
        ]
        server.slack_client.conversations_history.side_effect = self._history(msgs)
        server.slack_client.conversations_replies.return_value = {"messages": []}

        with patch("vault_mcp.server.SLACK_AVAILABLE", True):
            result = json.loads(
                __import__("asyncio").run(
                    server.vault_get_pending_db_credential_requests()
                )
            )

        self.assertEqual(result["counts"]["pending"], 1)
        self.assertEqual(result["pending_requests"][0]["duplicate_count"], 3)

    def test_processed_service_does_not_hide_other_service(self):
        """service-a processed must NOT mark service-b as processed (the bug fix)."""
        server = self._server()
        now = time.time()
        msgs = [
            # newest: audit that service-a was sent to Alice in dev
            _audit_message(f"{now-5:.6f}", "Alice", "dev", service="service-a"),
            _request_message(f"{now-10:.6f}", "UALICE", "Alice", "service-a", "dev"),
            _request_message(f"{now-20:.6f}", "UALICE", "Alice", "service-b", "dev"),
        ]
        server.slack_client.conversations_history.side_effect = self._history(msgs)
        server.slack_client.conversations_replies.return_value = {"messages": []}

        with patch("vault_mcp.server.SLACK_AVAILABLE", True):
            result = json.loads(
                __import__("asyncio").run(
                    server.vault_get_pending_db_credential_requests()
                )
            )

        # service-a is processed; service-b must still be pending.
        pending_services = {r["database"] for r in result["pending_requests"]}
        self.assertIn("service-b", pending_services)
        self.assertNotIn("service-a", pending_services)
        self.assertEqual(result["counts"]["already_processed"], 1)

    def test_trusted_sender_marks_matching_request_processed(self):
        server = self._server()
        now = time.time()
        msgs = [
            _audit_message(
                f"{now-5:.6f}",
                "Alice",
                "prod",
                service="service-a",
                sender_name="Noodles Wang",
            ),
            _request_message(
                f"{now-10:.6f}",
                "UALICE",
                "Alice",
                "service-a",
                "prod",
            ),
        ]
        server.slack_client.conversations_history.side_effect = self._history(msgs)
        server.slack_client.conversations_replies.return_value = {"messages": []}

        with patch("vault_mcp.server.SLACK_AVAILABLE", True):
            result = json.loads(
                __import__("asyncio").run(
                    server.vault_get_pending_db_credential_requests()
                )
            )

        self.assertEqual(result["counts"]["pending"], 0)
        self.assertEqual(result["counts"]["already_processed"], 1)

    def test_untrusted_sender_stays_pending_for_confirmation(self):
        server = self._server()
        now = time.time()
        msgs = [
            _audit_message(
                f"{now-5:.6f}",
                "Alice",
                "prod",
                service="service-a",
                sender_name="Someone Else",
            ),
            _request_message(
                f"{now-10:.6f}",
                "UALICE",
                "Alice",
                "service-a",
                "prod",
            ),
        ]
        server.slack_client.conversations_history.side_effect = self._history(msgs)
        server.slack_client.conversations_replies.return_value = {"messages": []}

        with patch("vault_mcp.server.SLACK_AVAILABLE", True):
            result = json.loads(
                __import__("asyncio").run(
                    server.vault_get_pending_db_credential_requests()
                )
            )

        self.assertEqual(result["counts"]["pending"], 1)
        self.assertTrue(result["pending_requests"][0]["possibly_processed"])
        self.assertEqual(
            result["pending_requests"][0]["status"]["confidence"],
            "medium",
        )

    def test_stale_request_separated(self):
        server = self._server()
        now = time.time()
        msgs = [
            # 36 hours old -> stale (fresh window default 24h, lookback 2d)
            _request_message(f"{now-36*3600:.6f}", "UBOB", "Bob", "service-c", "dev"),
        ]
        server.slack_client.conversations_history.side_effect = self._history(msgs)
        server.slack_client.conversations_replies.return_value = {"messages": []}

        with patch("vault_mcp.server.SLACK_AVAILABLE", True):
            result = json.loads(
                __import__("asyncio").run(
                    server.vault_get_pending_db_credential_requests()
                )
            )

        self.assertEqual(result["counts"]["pending"], 0)
        self.assertEqual(result["counts"]["stale_pending"], 1)
        self.assertEqual(result["stale_requests"][0]["age"]["tier"], "stale")

    def test_request_older_than_two_days_is_expired(self):
        server = self._server()
        now = time.time()
        msgs = [
            _request_message(
                f"{now-3*86400:.6f}",
                "UBOB",
                "Bob",
                "service-c",
                "dev",
            ),
        ]
        server.slack_client.conversations_history.side_effect = self._history(msgs)
        server.slack_client.conversations_replies.return_value = {"messages": []}

        with patch("vault_mcp.server.SLACK_AVAILABLE", True):
            result = json.loads(
                __import__("asyncio").run(
                    server.vault_get_pending_db_credential_requests()
                )
            )

        self.assertEqual(result["counts"]["pending"], 0)
        self.assertEqual(result["counts"]["stale_pending"], 0)

    def test_mark_request_adds_processing_and_completed_reactions(self):
        server = self._server()
        request_ts = f"{time.time():.6f}"
        request = _request_message(
            request_ts,
            "UALICE",
            "Alice",
            "service-a",
            "prod",
        )
        server.slack_client.conversations_replies.return_value = {
            "messages": [request]
        }

        with patch("vault_mcp.server.SLACK_AVAILABLE", True):
            processing = json.loads(
                __import__("asyncio").run(
                    server.vault_mark_db_credential_request(
                        channel_id="C123",
                        request_ts=request_ts,
                        status="processing",
                    )
                )
            )
            completed = json.loads(
                __import__("asyncio").run(
                    server.vault_mark_db_credential_request(
                        channel_id="C123",
                        request_ts=request_ts,
                        status="completed",
                    )
                )
            )

        self.assertTrue(processing["success"])
        self.assertEqual(processing["reaction"], "eyes")
        self.assertTrue(completed["success"])
        self.assertEqual(completed["reaction"], "white_check_mark")
        self.assertEqual(
            server.slack_client.reactions_add.call_args_list,
            [
                call(
                    channel="C123",
                    timestamp=request_ts,
                    name="eyes",
                ),
                call(
                    channel="C123",
                    timestamp=request_ts,
                    name="white_check_mark",
                ),
            ],
        )
        server.slack_client.reactions_remove.assert_called_once_with(
            channel="C123",
            timestamp=request_ts,
            name="eyes",
        )

    def test_mark_request_rejects_non_request_message(self):
        server = self._server()
        request_ts = f"{time.time():.6f}"
        server.slack_client.conversations_replies.return_value = {
            "messages": [{"ts": request_ts, "text": "not a credential request"}]
        }

        with patch("vault_mcp.server.SLACK_AVAILABLE", True):
            result = json.loads(
                __import__("asyncio").run(
                    server.vault_mark_db_credential_request(
                        channel_id="C123",
                        request_ts=request_ts,
                        status="processing",
                    )
                )
            )

        self.assertFalse(result["success"])
        server.slack_client.reactions_add.assert_not_called()


if __name__ == "__main__":
    unittest.main()
