"""Lightweight tests for the safe Redis-only threat simulator."""

import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import trigger  # noqa: E402


class TriggerTests(unittest.TestCase):
    def test_build_event_has_parser_and_enforcement_fields(self):
        event = trigger.build_event("FIREWALL_DISABLED", "session-jti-123", "203.0.113.10")

        self.assertEqual(event["specversion"], "1.0")
        self.assertEqual(
            event["event_type"],
            "https://schemas.openid.net/secevent/caep/event-type/FIREWALL_DISABLED",
        )
        self.assertEqual(event["subject"]["jti"], "session-jti-123")
        self.assertEqual(event["subject"]["session"], "session-jti-123")
        self.assertEqual(event["event_data"]["type"], "FIREWALL_DISABLED")
        self.assertTrue(event["event_data"]["simulated"])

    def test_publish_serializes_valid_json_to_expected_channel(self):
        client = Mock()
        client.publish.return_value = 1
        original_redis = trigger.redis
        trigger.redis = types.SimpleNamespace(Redis=Mock(return_value=client))
        try:
            event = trigger.build_event("TOKEN_HIJACKED", "session-jti-456", "203.0.113.10")
            subscribers = trigger.publish_event(event, "localhost", 6379)
        finally:
            trigger.redis = original_redis

        self.assertEqual(subscribers, 1)
        client.ping.assert_called_once_with()
        channel, payload = client.publish.call_args[0]
        self.assertEqual(channel, trigger.REDIS_CHANNEL)
        self.assertEqual(json.loads(payload)["subject"]["jti"], "session-jti-456")
        client.close.assert_called_once_with()

    def test_dry_run_starts_without_redis_connection(self):
        self.assertEqual(
            trigger.main([
                "--event", "VPN_DETECTED",
                "--jti", "session-jti-789",
                "--dry-run",
            ]),
            0,
        )

    def test_all_supported_event_types_build(self):
        for event_name in trigger.SIMULATED_EVENTS:
            with self.subTest(event_name=event_name):
                event = trigger.build_event(event_name, "session-jti", "203.0.113.10")
                self.assertEqual(event["event_data"]["type"], event_name)

    def test_build_event_requires_a_target_jti(self):
        with self.assertRaises(ValueError):
            trigger.build_event("TOKEN_HIJACKED", "", "203.0.113.10")


if __name__ == "__main__":
    unittest.main()
