"""Safely publish simulated CAEP security events to ZeroPulse Redis.

This program only sends JSON messages to Redis Pub/Sub.  It does not inspect
or change firewall settings, credentials, tokens, or network configuration.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import time
import uuid
from typing import Any, Dict, Optional, Sequence

try:
    import redis
except ImportError:  # Keeps --help and --dry-run useful before installation.
    redis = None


REDIS_CHANNEL = "caep:security_events"
CAEP_EVENT_TYPE_PREFIX = "https://schemas.openid.net/secevent/caep/event-type/"
SIMULATED_EVENTS = (
    "FIREWALL_DISABLED",
    "IMPOSSIBLE_TRAVEL",
    "VPN_DETECTED",
    "TOKEN_HIJACKED",
)


def parse_ip(value: str) -> str:
    """Reject malformed addresses while allowing a caller-provided test IP."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        raise argparse.ArgumentTypeError("--ip must be a valid IPv4 or IPv6 address") from error


def build_event(
    event_name: str,
    session_jti: str,
    ip_address: str,
    user_id: str = "simulated-user",
    platform: str = "simulator",
) -> Dict[str, Any]:
    """Build the exact envelope consumed by caepEventParser.js.

    `event_data.type` is deliberately the supplied simulation event name: it
    is the field used by the existing risk engine.  The URI is the same
    OpenID CAEP-style event_type convention used by the Node endpoint agent.
    """
    if event_name not in SIMULATED_EVENTS:
        raise ValueError("Unsupported simulated event: {}".format(event_name))
    if not session_jti:
        raise ValueError("A target session JTI is required")

    event_data: Dict[str, Any] = {
        "type": event_name,
        "source": "ZeroPulse-ThreatSimulator",
        "platform": platform,
        "ip_address": ip_address,
        "simulated": True,
    }

    if event_name == "FIREWALL_DISABLED":
        # This is descriptive test data only; it does not touch a firewall.
        event_data.update({"profile": "Public", "from": "ON", "to": "OFF"})
    elif event_name == "IMPOSSIBLE_TRAVEL":
        event_data.update({"previous_ip": "198.51.100.20", "current_ip": ip_address})
    elif event_name == "VPN_DETECTED":
        event_data.update({"vpn_detected": True})
    elif event_name == "TOKEN_HIJACKED":
        event_data.update({"token_compromised": True})

    return {
        "specversion": "1.0",
        "event_type": CAEP_EVENT_TYPE_PREFIX + event_name,
        "jti": "evt_{}_{}".format(int(time.time() * 1000), uuid.uuid4().hex[:8]),
        "event_timestamp": int(time.time()),
        "subject": {
            "format": "complex",
            "user": user_id,
            "session": session_jti,
            "jti": session_jti,
        },
        "event_data": event_data,
    }


def publish_event(event: Dict[str, Any], host: str, port: int) -> int:
    """Publish one serialized event and return the number of subscribers."""
    if redis is None:
        raise RuntimeError(
            "The Python Redis package is not installed. Run: pip install -r backend/simulator/requirements.txt"
        )

    client = redis.Redis(
        host=host,
        port=port,
        decode_responses=True,
        socket_connect_timeout=3,
        socket_timeout=3,
    )
    try:
        client.ping()
        return int(client.publish(REDIS_CHANNEL, json.dumps(event)))
    finally:
        client.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safely publish a simulated ZeroPulse CAEP security event."
    )
    parser.add_argument("--event", required=True, choices=SIMULATED_EVENTS)
    parser.add_argument("--jti", "--session", dest="jti", required=True,
                        help="Target authenticated session JWT ID (JTI).")
    parser.add_argument("--ip", type=parse_ip, default="203.0.113.10",
                        help="Simulated source IP (default: documentation address 203.0.113.10).")
    parser.add_argument("--user-id", default="simulated-user",
                        help="Optional simulated subject user identifier; never a credential.")
    parser.add_argument("--platform", default="simulator",
                        help="Label included in event_data.platform (default: simulator).")
    parser.add_argument("--redis-host", default=os.getenv("REDIS_HOST", "localhost"))
    parser.add_argument("--redis-port", type=int, default=int(os.getenv("REDIS_PORT", "6379")))
    parser.add_argument("--dry-run", action="store_true",
                        help="Print valid JSON without connecting to Redis.")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    event = build_event(args.event, args.jti, args.ip, args.user_id, args.platform)

    if args.dry_run:
        print(json.dumps(event, indent=2, sort_keys=True))
        return 0

    try:
        subscribers = publish_event(event, args.redis_host, args.redis_port)
    except Exception as error:
        print("Failed to publish simulated CAEP event: {}".format(error), file=sys.stderr)
        return 1

    print(
        "Published {} for session {} to {} ({} subscriber(s) received it).".format(
            args.event, args.jti, REDIS_CHANNEL, subscribers
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
