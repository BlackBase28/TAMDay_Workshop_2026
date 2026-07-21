#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from unittest.mock import patch
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "playbooks" / "roles" / "cve_radar_eda_forwarder" / "files" / "cve_radar_event_forwarder.py"
spec = importlib.util.spec_from_file_location("forwarder", SCRIPT)
assert spec and spec.loader
forwarder = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = forwarder
spec.loader.exec_module(forwarder)


class NormalizationTests(unittest.TestCase):
    def normalize(self, value: dict, source_file: str = "/var/log/kernel-cve-radar/auth-events.jsonl") -> dict:
        event = forwarder.normalize_line(
            json.dumps(value), sequence=1, hostname="testclone.example", source_file=source_file
        )
        self.assertIsNotNone(event)
        return event

    def test_admin_access_compact_format(self) -> None:
        event = self.normalize({
            "ts": "2026-07-11T14:18:47Z", "event": "admin_access",
            "user": "user1", "role": "user", "ip": "192.168.1.104",
            "path": "/admin", "result": "allowed",
        })
        self.assertEqual(event["event_key"], forwarder.ADMIN_ACCESS_KEY)
        self.assertEqual(event["username"], "user1")
        self.assertEqual(event["user_role"], "user")
        self.assertEqual(event["event_outcome"], "allowed")

    def test_admin_login_success_has_dedicated_wakeup_key(self) -> None:
        failed = self.normalize({
            "timestamp": "2026-07-18T10:00:00Z", "event": "login_failure",
            "user": "admin", "source_ip": "192.168.1.104", "path": "/login",
            "outcome": "failed", "status": 401,
        })
        success = self.normalize({
            "timestamp": "2026-07-18T10:00:30Z", "event": "login_success",
            "user": "admin", "role": "admin", "source_ip": "192.168.1.104",
            "path": "/login", "outcome": "success", "status": 200,
        })
        self.assertEqual(failed["event_key"], forwarder.LOGIN_FAILURE_KEY)
        self.assertEqual(failed["event_outcome"], "failure")
        self.assertEqual(success["event_key"], forwarder.ADMIN_LOGIN_SUCCESS_KEY)
        self.assertEqual(success["event_outcome"], "success")
        self.assertNotIn("failure_count", success)

    def test_non_admin_login_success_does_not_use_admin_wakeup_key(self) -> None:
        event = self.normalize({
            "timestamp": "2026-07-18T10:00:30Z", "event": "login_success",
            "user": "user1", "role": "user", "source_ip": "192.168.1.104",
            "path": "/login", "outcome": "success", "status": 200,
        })
        self.assertEqual(event["event_key"], forwarder.LOGIN_SUCCESS_KEY)

    def test_apache_combined_access(self) -> None:
        line = '203.0.113.99 - - [11/Jul/2026:14:30:00 +0000] "GET /login HTTP/1.1" 200 123 "-" "curl/8.0"'
        event = forwarder.normalize_line(
            line, sequence=7, hostname="testclone.example", source_file="/var/log/httpd/access_log"
        )
        self.assertIsNotNone(event)
        self.assertEqual(event["event_key"], forwarder.HTTP_ACCESS_KEY)
        self.assertEqual(event["effective_source_ip"], "203.0.113.99")
        self.assertEqual(event["url_path"], "/login")
        self.assertEqual(event["status_code"], 200)

    def test_json_http_access(self) -> None:
        event = self.normalize({
            "event_type": "http", "event_action": "access", "ip": "203.0.113.99",
            "method": "GET", "path": "/", "status": 200,
        }, "/var/log/kernel-cve-radar/access.log")
        self.assertEqual(event["event_key"], forwarder.HTTP_ACCESS_KEY)

    def test_trusted_proxy_forwarded_for(self) -> None:
        with patch.dict(os.environ, {"TRUSTED_PROXY_NETWORKS": "10.88.0.0/16"}, clear=False):
            event = self.normalize({
                "event": "admin_access", "user": "user1", "role": "user",
                "connection_ip": "10.88.0.1", "source_ip": "10.88.0.1",
                "forwarded_for": "192.168.1.104", "path": "/admin", "result": "allowed",
            })
        self.assertEqual(event["effective_source_ip"], "192.168.1.104")

    def test_static_asset_http_access_is_ignored(self) -> None:
        line = '203.0.113.99 - - [11/Jul/2026:14:30:00 +0000] "GET /static/app.js HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
        event = forwarder.normalize_line(
            line, sequence=8, hostname="testclone.example", source_file="/var/log/httpd/access_log"
        )
        self.assertIsNone(event)

    def test_default_forwarder_scope_is_auth_log_only(self) -> None:
        with patch.dict(os.environ, {
            "EDA_EVENT_STREAM_URL": "http://127.0.0.1:9/events",
            "AUTH_EVENT_LOGS": "/tmp/auth-events.jsonl",
            "HTTP_ACCESS_LOGS": "/tmp/access.log",
            "FORWARD_HTTP_ACCESS_EVENTS": "false",
        }, clear=False):
            instance = forwarder.Forwarder()
        self.assertEqual(list(instance.state.cursors), ["/tmp/auth-events.jsonl"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
