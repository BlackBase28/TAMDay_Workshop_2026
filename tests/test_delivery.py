#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "playbooks" / "roles" / "cve_radar_eda_forwarder" / "files" / "cve_radar_event_forwarder.py"
spec = importlib.util.spec_from_file_location("forwarder_delivery", SCRIPT)
assert spec and spec.loader
forwarder = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = forwarder
spec.loader.exec_module(forwarder)


class CollectorHandler(BaseHTTPRequestHandler):
    events: list[dict] = []
    auth_headers: list[str | None] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        self.__class__.events.append(json.loads(self.rfile.read(length)))
        self.__class__.auth_headers.append(self.headers.get("X-CVE-Radar-Token"))
        self.send_response(202)
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:
        return


class DeliveryTests(unittest.TestCase):
    def test_failures_are_retained_but_every_admin_success_is_delivered(self) -> None:
        CollectorHandler.events = []
        CollectorHandler.auth_headers = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), CollectorHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                auth = root / "auth-events.jsonl"
                state = root / "state.json"
                records = [
                    {"timestamp": "2026-07-18T10:00:00Z", "event": "admin_access", "user": "user1", "role": "user", "source_ip": "192.168.1.104", "path": "/admin", "result": "allowed"},
                    {"timestamp": "2026-07-18T10:01:00Z", "event": "login_failure", "user": "admin", "source_ip": "192.168.1.104", "path": "/login", "outcome": "failed", "status": 401},
                    {"timestamp": "2026-07-18T10:01:10Z", "event": "login_failure", "user": "admin", "source_ip": "192.168.1.104", "path": "/login", "outcome": "failed", "status": 401},
                    {"timestamp": "2026-07-18T10:01:20Z", "event": "login_failure", "user": "admin", "source_ip": "192.168.1.104", "path": "/login", "outcome": "failed", "status": 401},
                    {"timestamp": "2026-07-18T10:01:30Z", "event": "login_success", "user": "admin", "role": "admin", "source_ip": "192.168.1.104", "path": "/login", "outcome": "success", "status": 200, "request_id": "success-1"},
                    {"timestamp": "2026-07-18T10:02:30Z", "event": "login_success", "user": "admin", "role": "admin", "source_ip": "192.168.1.104", "path": "/login", "outcome": "success", "status": 200, "request_id": "success-2"},
                    {"timestamp": "2026-07-18T10:03:00Z", "event": "login_success", "user": "user1", "role": "user", "source_ip": "192.168.1.104", "path": "/login", "outcome": "success", "status": 200},
                ]
                auth.write_text("\n".join(json.dumps(item) for item in records) + "\n", encoding="utf-8")
                settings = {
                    "EDA_EVENT_STREAM_URL": f"http://127.0.0.1:{server.server_port}/events",
                    "EDA_EVENT_STREAM_TOKEN": "test-token",
                    "AUTH_EVENT_LOGS": str(auth),
                    "FORWARD_HTTP_ACCESS_EVENTS": "false",
                    "FORWARDER_STATE_FILE": str(state),
                    "FORWARDER_START_AT_END": "false",
                    "FORWARDER_LOG_LEVEL": "ERROR",
                }
                old = {key: os.environ.get(key) for key in settings}
                os.environ.update(settings)
                try:
                    instance = forwarder.Forwarder()
                    for cursor in instance.state.cursors.values():
                        instance.process_path(cursor)
                finally:
                    for key, value in old.items():
                        if value is None:
                            os.environ.pop(key, None)
                        else:
                            os.environ[key] = value

                keys = [event["event_key"] for event in CollectorHandler.events]
                self.assertEqual(keys, [
                    forwarder.ADMIN_ACCESS_KEY,
                    forwarder.ADMIN_LOGIN_SUCCESS_KEY,
                    forwarder.ADMIN_LOGIN_SUCCESS_KEY,
                ])
                self.assertTrue(all("failure_count" not in event for event in CollectorHandler.events[1:]))
                self.assertTrue(state.exists())
                self.assertEqual(CollectorHandler.auth_headers, ["test-token"] * 3)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
