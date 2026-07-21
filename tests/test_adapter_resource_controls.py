#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import importlib.util
import json
import os
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "adapter_resource_controls",
    ROOT / "playbooks/files/governed_agentic_adapter.py",
)
assert SPEC and SPEC.loader
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


class AdapterResourceControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.saved_env = dict(os.environ)
        os.environ.update(
            {
                "AI_MODEL_URL": "https://model.example/v1/chat/completions",
                "AI_API_TOKEN": "secret",
                "AI_MODEL": "test-model",
                "AI_VALIDATE_CERTS": "false",
                "AI_TIMEOUT": "30",
                "AI_MODEL_MAX_RETRIES": "1",
                "AI_MODEL_RETRY_DELAY_SECONDS": "0.1",
            }
        )

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self.saved_env)

    def test_default_log_scope_is_small(self) -> None:
        for key in (
            "GOVERNED_AUTH_LOG_TAIL_LINES",
            "GOVERNED_ACCESS_LOG_TAIL_LINES",
            "GOVERNED_ERROR_LOG_TAIL_LINES",
            "GOVERNED_MAX_LOG_LINES",
        ):
            os.environ.pop(key, None)
        policy = adapter.build_log_policy(
            {
                "investigation": {
                    "auth_log_path": "/var/log/kernel-cve-radar/auth-events.jsonl",
                    "web_access_log_path": "/var/log/httpd/access_log",
                    "web_error_log_path": "/var/log/httpd/error_log",
                }
            }
        )
        self.assertEqual(
            policy["/var/log/kernel-cve-radar/auth-events.jsonl"]["default_tail_lines"],
            30,
        )
        self.assertEqual(policy["/var/log/httpd/access_log"]["default_tail_lines"], 60)
        self.assertEqual(policy["/var/log/httpd/error_log"]["default_tail_lines"], 30)
        self.assertTrue(all(item["max_lines"] == 60 for item in policy.values()))

    def test_evidence_is_compacted_before_model_use(self) -> None:
        os.environ["GOVERNED_TOOL_RESULT_MAX_CHARS"] = "1000"
        os.environ["GOVERNED_MAX_EVIDENCE_CHARS"] = "3000"
        evidence = [
            {"round": index, "tool": "read_log_file", "result": "x" * 5000}
            for index in range(1, 7)
        ]
        compact = adapter.compact_evidence_for_model(evidence)
        serialized = json.dumps(compact, ensure_ascii=False)
        self.assertLessEqual(len(serialized), 3000)
        self.assertIn("evidence omitted", serialized.lower())

    def test_journal_log_count_is_bounded(self) -> None:
        policy = adapter.build_log_policy(
            {
                "investigation": {
                    "auth_log_path": "/var/log/kernel-cve-radar/auth-events.jsonl",
                    "web_access_log_path": "/var/log/httpd/access_log",
                    "web_error_log_path": "/var/log/httpd/error_log",
                }
            }
        )
        schema = {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "unit": {"type": "string"},
                "lines": {"type": "integer"},
            },
        }
        allowed = {"read_log_file", "get_journal_logs", "get_service_status"}
        ok, reason, arguments, applied = adapter.govern_tool_call(
            "get_journal_logs",
            {"host": "other-host", "unit": "kernel-cve-radar", "lines": 9999},
            "testclone",
            schema,
            policy,
            allowed,
        )
        self.assertFalse(ok)
        self.assertIn("different host", reason)

        ok, reason, arguments, applied = adapter.govern_tool_call(
            "get_journal_logs",
            {"host": "testclone", "unit": "kernel-cve-radar", "lines": 9999},
            "testclone",
            schema,
            policy,
            allowed,
        )
        self.assertTrue(ok, reason)
        self.assertEqual(arguments["lines"], 60)
        self.assertTrue(applied["journal_read_only"])
        self.assertEqual(applied["max_lines"], 60)


    def test_log_path_alias_is_remapped_to_advertised_schema(self) -> None:
        policy = adapter.build_log_policy(
            {
                "investigation": {
                    "auth_log_path": "/var/log/kernel-cve-radar/auth-events.jsonl",
                    "web_access_log_path": "/var/log/httpd/access_log",
                    "web_error_log_path": "/var/log/httpd/error_log",
                }
            }
        )
        schema = {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "log_path": {"type": "string"},
                "lines": {"type": "integer"},
            },
        }
        ok, reason, arguments, applied = adapter.govern_tool_call(
            "read_log_file",
            {
                "host": "testclone",
                "path": "/var/log/kernel-cve-radar/auth-events.jsonl",
                "lines": 9999,
            },
            "testclone",
            schema,
            policy,
            {"read_log_file", "get_journal_logs", "get_service_status"},
        )
        self.assertTrue(ok, reason)
        self.assertNotIn("path", arguments)
        self.assertEqual(arguments["log_path"], "/var/log/kernel-cve-radar/auth-events.jsonl")
        self.assertEqual(arguments["lines"], 30)
        self.assertEqual(applied["applied_log_path_argument"], "log_path")


    def test_transient_transport_error_retries_once(self) -> None:
        class Response:
            status_code = 200
            text = ""
            headers = {}

            @staticmethod
            def json():
                return {
                    "choices": [
                        {"message": {"role": "assistant", "content": "{}"}}
                    ]
                }

        class Client:
            calls = 0

            def __init__(self, **_kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            async def post(self, *_args, **_kwargs):
                self.__class__.calls += 1
                if self.__class__.calls == 1:
                    request = adapter.httpx.Request("POST", "https://model.example")
                    raise adapter.httpx.RemoteProtocolError(
                        "Server disconnected without sending a response.",
                        request=request,
                    )
                return Response()

        async def no_sleep(_seconds):
            return None

        original_client = adapter.httpx.AsyncClient
        original_sleep = adapter.asyncio.sleep
        adapter.httpx.AsyncClient = Client
        adapter.asyncio.sleep = no_sleep
        try:
            message = asyncio.run(
                adapter.call_model(
                    [{"role": "user", "content": "test"}],
                    trace_stage="model_final",
                )
            )
        finally:
            adapter.httpx.AsyncClient = original_client
            adapter.asyncio.sleep = original_sleep
        self.assertEqual(Client.calls, 2)
        self.assertEqual(message["content"], "{}")

    def test_auth_error_is_not_retried(self) -> None:
        class Response:
            status_code = 401
            text = '{"error":"unauthorized"}'
            headers = {}

            @staticmethod
            def json():
                return {"error": "unauthorized"}

        class Client:
            calls = 0

            def __init__(self, **_kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            async def post(self, *_args, **_kwargs):
                self.__class__.calls += 1
                return Response()

        original_client = adapter.httpx.AsyncClient
        adapter.httpx.AsyncClient = Client
        try:
            with self.assertRaises(adapter.ModelInvocationError) as raised:
                asyncio.run(
                    adapter.call_model(
                        [{"role": "user", "content": "test"}],
                        trace_stage="model_plan",
                    )
                )
        finally:
            adapter.httpx.AsyncClient = original_client
        self.assertEqual(Client.calls, 1)
        self.assertEqual(raised.exception.category, "auth_error")
        self.assertEqual(raised.exception.status_code, 401)

    def test_nested_model_error_is_detected_inside_task_group(self) -> None:
        model_error = adapter.ModelInvocationError(
            "temporary disconnect",
            stage="model_final",
            category="transport_error",
        )
        grouped = ExceptionGroup("task group", [model_error])
        found = adapter.find_nested_exception(grouped, adapter.ModelInvocationError)
        self.assertIs(found, model_error)


if __name__ == "__main__":
    unittest.main(verbosity=2)
