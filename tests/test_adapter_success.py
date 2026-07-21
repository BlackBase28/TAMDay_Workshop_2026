#!/usr/bin/env python3
from contextlib import asynccontextmanager
import asyncio
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("adapter", ROOT / "playbooks/files/governed_agentic_adapter.py")
assert SPEC and SPEC.loader
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


class AdapterSuccessTests(unittest.TestCase):
    def test_governed_admin_success_path(self) -> None:
        os.environ.update({
            "AI_MODEL_URL": "https://model.example/v1/chat/completions",
            "AI_API_TOKEN": "model-secret",
            "AI_MODEL": "test-model",
            "AI_VALIDATE_CERTS": "false",
            "RHEL_MCP_URL": "https://mcp.example/mcp",
            "RHEL_MCP_TOKEN": "mcp-secret",
            "GOVERNED_MAX_INVESTIGATION_ROUNDS": "1",
            "GOVERNED_MAX_TOOL_CALLS_PER_ROUND": "2",
            "GOVERNED_MAX_TOTAL_TOOL_CALLS": "2",
        })

        class Response:
            status_code = 200
            text = ""
            def __init__(self, content: dict) -> None:
                self.content = content
            def json(self) -> dict:
                return {"choices": [{"message": {"role": "assistant", "content": json.dumps(self.content)}}]}

        class HTTPClient:
            calls = 0
            def __init__(self, **_kwargs) -> None: pass
            async def __aenter__(self): return self
            async def __aexit__(self, *_args): return False
            async def post(self, _url, headers=None, json=None):
                self.__class__.calls += 1
                self.assert_headers(headers)
                if self.__class__.calls == 1:
                    return Response({"tool_calls": [{"tool": "read_log_file", "arguments": {"host": "testclone", "path": "/var/log/kernel-cve-radar/auth-events.jsonl", "lines": 9999}}]})
                return Response({
                    "assessment": "highly_suspicious", "confidence": 0.95,
                    "incident_type": "broken_access_control", "severity": "high",
                    "recommended_next_step": "repair_web_code", "reason": "Confirmed.",
                    "affected_user": "user1", "source_ips": ["192.0.2.10"],
                    "evidence_summary": ["user1 accessed /admin"], "evidence_gaps": [],
                    "additional_evidence_requests": [], "evidence": {"confirmed": True},
                })
            @staticmethod
            def assert_headers(headers):
                assert headers["Authorization"] == "Bearer model-secret"

        class Session:
            def __init__(self, *_args): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *_args): return False
            async def initialize(self): return None
            async def list_tools(self):
                return SimpleNamespace(tools=[SimpleNamespace(name="read_log_file", description="read", inputSchema={"type": "object", "properties": {"host": {"type": "string"}, "path": {"type": "string"}, "lines": {"type": "integer"}}})])
            async def call_tool(self, name, arguments):
                assert name == "read_log_file"
                assert arguments["host"] == "testclone"
                assert arguments["lines"] == 30
                return SimpleNamespace(structuredContent={"records": [{"user": "user1", "role": "user", "path": "/admin", "result": "allowed"}]}, content=[])

        @asynccontextmanager
        async def stream(_url, headers=None, **_kwargs):
            assert headers["Authorization"] == "Bearer mcp-secret"
            yield object(), object(), lambda: "session"

        originals = adapter.httpx.AsyncClient, adapter.ClientSession, adapter.streamablehttp_client
        adapter.httpx.AsyncClient, adapter.ClientSession, adapter.streamablehttp_client = HTTPClient, Session, stream
        request = {
            "trigger_event": {"event_key": "kernel-cve-radar.authorization.admin.access", "username": "user1", "user_role": "user", "http_path": "/admin", "event_outcome": "allowed", "effective_source_ip": "192.0.2.10"},
            "investigation": {"target_host": "testclone", "auth_log_path": "/var/log/kernel-cve-radar/auth-events.jsonl", "web_access_log_path": "/var/log/httpd/access_log", "web_error_log_path": "/var/log/httpd/error_log"},
        }
        try:
            result = asyncio.run(adapter.run_governed_investigation(request))
        finally:
            adapter.httpx.AsyncClient, adapter.ClientSession, adapter.streamablehttp_client = originals

        self.assertEqual(result["recommended_next_step"], "repair_web_code")
        self.assertEqual(result["incident_type"], "broken_access_control")
        self.assertEqual(result["investigation_status"], "action_proposed")
        self.assertEqual(result["total_mcp_tool_calls"], 1)
        self.assertEqual(HTTPClient.calls, 2)


    def test_admin_login_uses_model_planner_with_governed_tool_allowlist(self) -> None:
        saved_env = dict(os.environ)
        os.environ.update({
            "AI_MODEL_URL": "https://model.example/v1/chat/completions",
            "AI_API_TOKEN": "model-secret",
            "AI_MODEL": "test-model",
            "AI_VALIDATE_CERTS": "false",
            "RHEL_MCP_URL": "https://mcp.example/mcp",
            "RHEL_MCP_TOKEN": "mcp-secret",
            "GOVERNED_ALLOWED_MCP_TOOLS": "read_log_file,get_journal_logs,get_service_status",
            "GOVERNED_MAX_INVESTIGATION_ROUNDS": "1",
            "GOVERNED_MAX_TOOL_CALLS_PER_ROUND": "3",
            "GOVERNED_MAX_TOTAL_TOOL_CALLS": "3",
        })

        class Response:
            status_code = 200
            text = ""
            def __init__(self, content: dict) -> None:
                self.content = content
            def json(self) -> dict:
                return {"choices": [{"message": {"role": "assistant", "content": json.dumps(self.content, ensure_ascii=False)}}]}

        class HTTPClient:
            calls = 0
            planner_tools = []
            def __init__(self, **_kwargs) -> None: pass
            async def __aenter__(self): return self
            async def __aexit__(self, *_args): return False
            async def post(self, _url, headers=None, json=None):
                self.__class__.calls += 1
                assert headers["Authorization"] == "Bearer model-secret"
                if self.__class__.calls == 1:
                    user_payload = __import__("json").loads(json["messages"][1]["content"])
                    self.__class__.planner_tools = [item["name"] for item in user_payload["available_tools"]]
                    # The Model may choose supplementary service evidence. The
                    # Adapter must add the mandatory Auth Log read in front.
                    return Response({"tool_calls": [{
                        "tool": "get_service_status",
                        "arguments": {"host": "testclone", "service": "kernel-cve-radar"},
                    }]})
                return Response({
                    "assessment": "suspicious",
                    "confidence": 0.8,
                    "incident_type": "suspicious_login_success",
                    "severity": "medium",
                    "recommended_next_step": "require_approval",
                    "reason": "最近五分鐘有三次登入失敗。",
                    "affected_user": "admin",
                    "source_ips": ["192.168.1.104"],
                    "evidence_summary": ["three failures"],
                    "evidence_gaps": [],
                    "additional_evidence_requests": [],
                    "evidence": {"recent_admin_login_failure_count": 3},
                })

        class Session:
            calls = []
            def __init__(self, *_args): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *_args): return False
            async def initialize(self): return None
            async def list_tools(self):
                def tool(name, properties):
                    return SimpleNamespace(
                        name=name,
                        description=name,
                        inputSchema={"type": "object", "properties": properties},
                    )
                return SimpleNamespace(tools=[
                    tool("read_log_file", {
                        "host": {"type": "string"},
                        "path": {"type": "string"},
                        "lines": {"type": "integer"},
                    }),
                    tool("get_journal_logs", {
                        "host": {"type": "string"},
                        "unit": {"type": "string"},
                        "lines": {"type": "integer"},
                    }),
                    tool("get_service_status", {
                        "host": {"type": "string"},
                        "service": {"type": "string"},
                    }),
                    tool("get_system_resources", {"host": {"type": "string"}}),
                ])
            async def call_tool(self, name, arguments):
                self.__class__.calls.append((name, dict(arguments)))
                if name == "read_log_file":
                    assert arguments["host"] == "testclone"
                    assert arguments["path"] == "/var/log/kernel-cve-radar/auth-events.jsonl"
                    assert arguments["lines"] == 30
                    return SimpleNamespace(structuredContent={"records": [
                        {"timestamp": "2026-07-18T10:01:00Z", "event": "login_failure", "user": "admin", "path": "/login", "status": 401},
                        {"timestamp": "2026-07-18T10:02:00Z", "event": "login_failure", "user": "admin", "path": "/login", "status": 401},
                        {"timestamp": "2026-07-18T10:04:00Z", "event": "login_failure", "user": "admin", "path": "/login", "status": 401},
                    ]}, content=[])
                assert name == "get_service_status"
                assert arguments["host"] == "testclone"
                return SimpleNamespace(structuredContent={"service": "kernel-cve-radar", "active": True}, content=[])

        @asynccontextmanager
        async def stream(_url, headers=None, **_kwargs):
            assert headers["Authorization"] == "Bearer mcp-secret"
            yield object(), object(), lambda: "session"

        originals = adapter.httpx.AsyncClient, adapter.ClientSession, adapter.streamablehttp_client
        adapter.httpx.AsyncClient, adapter.ClientSession, adapter.streamablehttp_client = HTTPClient, Session, stream
        request = {
            "trigger_event": {
                "event_key": "kernel-cve-radar.authentication.admin.login.success",
                "event_outcome": "success",
                "username": "admin",
                "user_role": "admin",
                "timestamp": "2026-07-18T10:05:00Z",
            },
            "detection_context": {"scenario": "admin_login_success", "detection_threshold": 3},
            "investigation": {
                "target_host": "testclone",
                "lookback_minutes": 5,
                "auth_log_path": "/var/log/kernel-cve-radar/auth-events.jsonl",
                "web_access_log_path": "/var/log/httpd/access_log",
                "web_error_log_path": "/var/log/httpd/error_log",
            },
        }
        try:
            result = asyncio.run(adapter.run_governed_investigation(request))
        finally:
            adapter.httpx.AsyncClient, adapter.ClientSession, adapter.streamablehttp_client = originals
            os.environ.clear()
            os.environ.update(saved_env)

        self.assertEqual(HTTPClient.calls, 2)
        self.assertEqual(
            HTTPClient.planner_tools,
            ["read_log_file", "get_journal_logs", "get_service_status"],
        )
        self.assertEqual([name for name, _args in Session.calls], ["read_log_file", "get_service_status"])
        self.assertNotIn("get_system_resources", HTTPClient.planner_tools)
        self.assertEqual(result["recommended_next_step"], "require_approval")
        self.assertEqual(result["evidence"]["recent_admin_login_check"]["failure_count"], 3)
        self.assertEqual(result["total_mcp_tool_calls"], 2)


    def test_admin_login_with_three_recent_failures_requires_review(self) -> None:
        request = {
            "trigger_event": {
                "event_key": "kernel-cve-radar.authentication.admin.login.success",
                "event_outcome": "success",
                "username": "admin",
                "user_role": "admin",
                "effective_source_ip": "192.168.1.104",
                "timestamp": "2026-07-18T10:05:00Z",
            },
            "detection_context": {"scenario": "admin_login_success", "detection_threshold": 3},
            "investigation": {
                "lookback_minutes": 5,
                "auth_log_path": "/var/log/kernel-cve-radar/auth-events.jsonl",
            },
        }
        records = [
            {"timestamp": "2026-07-18T10:01:00Z", "event": "login_failure", "user": "admin", "source_ip": "192.168.1.104", "status": 401},
            {"timestamp": "2026-07-18T10:02:00Z", "event": "login_failure", "user": "admin", "source_ip": "192.168.1.104", "status": 401},
            {"timestamp": "2026-07-18T10:04:00Z", "event": "login_failure", "user": "admin", "source_ip": "198.51.100.8", "status": 401},
            {"timestamp": "2026-07-18T09:50:00Z", "event": "login_failure", "user": "admin", "source_ip": "192.168.1.104", "status": 401},
        ]
        evidence = [{
            "round": 1,
            "tool": "read_log_file",
            "arguments": {"host": "testclone", "path": "/var/log/kernel-cve-radar/auth-events.jsonl", "lines": 30},
            "result": json.dumps({"records": records}),
        }]
        normalized = adapter.normalize_envelope(
            {
                "assessment": "likely_user_error",
                "confidence": 0.55,
                "incident_type": "user_error",
                "severity": "low",
                "recommended_next_step": "observe",
                "reason": "模型初步判斷。",
                "affected_user": "admin",
                "source_ips": [],
                "evidence_summary": [],
                "evidence_gaps": [],
                "additional_evidence_requests": [],
                "evidence": {"recent_admin_login_failure_count": 3},
            },
            ["read_log_file"],
            request=request,
            mcp_evidence=evidence,
        )
        self.assertEqual(normalized["incident_type"], "suspicious_login_success")
        self.assertEqual(normalized["recommended_next_step"], "require_approval")
        self.assertGreaterEqual(normalized["confidence"], 0.75)
        self.assertEqual(normalized["evidence"]["recent_admin_login_check"]["failure_count"], 3)
        self.assertIn("admin_login_recent_failures_requires_human_review", normalized["governance_policy_applied"])

    def test_admin_login_below_threshold_is_observed(self) -> None:
        request = {
            "trigger_event": {
                "event_key": "kernel-cve-radar.authentication.admin.login.success",
                "event_outcome": "success",
                "username": "admin",
                "user_role": "admin",
                "timestamp": "2026-07-18T10:05:00Z",
            },
            "detection_context": {"scenario": "admin_login_success", "detection_threshold": 3},
            "investigation": {
                "lookback_minutes": 5,
                "auth_log_path": "/var/log/kernel-cve-radar/auth-events.jsonl",
            },
        }
        evidence = [{
            "round": 1,
            "tool": "read_log_file",
            "arguments": {"path": "/var/log/kernel-cve-radar/auth-events.jsonl"},
            "result": json.dumps({"records": [
                {"timestamp": "2026-07-18T10:04:00Z", "event": "login_failure", "user": "admin", "status": 401}
            ]}),
        }]
        normalized = adapter.normalize_envelope(
            {
                "assessment": "suspicious",
                "confidence": 0.8,
                "incident_type": "suspicious_login_success",
                "severity": "medium",
                "recommended_next_step": "require_approval",
                "reason": "模型初步判斷。",
                "evidence": {"recent_admin_login_failure_count": 1},
            },
            ["read_log_file"],
            request=request,
            mcp_evidence=evidence,
        )
        self.assertEqual(normalized["assessment"], "likely_user_error")
        self.assertEqual(normalized["incident_type"], "user_error")
        self.assertEqual(normalized["recommended_next_step"], "observe")
        self.assertIn("admin_login_below_failure_threshold_observe", normalized["governance_policy_applied"])


    def test_text_wrapped_auth_log_overrides_conflicting_model_summary(self) -> None:
        request = {
            "trigger_event": {
                "event_key": "kernel-cve-radar.authentication.admin.login.success",
                "event_outcome": "success",
                "username": "admin",
                "user_role": "admin",
                "effective_source_ip": "192.168.1.104",
                "timestamp": "2026-07-19T13:32:29Z",
            },
            "detection_context": {"scenario": "admin_login_success", "detection_threshold": 3},
            "investigation": {
                "lookback_minutes": 5,
                "auth_log_path": "/var/log/kernel-cve-radar/auth-events.jsonl",
            },
        }
        entries = [
            '{"ts":"2026-07-19T13:32:09Z","outcome":"fail","user":"admin","ip":"192.168.1.104","path":"/login","reason":"bad_password"}',
            '{"ts":"2026-07-19T13:32:13Z","outcome":"fail","user":"admin","ip":"192.168.1.104","path":"/login","reason":"bad_password"}',
            '{"ts":"2026-07-19T13:32:18Z","outcome":"fail","user":"admin","ip":"192.168.1.104","path":"/login","reason":"bad_password"}',
        ]
        wrapped_result = "MCP tool result:\n" + json.dumps(
            {
                "entries": entries,
                "path": "/var/log/kernel-cve-radar/auth-events.jsonl",
                "lines_count": 3,
            },
            ensure_ascii=False,
        )
        normalized = adapter.normalize_envelope(
            {
                "assessment": "likely_user_error",
                "confidence": 0.60,
                "incident_type": "user_error",
                "severity": "low",
                "recommended_next_step": "observe",
                "reason": "模型摘要與計數不一致。",
                "affected_user": "admin",
                "source_ips": ["192.168.1.104"],
                "evidence_summary": [
                    "admin 登入成功前 5 分鐘內只找到 0 次登入失敗，未達 3 次門檻。",
                    "前三次登入失敗時間: 2026-07-19T13:32:09Z, 13:32:13Z, 13:32:18Z",
                ],
                "evidence": {"recent_admin_login_failure_count": 0},
            },
            ["read_log_file"],
            request=request,
            mcp_evidence=[{
                "round": 1,
                "tool": "read_log_file",
                "arguments": {
                    "host": "testclone",
                    "log_path": "/var/log/kernel-cve-radar/auth-events.jsonl",
                    "lines": 30,
                },
                "result": wrapped_result,
            }],
        )
        self.assertEqual(normalized["recommended_next_step"], "require_approval")
        self.assertEqual(normalized["evidence"]["recent_admin_login_check"]["failure_count"], 3)
        self.assertEqual(len(normalized["evidence"]["recent_admin_login_check"]["failures"]), 3)
        self.assertIn("找到 3 次登入失敗", normalized["evidence_summary"][0])
        self.assertFalse(any("只找到 0 次" in item for item in normalized["evidence_summary"]))
        self.assertTrue(any(item.startswith("登入失敗時間: 2026-07-19T13:32:09Z") for item in normalized["evidence_summary"]))
        self.assertIn("失敗原因: bad_password", normalized["evidence_summary"])
        self.assertIn("登入來源 IP: 192.168.1.104", normalized["evidence_summary"])
        self.assertIn(
            "adapter_auth_log_count_overrides_model_count",
            normalized["governance_policy_applied"],
        )


    def test_native_mcp_records_are_extracted_before_serialization_truncation(self) -> None:
        request = {
            "trigger_event": {
                "event_key": "kernel-cve-radar.authentication.admin.login.success",
                "event_outcome": "success",
                "username": "admin",
                "user_role": "admin",
                "effective_source_ip": "192.168.1.104",
                "timestamp": "2026-07-19T14:14:14Z",
            },
            "detection_context": {"scenario": "admin_login_success", "detection_threshold": 3},
            "investigation": {
                "lookback_minutes": 5,
                "auth_log_path": "/var/log/kernel-cve-radar/auth-events.jsonl",
            },
        }
        entries = [
            '{"ts":"2026-07-19T14:13:50Z","outcome":"fail","user":"admin","ip":"192.168.1.104","path":"/login","reason":"bad_password"}',
            '{"ts":"2026-07-19T14:13:55Z","outcome":"fail","user":"admin","ip":"192.168.1.104","path":"/login","reason":"bad_password"}',
            '{"ts":"2026-07-19T14:14:01Z","outcome":"fail","user":"admin","ip":"192.168.1.104","path":"/login","reason":"bad_password"}',
            '{"ts":"2026-07-19T14:14:14Z","event":"login_success","outcome":"success","user":"admin","ip":"192.168.1.104","path":"/login"}',
        ]
        result = SimpleNamespace(
            structuredContent={"noise": "x" * 6000, "entries": entries},
            content=[],
        )
        serialized = adapter.serialize_tool_result(result, 4000)
        self.assertIn("earlier tool output omitted", serialized)
        self.assertIn('\\"ts\\"', serialized)
        parsed_records = adapter.extract_log_records_from_tool_result(result)
        self.assertGreaterEqual(len(parsed_records), 4)

        normalized = adapter.normalize_envelope(
            {
                "assessment": "suspicious",
                "incident_type": "authentication_failure",
                "confidence": 0.95,
                "severity": "medium",
                "recommended_next_step": "require_approval",
                "reason": "模型從截斷後的顯示文字看見三次失敗。",
                "affected_user": "admin",
                "source_ips": ["192.168.1.104"],
                "evidence_summary": [
                    "2026-07-19T14:13:50Z: admin登入失敗 (bad_password)",
                    "2026-07-19T14:13:55Z: admin登入失敗 (bad_password)",
                    "2026-07-19T14:14:01Z: admin登入失敗 (bad_password)",
                    "2026-07-19T14:14:14Z: admin登入成功",
                ],
            },
            ["read_log_file"],
            request=request,
            mcp_evidence=[{
                "round": 1,
                "tool": "read_log_file",
                "arguments": {"log_path": "/var/log/kernel-cve-radar/auth-events.jsonl"},
                "result": serialized,
                "parsed_log_records": parsed_records,
                "log_record_parse_status": "parsed",
            }],
        )
        check = normalized["evidence"]["recent_admin_login_check"]
        self.assertEqual(check["failure_count"], 3)
        self.assertEqual(check["count_source"], "adapter_mcp_evidence")
        self.assertEqual(normalized["recommended_next_step"], "require_approval")
        self.assertIn("找到 3 次登入失敗", normalized["evidence_summary"][0])

    def test_unparseable_nonempty_auth_log_is_not_treated_as_zero(self) -> None:
        request = {
            "trigger_event": {
                "event_key": "kernel-cve-radar.authentication.admin.login.success",
                "event_outcome": "success",
                "username": "admin",
                "user_role": "admin",
                "effective_source_ip": "192.168.1.104",
                "timestamp": "2026-07-19T14:14:14Z",
            },
            "detection_context": {"scenario": "admin_login_success", "detection_threshold": 3},
            "investigation": {
                "lookback_minutes": 5,
                "auth_log_path": "/var/log/kernel-cve-radar/auth-events.jsonl",
            },
        }
        normalized = adapter.normalize_envelope(
            {
                "assessment": "suspicious",
                "incident_type": "authentication_failure",
                "confidence": 0.95,
                "severity": "medium",
                "recommended_next_step": "require_approval",
                "reason": "模型表示有三次失敗，但沒有提供 governed count 欄位。",
                "affected_user": "admin",
                "source_ips": ["192.168.1.104"],
                "evidence_summary": ["模型可讀但 Adapter 無法解析的輸出"],
            },
            ["read_log_file"],
            request=request,
            mcp_evidence=[{
                "round": 1,
                "tool": "read_log_file",
                "arguments": {"log_path": "/var/log/kernel-cve-radar/auth-events.jsonl"},
                "result": "non-empty MCP output without machine-readable records",
                "parsed_log_records": [],
                "log_record_parse_status": "unparsed_nonempty",
            }],
        )
        check = normalized["evidence"]["recent_admin_login_check"]
        self.assertIsNone(check["failure_count"])
        self.assertEqual(normalized["assessment"], "insufficient_context")
        self.assertEqual(normalized["recommended_next_step"], "collect_more_evidence")
        self.assertFalse(any("只找到 0 次" in item for item in normalized["evidence_summary"]))

    def test_truncated_escaped_json_fragments_are_still_parseable(self) -> None:
        text = (
            '...[earlier omitted] \"entries\": ['
            '{\"ts\":\"2026-07-19T14:13:50Z\",\"outcome\":\"fail\",'
            '\"user\":\"admin\",\"path\":\"/login\"}, '
            '{\"ts\":\"2026-07-19T14:13:55Z\",\"outcome\":\"fail\",'
            '\"user\":\"admin\",\"path\":\"/login\"}'
        )
        records = [item for item in adapter._iter_log_records(text) if adapter._looks_like_log_record(item)]
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["user"], "admin")



if __name__ == "__main__":
    unittest.main(verbosity=2)
