from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ADAPTER_PATH = (
    Path(__file__).resolve().parents[1]
    / "playbooks"
    / "files"
    / "governed_agentic_adapter.py"
)


def load_adapter():
    spec = importlib.util.spec_from_file_location("governed_adapter_under_test", ADAPTER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class AdapterMcpErrorHandlingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapter = load_adapter()

    def test_exception_group_exposes_leaf_error(self):
        error = ExceptionGroup(
            "unhandled errors in a TaskGroup",
            [ConnectionError("All connection attempts failed")],
        )
        details = self.adapter.describe_exception_tree(error)
        self.assertIn("ConnectionError", details["summary"])
        self.assertIn("All connection attempts failed", details["summary"])
        self.assertEqual(details["root_errors"][0]["type"], "ConnectionError")

    def test_structured_admin_trigger_fails_closed_on_mcp_transport_failure(self):
        request = {
            "trigger_event": {
                "event_key": "kernel-cve-radar.authorization.admin.access",
                "username": "user1",
                "user_role": "user",
                "http_path": "/admin",
                "event_outcome": "allowed",
                "source_ip": "192.168.1.104",
            },
            "investigation": {"target_host": "testclone"},
        }
        error = ExceptionGroup(
            "unhandled errors in a TaskGroup",
            [ConnectionError("All connection attempts failed")],
        )
        result = self.adapter.finalize_mcp_transport_failure(
            request,
            error,
            stage="initialize",
        )
        self.assertEqual(result["assessment"], "insufficient_context")
        self.assertEqual(result["incident_type"], "unknown")
        self.assertEqual(result["confidence"], 0.0)
        self.assertEqual(result["recommended_next_step"], "require_approval")
        self.assertEqual(result["investigation_status"], "mcp_error")
        self.assertIn("mcp_root_errors", result)
        self.assertIn("mcp_failure_fail_closed", result["governance_policy_applied"])
        self.assertNotIn("structured_admin_trigger_confidence_floor", result["governance_policy_applied"])

    def test_non_structured_event_stops_for_approval(self):
        request = {
            "trigger_event": {"event_key": "kernel-cve-radar.http.access"},
            "investigation": {"target_host": "testclone"},
        }
        error = ExceptionGroup(
            "unhandled errors in a TaskGroup",
            [TimeoutError("timed out")],
        )
        result = self.adapter.finalize_mcp_transport_failure(
            request,
            error,
            stage="initialize",
        )
        self.assertEqual(result["recommended_next_step"], "require_approval")
        self.assertEqual(result["investigation_status"], "mcp_error")

    def test_model_401_fails_closed_even_for_structured_admin_event(self):
        request = {
            "trigger_event": {
                "event_key": "kernel-cve-radar.authorization.admin.access",
                "username": "user1",
                "user_role": "user",
                "http_path": "/admin",
                "event_outcome": "allowed",
            },
            "investigation": {"target_host": "testclone"},
        }
        error = self.adapter.ModelInvocationError(
            "AI model endpoint returned HTTP 401",
            stage="model_plan",
            category="auth_error",
            status_code=401,
            response_text='{"error":{"message":"No api key passed in"}}',
        )
        result = self.adapter.finalize_model_failure(request, error)
        self.assertEqual(result["assessment"], "insufficient_context")
        self.assertEqual(result["confidence"], 0.0)
        self.assertEqual(result["recommended_next_step"], "require_approval")
        self.assertEqual(result["investigation_status"], "model_auth_error")
        self.assertEqual(result["model_http_status"], 401)
        self.assertNotIn("structured_admin_trigger_confidence_floor", result["governance_policy_applied"])
        self.assertIn("model_failure_fail_closed", result["governance_policy_applied"])



if __name__ == "__main__":
    unittest.main()
