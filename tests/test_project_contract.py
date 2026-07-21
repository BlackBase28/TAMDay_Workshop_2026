#!/usr/bin/env python3
from pathlib import Path
import re
import unittest
import yaml
from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parents[1]
AI = ROOT / "playbooks/eda_ai_risk_analysis.yml"
DEFAULTS = ROOT / "playbooks/vars/ai_risk_analysis_defaults.yml"
RULEBOOK = ROOT / "extensions/eda/rulebooks/cve_radar_authentication_anomaly.yml"
FORWARDER = ROOT / "playbooks/roles/cve_radar_eda_forwarder/files/cve_radar_event_forwarder.py"
REVIEW = ROOT / "playbooks/suspicious_login_review.yml"


class ProjectContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ai_text = AI.read_text(encoding="utf-8")
        cls.ai_data = yaml.safe_load(cls.ai_text)
        cls.defaults_data = yaml.safe_load(DEFAULTS.read_text(encoding="utf-8"))
        cls.defaults = cls.defaults_data["cve_radar_ai_defaults"]
        cls.rulebook_text = RULEBOOK.read_text(encoding="utf-8")
        cls.rulebook_data = yaml.safe_load(cls.rulebook_text)
        cls.forwarder_text = FORWARDER.read_text(encoding="utf-8")
        cls.review_text = REVIEW.read_text(encoding="utf-8")

    def test_git_default_file_contract(self) -> None:
        self.assertEqual(self.defaults["ai_model"], "qwen3-14b")
        self.assertEqual(self.defaults["rhel_mcp_url"], "http://192.168.1.110:8000/mcp")
        self.assertFalse(self.defaults["ai_validate_certs"])
        self.assertFalse(self.defaults["rhel_mcp_validate_certs"])
        self.assertEqual(
            self.defaults["governed_allowed_mcp_tools"],
            "read_log_file,get_journal_logs,get_service_status",
        )
        self.assertEqual(self.defaults["governed_auth_log_tail_lines"], 30)
        self.assertEqual(self.defaults["governed_access_log_tail_lines"], 60)
        self.assertEqual(self.defaults["governed_error_log_tail_lines"], 30)
        self.assertEqual(self.defaults["governed_max_evidence_chars"], 12000)
        self.assertEqual(self.defaults["ai_model_max_retries"], 1)
        self.assertTrue(self.defaults["ai_decision_event_enabled"])
        self.assertFalse(self.defaults["ai_decision_event_dry_run"])
        self.assertEqual(self.defaults["ai_decision_event_auth_header"], "X-CVE-Radar-Token")
        self.assertEqual(self.defaults["remediation_web_source_variant"], "solution")
        self.assertNotIn("token", " ".join(self.defaults.keys()).lower())

    def test_playbook_loads_git_defaults_and_allows_overrides(self) -> None:
        play = self.ai_data[0]
        self.assertEqual(play["vars_files"], ["vars/ai_risk_analysis_defaults.yml"])
        for marker in (
            "ai_model_url | default(cve_radar_ai_defaults.ai_model_url, true)",
            "rhel_mcp_url | default(cve_radar_ai_defaults.rhel_mcp_url, true)",
            "governed_allowed_mcp_tools | default(cve_radar_ai_defaults.governed_allowed_mcp_tools)",
            "default(cve_radar_ai_defaults.ai_decision_event_enabled)",
        ):
            self.assertIn(marker, self.ai_text)

    def test_override_precedence_contract(self) -> None:
        env = Environment(undefined=StrictUndefined)
        template = env.from_string("{{ ai_model_url | default(git_url, true) }}")
        self.assertEqual(template.render(ai_model_url="https://extra.example", git_url="https://git.example"), "https://extra.example")
        self.assertEqual(template.render(git_url="https://git.example"), "https://git.example")
        rule_name = env.from_string("{{ cve_radar_ai_job_template_name | default('CVE Radar - AI Risk Analysis') }}")
        self.assertEqual(rule_name.render(), "CVE Radar - AI Risk Analysis")
        self.assertEqual(rule_name.render(cve_radar_ai_job_template_name="Lab AI Analysis"), "Lab AI Analysis")

    def test_model_credential_contract(self) -> None:
        self.assertIn("lookup('ansible.builtin.env', 'AI_RISK_WEBHOOK_TOKEN')", self.ai_text)
        for name in ("AI_MODEL_URL", "AI_API_TOKEN", "AI_API_KEY", "LITELLM_API_KEY", "OPENAI_API_KEY"):
            self.assertNotIn(f"lookup('ansible.builtin.env', '{name}')", self.ai_text)
        self.assertIn('AI_MODEL_URL: "{{ ai_model_url_effective }}"', self.ai_text)
        self.assertIn('AI_API_TOKEN: "{{ ai_api_token_effective }}"', self.ai_text)

    def test_active_scenarios_only(self) -> None:
        runtime = "\n".join((self.ai_text, self.rulebook_text, self.forwarder_text))
        for required in (
            "kernel-cve-radar.authorization.admin.access",
            "kernel-cve-radar.authentication.admin.login.success",
            "admin_login_success",
            "suspicious_login_success",
            "require_approval",
            "repair_web_code",
        ):
            self.assertIn(required, runtime)
        for removed in (
            "http_ddos",
            "ddos_mitigation",
            "switch_maintenance_page",
            "web_ddos",
            "credential_stuffing",
            "lock_user",
        ):
            self.assertNotIn(removed, runtime)

    def test_ai_fail_closed_and_governed_handoff_contract(self) -> None:
        for marker in (
            "Stop AI Risk Analysis on Model or MCP failure",
            "fatal_investigation_statuses",
            "kernel-cve-radar.ai.remediation.proposed",
            "kernel-cve-radar.ai.review.proposed",
            "governed_web_remediation",
            "suspicious_login_review",
            "Send governed AI action proposal to the same EDA Event Stream",
        ):
            self.assertIn(marker, self.ai_text)

    def test_rulebook_action_name_variables(self) -> None:
        expected = {
            "cve_radar_aap_organization": "Default",
            "cve_radar_ai_job_template_name": "CVE Radar - AI Risk Analysis",
            "cve_radar_web_remediation_workflow_name": "CVE Radar - Governed Web Remediation",
            "cve_radar_suspicious_login_review_workflow_name": "CVE Radar - Suspicious Login Review",
        }
        for variable, default in expected.items():
            self.assertIn(f"{variable} | default('{default}')", self.rulebook_text)
        activation_vars = yaml.safe_load((ROOT / "examples/rulebook_activation_vars.yml").read_text())
        self.assertEqual(activation_vars, expected)

    def test_review_workflow_does_not_inherit_target_limit(self) -> None:
        review_route = self.rulebook_text.split(
            "- name: Route AI proposal to suspicious login review Workflow", 1
        )[1].split("- name: Detect non-admin access to admin content", 1)[0]
        self.assertNotIn('limit: "{{ event.payload.target_host }}"', review_route)
        self.assertIn('target_host: "{{ event.payload.target_host }}"', review_route)

    def test_rulebook_admin_login_trigger_and_order(self) -> None:
        rules = self.rulebook_data[0]["rules"]
        by_name = {rule["name"]: rule for rule in rules}
        admin = by_name["Detect non-admin access to admin content"]
        self.assertEqual(admin["throttle"]["once_within"], "1 minute")
        login = by_name["Investigate every successful admin login"]
        self.assertNotIn("throttle", login)
        self.assertIn("kernel-cve-radar.authentication.admin.login.success", login["condition"])
        self.assertIn('event.payload.username == "admin"', login["condition"])
        self.assertNotIn("failure_count", login["condition"])
        extra_vars = login["action"]["run_job_template"]["job_args"]["extra_vars"]
        self.assertEqual(extra_vars["investigation_lookback_minutes"], 5)
        self.assertEqual(extra_vars["detection_context"]["detection_threshold"], 3)
        names = [rule["name"] for rule in rules]
        terminal = names.index("Diagnose unrouted AI action proposal")
        for route in (
            "Route AI proposal to governed web remediation Workflow",
            "Route AI proposal to suspicious login review Workflow",
        ):
            self.assertLess(names.index(route), terminal)

    def test_forwarder_admin_success_wakeup_contract(self) -> None:
        for marker in (
            "LOGIN_FAILURE_KEY",
            "LOGIN_SUCCESS_KEY",
            "ADMIN_LOGIN_SUCCESS_KEY",
            "Every successful admin login is forwarded immediately",
            'FORWARD_HTTP_ACCESS_EVENTS',
        ):
            self.assertIn(marker, self.forwarder_text)
        for removed in (
            "FAILED_THEN_SUCCESS_KEY",
            "class LoginFailureCorrelation",
            "LOGIN_FAILURE_THRESHOLD",
            "LOGIN_FAILURE_WINDOW_SECONDS",
        ):
            self.assertNotIn(removed, self.forwarder_text)
        defaults = (ROOT / "playbooks/roles/cve_radar_eda_forwarder/defaults/main.yml").read_text()
        self.assertNotIn("cve_radar_login_failure_threshold", defaults)
        self.assertNotIn("cve_radar_login_failure_window_seconds", defaults)
        self.assertIn("default(false)", defaults)

    def test_review_playbook_is_record_only(self) -> None:
        review = yaml.safe_load(self.review_text)
        self.assertEqual(review[0]["hosts"], "localhost")
        self.assertIn("automatic_account_action: false", self.review_text)
        for forbidden in (
            "ansible.builtin.user:",
            "ansible.posix.firewalld:",
            "community.general.nmcli:",
            "iptables",
            "nftables",
            "ansible.builtin.systemd:",
            "ansible.builtin.command:",
            "ansible.builtin.shell:",
        ):
            self.assertNotIn(forbidden, self.review_text)

    def test_all_effective_variables_are_defined(self) -> None:
        references = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*_effective)\b", self.ai_text))
        definitions = set(re.findall(r"^    ([A-Za-z_][A-Za-z0-9_]*_effective):", self.ai_text, re.MULTILINE))
        self.assertEqual(references - definitions, set())
        self.assertNotIn("GOVERNED_MAX_TOOL_CALLS:", self.ai_text)
        self.assertIn("GOVERNED_MAX_TOOL_CALLS_PER_ROUND:", self.ai_text)

    def test_model_prompts_request_traditional_chinese_and_review_only_login(self) -> None:
        adapter = (ROOT / "playbooks/files/governed_agentic_adapter.py").read_text()
        self.assertGreaterEqual(adapter.count("Use Traditional Chinese (zh-TW) for all reasoning and human-readable text"), 2)
        self.assertIn("provider-exposed reasoning_content", adapter)
        self.assertIn("admin_login_recent_failures_requires_human_review", adapter)
        self.assertIn("admin_login_below_failure_threshold_observe", adapter)
        self.assertIn("recent_admin_login_failure_count", adapter)
        self.assertIn("Never recommend account locking", adapter)
        self.assertIn('"read_log_file",', adapter)
        self.assertIn('"get_journal_logs",', adapter)
        self.assertIn('"get_service_status",', adapter)
        self.assertNotIn('"get_system_resources",', adapter.split("LOG_LINE_ARGUMENT_KEYS", 1)[0])
        self.assertIn("ensure_admin_login_auth_log_plan", adapter)
        self.assertIn("admin_login_required_evidence_added", adapter)
        self.assertIn("adapter_auth_log_count_overrides_model_count", adapter)
        self.assertIn("workflow_review_summary", self.ai_text)
        self.assertIn("workflow_review_summary", self.rulebook_text)
        self.assertIn("workflow_review_summary", self.review_text)
        self.assertIn("login_failures", self.rulebook_text)


    def test_forwarder_deployment_uses_aap_connection_credential(self):
        deploy = (ROOT / "playbooks/deploy_forwarder.yml").read_text()
        self.assertNotIn("cve_radar_host_passwords", deploy)
        self.assertNotIn("vars/host_passwords.yml", deploy)
        self.assertNotIn("ansible_password:", deploy)
        self.assertIn("AAP Machine Credential", deploy)


    def test_forwarder_role_configures_mcp_log_acl(self):
        defaults = (ROOT / "playbooks/roles/cve_radar_eda_forwarder/defaults/main.yml").read_text()
        tasks = (ROOT / "playbooks/roles/cve_radar_eda_forwarder/tasks/main.yml").read_text()
        self.assertIn("cve_radar_mcp_log_acl_enabled: true", defaults)
        self.assertIn("cve_radar_mcp_user:", defaults)
        self.assertIn("Grant MCP user read access to application evidence logs", tasks)
        self.assertIn("Grant MCP user read-only access to available httpd evidence paths", tasks)
        self.assertIn("Verify MCP user can read primary authentication evidence log", tasks)

if __name__ == "__main__":
    unittest.main(verbosity=2)
