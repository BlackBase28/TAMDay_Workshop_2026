#!/usr/bin/env python3
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]


class WorkshopSlimContractTests(unittest.TestCase):
    def test_version_and_source_base(self):
        self.assertEqual((ROOT / "VERSION").read_text().strip(), "1.9.5-slim23")
        source = (ROOT / "SOURCE_BASE.md").read_text()
        self.assertIn("024c5440690631cd9a11ddaac7cde2e6bcd526ca", source)
        self.assertIn("1.9.5-slim17", source)

    def test_active_entry_points_exist(self):
        required = [
            "playbooks/deploy_forwarder.yml",
            "playbooks/eda_ai_risk_analysis.yml",
            "playbooks/suspicious_login_review.yml",
            "playbooks/enable_maintenance_page.yml",
            "playbooks/sync_solution_from_git_and_deploy.yml",
            "playbooks/restore_login_page.yml",
            "playbooks/verify_fixed_site.yml",
            "playbooks/sync_start_from_git_and_deploy.yml",
            "playbooks/send_ntfy_alert.yml",
            "roles/kernel_cve_radar_remediation/tasks/main.yml",
        ]
        for rel in required:
            self.assertTrue((ROOT / rel).is_file(), rel)

    def test_obsolete_and_operator_only_files_are_absent(self):
        removed = [
            "playbooks/verify_fixed_site_before_restore.yml",
            "playbooks/ai_dispatch_remediation.yml",
            "playbooks/send_slack_alert.yml",
            "roles/kernel_cve_radar_remediation/tasks/send_slack_alert.yml",
            "roles/kernel_cve_radar_remediation/tasks/send_ntfy_alert.yml",
            "decision-environment",
            "requirements.yml",
        ]
        for rel in removed:
            self.assertFalse((ROOT / rel).exists(), rel)

    def test_remediation_action_allowlist_is_remediation_only(self):
        text = (ROOT / "roles/kernel_cve_radar_remediation/tasks/main.yml").read_text()
        for action in (
            "enable_maintenance",
            "restore_site",
            "sync_solution_from_git_and_deploy",
            "sync_start_from_git_and_deploy",
            "verify_fixed_site",
        ):
            self.assertIn(action, text)
        for removed in (
            "send_slack_alert",
            "send_ntfy_alert",
            "verify_fixed_site_pre_restore",
        ):
            self.assertNotIn(removed, text)

    def test_ntfy_is_standalone_workflow_playbook(self):
        playbook = (ROOT / "playbooks/send_ntfy_alert.yml").read_text()
        defaults = (
            ROOT / "roles/kernel_cve_radar_remediation/defaults/main.yml"
        ).read_text()
        self.assertIn("hosts: localhost", playbook)
        self.assertIn("connection: local", playbook)
        self.assertIn("ansible.builtin.uri", playbook)
        self.assertIn('url: "{{ ntfy_url | trim }}"', playbook)
        self.assertIn("method: POST", playbook)
        self.assertIn('body: "{{ ntfy_message_effective }}"', playbook)
        self.assertIn("workflow_review_summary", playbook)
        self.assertNotIn("roles:", playbook)
        self.assertNotIn("kernel_cve_radar_remediation_action", playbook)
        self.assertNotIn("ntfy", defaults.lower())

    def test_executable_runtime_has_no_slack_implementation(self):
        checked = [
            ROOT / "playbooks",
            ROOT / "roles/kernel_cve_radar_remediation",
        ]
        for item in checked:
            for path in item.rglob("*"):
                if (
                    not path.is_file()
                    or "__pycache__" in path.parts
                    or path.suffix == ".pyc"
                ):
                    continue
                with self.subTest(path=path.relative_to(ROOT)):
                    self.assertNotIn(
                        "slack",
                        path.read_text(encoding="utf-8").lower(),
                    )

    def test_all_yaml_files_parse(self):
        for pattern in ("*.yml", "*.yaml"):
            for path in ROOT.rglob(pattern):
                with self.subTest(path=path.relative_to(ROOT)):
                    yaml.safe_load(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
