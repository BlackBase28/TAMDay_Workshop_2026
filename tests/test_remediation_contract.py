#!/usr/bin/env python3
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]


class RemediationContractTests(unittest.TestCase):
    def test_component_versions_are_recorded(self) -> None:
        versions = yaml.safe_load((ROOT / "COMPONENT_VERSIONS.yml").read_text(encoding="utf-8"))
        self.assertEqual(versions["merged_project"]["version"], "1.0.0")
        self.assertEqual(versions["components"]["eda_event_stream"]["version"], "1.9.5-slim10")
        self.assertEqual(versions["components"]["ansible_mcp_remediation"]["version"], "0.2.2")

    def test_combined_role_search_path(self) -> None:
        cfg = (ROOT / "ansible.cfg").read_text(encoding="utf-8")
        self.assertIn("./roles", cfg)
        self.assertIn("./playbooks/roles", cfg)
        self.assertIn("/runner/project/roles", cfg)
        self.assertIn("/runner/project/playbooks/roles", cfg)

    def test_forwarder_uses_aap_machine_credential(self) -> None:
        text = (ROOT / "playbooks/deploy_forwarder.yml").read_text(encoding="utf-8")
        self.assertIn("target_hosts | default('cve_radar', true)", text)
        self.assertNotIn("host_passwords", text)
        self.assertNotIn("ansible_password", text)
        self.assertFalse((ROOT / "vars/host_passwords.yml.example").exists())

    def test_required_remediation_playbooks_exist(self) -> None:
        required = [
            "enable_maintenance_page.yml",
            "sync_solution_from_git_and_deploy.yml",
            "verify_fixed_site_before_restore.yml",
            "restore_login_page.yml",
            "verify_fixed_site.yml",
            "sync_start_from_git_and_deploy.yml",
        ]
        for name in required:
            path = ROOT / "playbooks" / name
            self.assertTrue(path.is_file(), name)
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertIsInstance(data, list)
            self.assertEqual(data[0]["roles"], ["kernel_cve_radar_remediation"])

    def test_remediation_allowlist_and_defaults(self) -> None:
        dispatcher = (ROOT / "playbooks/ai_dispatch_remediation.yml").read_text(encoding="utf-8")
        for marker in (
            "repair_web_code",
            "sync_solution_from_git_and_deploy",
            "verify_fixed_site_pre_restore",
            "restore_site",
            "noop",
        ):
            self.assertIn(marker, dispatcher)

        defaults = yaml.safe_load((ROOT / "vars/project_defaults.yml").read_text(encoding="utf-8"))
        self.assertEqual(defaults["kernel_cve_radar_container_name"], "kernel-cve-radar")
        self.assertEqual(defaults["kernel_cve_radar_backend_port"], 8080)
        self.assertEqual(defaults["kernel_cve_radar_container_port"], 8000)
        self.assertEqual(defaults["kernel_cve_radar_repo_url"], "")

    def test_workshop_manifest_matches_rulebook_defaults(self) -> None:
        manifest = yaml.safe_load((ROOT / "bootstrap/aap_objects.yml").read_text(encoding="utf-8"))
        templates = {item["name"]: item["playbook"] for item in manifest["job_templates"]}
        self.assertEqual(
            templates["CVE Radar - AI Risk Analysis"],
            "playbooks/eda_ai_risk_analysis.yml",
        )
        self.assertEqual(
            templates["CVE Radar - Deploy Repaired Website"],
            "playbooks/sync_solution_from_git_and_deploy.yml",
        )
        self.assertEqual(
            manifest["workflows"]["governed_web_remediation"]["name"],
            "CVE Radar - Governed Web Remediation",
        )
        self.assertEqual(
            manifest["workflows"]["suspicious_login_review"]["name"],
            "CVE Radar - Suspicious Login Review",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
