#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
required=(
  VERSION README.md COMPONENT_VERSIONS.yml
  bootstrap/aap_objects.yml
  playbooks/deploy_forwarder.yml
  playbooks/eda_ai_risk_analysis.yml
  playbooks/suspicious_login_review.yml
  playbooks/enable_maintenance_page.yml
  playbooks/sync_solution_from_git_and_deploy.yml
  playbooks/verify_fixed_site_before_restore.yml
  playbooks/restore_login_page.yml
  playbooks/verify_fixed_site.yml
  playbooks/sync_start_from_git_and_deploy.yml
  playbooks/vars/ai_risk_analysis_defaults.yml
  playbooks/files/governed_agentic_adapter.py
  playbooks/roles/cve_radar_eda_forwarder/files/cve_radar_event_forwarder.py
  roles/kernel_cve_radar_remediation/tasks/main.yml
  extensions/eda/rulebooks/cve_radar_authentication_anomaly.yml
  examples/rulebook_activation_vars.yml
  tests/send_test_event.sh
)
for item in "${required[@]}"; do
  [[ -f "$root/$item" ]] || { echo "MISSING: $item" >&2; exit 1; }
done
[[ ! -e "$root/playbooks/eda_mcp_auth_investigation.yml" ]]
[[ ! -e "$root/playbooks/files/normalize_litellm_response.py" ]]
[[ ! -e "$root/vars/host_passwords.yml.example" ]]
[[ -z "$(find "$root" -type f \( -name '*.pyc' -o -path '*/__pycache__/*' \) -print -quit)" ]]
python3 -m py_compile \
  "$root/playbooks/files/governed_agentic_adapter.py" \
  "$root/playbooks/roles/cve_radar_eda_forwarder/files/cve_radar_event_forwarder.py"
python3 -m unittest discover -s "$root/tests" -p 'test_*.py' -v
find "$root" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$root" -type f -name '*.pyc' -delete
echo "OK: TAM Day Workshop 1.0.0 merged EDA and governed remediation contract"
