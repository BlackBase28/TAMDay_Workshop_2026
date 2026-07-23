#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

required=(
  VERSION README.md SOURCE_BASE.md ansible.cfg collections/requirements.yml
  playbooks/deploy_forwarder.yml
  playbooks/eda_ai_risk_analysis.yml
  playbooks/suspicious_login_review.yml
  playbooks/enable_maintenance_page.yml
  playbooks/sync_solution_from_git_and_deploy.yml
  playbooks/restore_login_page.yml
  playbooks/verify_fixed_site.yml
  playbooks/sync_start_from_git_and_deploy.yml
  playbooks/send_ntfy_alert.yml
  playbooks/files/governed_agentic_adapter.py
  playbooks/roles/cve_radar_eda_forwarder/files/cve_radar_event_forwarder.py
  roles/kernel_cve_radar_remediation/defaults/main.yml
  roles/kernel_cve_radar_remediation/tasks/main.yml
  extensions/eda/rulebooks/cve_radar_authentication_anomaly.yml
  tests/send_test_event.sh
)
for item in "${required[@]}"; do
  [[ -f "$root/$item" ]] || { echo "MISSING: $item" >&2; exit 1; }
done

removed=(
  decision-environment
  requirements.yml
  playbooks/verify_fixed_site_before_restore.yml
  playbooks/ai_dispatch_remediation.yml
  playbooks/send_slack_alert.yml
  roles/kernel_cve_radar_remediation/tasks/send_slack_alert.yml
  roles/kernel_cve_radar_remediation/tasks/send_ntfy_alert.yml
)
for item in "${removed[@]}"; do
  [[ ! -e "$root/$item" ]] || { echo "OBSOLETE: $item" >&2; exit 1; }
done

python3 -m py_compile \
  "$root/playbooks/files/governed_agentic_adapter.py" \
  "$root/playbooks/roles/cve_radar_eda_forwarder/files/cve_radar_event_forwarder.py"

python3 -m unittest discover -s "$root/tests" -p 'test_*.py' -v

grep -Eq '^  ai_model_url: ""$' "$root/playbooks/vars/ai_risk_analysis_defaults.yml"
grep -Eq '^  ai_model: ""$' "$root/playbooks/vars/ai_risk_analysis_defaults.yml"
grep -q "Show raw Model responses for comparison" "$root/playbooks/eda_ai_risk_analysis.yml"
grep -q "body_format: json" "$root/playbooks/send_ntfy_alert.yml"
! grep -q "headers:" "$root/playbooks/send_ntfy_alert.yml"
! grep -q "qwen3-14b" "$root/playbooks/files/governed_agentic_adapter.py"

find "$root" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$root" -type f -name '*.pyc' -delete

echo "OK: Workshop 1.9.5-slim24 GitHub-based slim runtime with standalone ntfy"
