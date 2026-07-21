# TAM Day – Governed EDA Security Investigation

Git-managed project based on the proven **V1.9.5** runtime baseline.

## Active labs

| Lab | EDA trigger | AI investigation | Governed hand-off |
|---|---|---|---|
| Lab 1 | Non-admin successfully accesses `/admin` | Confirm broken access control | `CVE Radar - Governed Web Remediation` |
| Lab 2 | Every successful `admin` login | RHEL MCP reads the auth log and counts `admin` login failures in the previous 5 minutes | Start `CVE Radar - Suspicious Login Review` only when failures ≥ 3 |

For Lab 2, the successful login is only a wake-up signal. Login failures remain
in `/var/log/kernel-cve-radar/auth-events.jsonl` and are not individually sent to
EDA. The Model plans a bounded MCP investigation, while the Adapter restricts it
to `read_log_file`, `get_journal_logs`, and `get_service_status`. The Auth Log
read remains mandatory because the Adapter applies the five-minute threshold
after MCP evidence is collected.

When fewer than three failures are found, the AI Job records `observe` and does
not publish a Review proposal. The flow never locks the account, blocks an IP,
enables maintenance mode, or changes the target host.

The Adapter rebuilds the Lab 2 evidence summary from the parsed Auth Log records,
so a Model-generated count cannot conflict with the governed five-minute count.
When the Review Workflow is launched, it receives the failure timestamps,
reasons, source IPs, and a formatted `workflow_review_summary` through
`extra_vars`.

## Active flow

```text
admin login succeeds
→ Forwarder sends admin.login.success
→ EDA launches CVE Radar - AI Risk Analysis
→ Model plans bounded MCP evidence collection
→ Adapter permits only read_log_file/get_journal_logs/get_service_status
→ Auth Log read counts admin failures during the previous 5 minutes
├─ failures >= 3 → require_approval → Suspicious Login Review Workflow
└─ failures < 3  → observe → no Workflow
```

## Runtime entry points

- AI analysis: `playbooks/eda_ai_risk_analysis.yml`
- Review record: `playbooks/suspicious_login_review.yml`
- Git defaults: `playbooks/vars/ai_risk_analysis_defaults.yml`
- Forwarder deployment: `playbooks/deploy_forwarder.yml`

The Forwarder deployment uses the AAP Machine Credential or inventory connection variables for SSH authentication. It does not load host passwords from the Git Project.
The Forwarder also publishes `cve_radar_collector_hostname` (default: `inventory_hostname`) so AI Analysis uses the inventory/MCP host key instead of a cloud provider internal OS hostname. HTTPD log ACL deployment applies both directory traversal access and inherited defaults, explicitly recalculates masks with the supported `mask` enum, then validates readability as the configured MCP user. The deployment also adds the MCP SSH user to `systemd-journal` and validates `journalctl` access for `get_journal_logs`.
- Rulebook: `extensions/eda/rulebooks/cve_radar_authentication_anomaly.yml`

Job Template Extra Variables can remain empty. Tokens remain in AAP Credentials.
Rulebook Activation Variables can override the Organization, AI Job Template,
and Workflow names.

## Validation

```bash
./tests/verify_project.sh

# Direct Event Stream smoke tests
./tests/send_test_event.sh admin-access user1 192.168.1.104 /admin
./tests/send_test_event.sh admin-login-success 192.168.1.104

# End-to-end Lab 2 test through the Forwarder
sudo ./tests/send_test_event.sh append-login-sequence \
  192.168.1.104 3 \
  /var/log/kernel-cve-radar/auth-events.jsonl
```

Setup details are in `docs/SETUP.md`.
