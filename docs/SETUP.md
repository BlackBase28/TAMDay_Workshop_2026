# Setup

## AAP objects

Use this repository in Automation Execution and Automation Decisions.

### Job Templates

1. `CVE Radar - AI Risk Analysis`
   - Playbook: `playbooks/eda_ai_risk_analysis.yml`
   - Attach the Model Credential and Event Stream sender Credential.
   - Enable **Prompt on launch** for Variables so EDA-provided `extra_vars` are accepted.
   - Extra Variables may remain empty.

2. `CVE Radar - Record Suspicious Login Review`
   - Playbook: `playbooks/suspicious_login_review.yml`
   - Inventory: localhost-compatible inventory.
   - Credential: none required.
   - Enable **Prompt on launch** for Variables.

### Workflows

- `CVE Radar - Governed Web Remediation`: existing Lab 1 repair Workflow.
- `CVE Radar - Suspicious Login Review`: recommended nodes:

```text
CVE Radar - Record Suspicious Login Review
→ Approval: Review suspicious successful login
→ optional notification or follow-up Job Template
```

The review Workflow must not lock accounts, block source IPs, or change hosts.

The Workflow receives these launch variables from EDA:

```yaml
workflow_review_summary: "[investigation-id] governed evidence summary"
login_failures:
  - timestamp: 2026-07-19T13:32:09Z
    username: admin
    source_ip: 192.168.1.104
    failure_reason: bad_password
```

AAP Workflow Template `Description` is static and cannot be prompted at launch.
Use `workflow_review_summary` in the first record Job, downstream notifications,
or other review nodes instead of trying to modify the template description.

### Rulebook Activation

Rulebook:

```text
extensions/eda/rulebooks/cve_radar_authentication_anomaly.yml
```

Optional Activation Variables:

```yaml
cve_radar_aap_organization: Default
cve_radar_ai_job_template_name: CVE Radar - AI Risk Analysis
cve_radar_web_remediation_workflow_name: CVE Radar - Governed Web Remediation
cve_radar_suspicious_login_review_workflow_name: CVE Radar - Suspicious Login Review
```

Restart the Activation after syncing the changed Rulebook.

## Git-managed AI defaults

Non-sensitive defaults are in:

```text
playbooks/vars/ai_risk_analysis_defaults.yml
```

Precedence:

```text
Job Template Extra Variables → Git defaults
```

The MCP allowlist is:

```yaml
governed_allowed_mcp_tools: read_log_file,get_journal_logs,get_service_status
```

The Model plans the evidence collection, but the Adapter filters all plans
through this allowlist. For Lab 2, a bounded Auth Log read is mandatory even if
the Model initially selects only Journal or Service Status. The Adapter uses the
successful login timestamp as the end of the window and counts only `admin`
login failures from the preceding five minutes.

## Credentials

Model Credential Injector:

```yaml
env:
  AI_RISK_WEBHOOK_URL: '{{ ai_risk_webhook_url }}'
  AI_RISK_WEBHOOK_TOKEN: '{{ ai_risk_webhook_token }}'
  AI_VALIDATE_CERTS: '{{ ai_validate_certs }}'
```

Event Stream sender Credential Injector:

```yaml
env:
  EDA_EVENT_STREAM_URL: '{{ eda_event_stream_url }}'
  EDA_EVENT_STREAM_TOKEN: '{{ eda_event_stream_token }}'
```

## Stable Collector hostname

The Forwarder publishes a stable target name in every Event Stream payload. By default it uses the AAP inventory host name rather than the remote operating system FQDN:

```yaml
cve_radar_collector_hostname: "{{ inventory_hostname }}"
```

Override it explicitly when the RHEL MCP policy uses a different host key:

```yaml
cve_radar_collector_hostname: rhel.l2mmh.sandbox1190.opentlc.com
```

The generated `/etc/cve-radar-eda-forwarder.env` contains `COLLECTOR_HOSTNAME`. This prevents AWS or other cloud internal names such as `ip-192-168-0-81.us-east-2.compute.internal` from being sent as the governed MCP target. Redeploy or restart the Forwarder after changing this value.

## Forwarder behavior

The Forwarder watches the structured application Auth Log by default:

```yaml
cve_radar_auth_event_log: /var/log/kernel-cve-radar/auth-events.jsonl
cve_radar_web_access_enabled: false
```

Behavior:

```text
admin login failure    → retained in log, not sent to EDA
non-admin login success → retained in log, not sent to EDA
admin login success     → always sent to EDA immediately
```

There is no Forwarder-side failure counter or five-minute correlation state.
Redeploy the Forwarder after updating because its Python code and environment
template changed.

## Smoke tests

Direct Event Stream test for the EDA and AI route:

```bash
./tests/send_test_event.sh admin-login-success 192.168.1.104
```

This direct mode only sends the successful-login wake-up event. The target Auth
Log must already contain the evidence that MCP should inspect.

End-to-end test through the Forwarder:

```bash
sudo ./tests/send_test_event.sh append-login-sequence \
  192.168.1.104 3 \
  /var/log/kernel-cve-radar/auth-events.jsonl

journalctl -u cve-radar-eda-forwarder.service -f
```

Expected Forwarder event key:

```text
kernel-cve-radar.authentication.admin.login.success
```

## AAP connection credential

Attach a Machine Credential to the `Deploy Event Forwarder` Job Template. The
credential supplies the SSH username and password or private key used before
`Gathering Facts`. Do not place host passwords in the Git Project and do not
define `cve_radar_host_passwords`. Inventory variables may still supply standard
Ansible connection variables when required.

Typical Workshop settings are:

```text
Credential type: Machine
Username: lab-user
Password or SSH private key: environment-specific
Privilege escalation method: sudo
```

## RHEL MCP log read permissions

`deploy_forwarder.yml` now grants the RHEL MCP SSH account read-only ACLs for the evidence logs used by AI Analysis. The default account is `ansible_user`; override it when the MCP policy uses another SSH user:

```yaml
cve_radar_mcp_log_acl_enabled: true
cve_radar_mcp_user: lab-user
cve_radar_mcp_read_application_logs: true
cve_radar_mcp_read_httpd_logs: true
```

Application-log access includes `/var/log/kernel-cve-radar/auth-events.jsonl`. HTTPD access includes existing access and error logs under `/var/log/httpd`. Set `cve_radar_mcp_read_httpd_logs: false` when only Lab 2 authentication evidence is required. The role uses POSIX ACLs and does not change the file owner or globally-readable mode.

Verify after deployment:

```bash
sudo -u lab-user test -r /var/log/kernel-cve-radar/auth-events.jsonl
sudo -u lab-user test -r /var/log/httpd/access_log
```
