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
cve_radar_mcp_journal_access_enabled: true
cve_radar_mcp_journal_group: systemd-journal
```

Application-log access includes `/var/log/kernel-cve-radar/auth-events.jsonl`. HTTPD access includes existing access and error logs under `/var/log/httpd`. Set `cve_radar_mcp_read_httpd_logs: false` when only Lab 2 authentication evidence is required. The role uses POSIX ACLs and does not change the file owner or globally-readable mode. The role applies both an access ACL (`u:<mcp-user>:r-x`) to `/var/log/httpd` and a default ACL for future logrotate-created files, then verifies every existing HTTPD evidence log as the MCP user.

Verify after deployment:

```bash
sudo -u lab-user test -r /var/log/kernel-cve-radar/auth-events.jsonl
sudo -u lab-user test -r /var/log/httpd/access_log
```


### RHEL MCP journal permissions

`get_journal_logs` executes `journalctl` as `cve_radar_mcp_user`. The deployment
role therefore appends that account to the least-privilege
`systemd-journal` group and verifies journal readability while impersonating the
same user.

Verify after deployment:

```bash
id lab-user
sudo -u lab-user journalctl --quiet --no-pager --lines 5
```

Supplementary groups are applied when a new login session is created. If RHEL
MCP already has a persistent SSH connection, restart the RHEL MCP service or Pod
(or otherwise force a new SSH session) before retesting `get_journal_logs`.


### Why deployment verification uses setpriv

AAP commonly connects to the target as the same account configured for RHEL MCP,
for example `lab-user`. Ansible normally skips `become` when the remote user and
`become_user` are identical, so that existing SSH process keeps the supplementary
groups it had when the connection was created. Immediately after adding
`lab-user` to `systemd-journal`, a plain `become_user: lab-user` journal test can
therefore report a false permission failure.

The role validates the new permission using root plus:

```bash
setpriv --reuid=lab-user --regid="$(id -g lab-user)" --init-groups \
  journalctl --quiet --no-pager --lines 1
```

This creates a fresh process credential set from the current user/group database.
RHEL MCP itself must still create a new SSH connection after the deployment.


## Remediation Role discovery

The Project keeps two role roots. Do not move or duplicate the roles:

```text
roles/kernel_cve_radar_remediation
playbooks/roles/cve_radar_eda_forwarder
```

The repository root `ansible.cfg` must remain present so AAP Runner searches both locations.

## External Execution Environment

`CVE Radar - AI Risk Analysis` uses the prebuilt `CVE Radar AI EE 1.8.2` object.
The student Runtime Project intentionally does not carry Image build definitions.

## Optional ntfy Workflow node

Create a standalone Job Template using `playbooks/send_ntfy_alert.yml`.

Recommended Job Template settings:

```text
Name: CVE Radar - Send ntfy Alert
Playbook: playbooks/send_ntfy_alert.yml
Execution Environment: Default execution environment
Inventory: localhost-compatible inventory
Credentials: no target-host Machine Credential required
Variables: Prompt on launch enabled
```

Required Workflow or Job Template Extra Variable:

```yaml
ntfy_url: "https://ntfy.sh/<topic>"
```

Optional variables:

```yaml
ntfy_message: "Kernel CVE Radar remediation completed."
ntfy_title: "Kernel CVE Radar"
ntfy_priority: default
ntfy_tags: "white_check_mark,robot"
ntfy_validate_certs: true
ntfy_timeout: 30
ntfy_no_log: true
```

When `ntfy_message` is omitted, the Playbook uses `workflow_review_summary`
from an upstream Workflow node when available. The ntfy Playbook runs on
`localhost` and does not load the Remediation Role.



## Explicit Model selection and response comparison

The Project intentionally leaves these defaults empty:

```yaml
ai_model_url: ""
ai_model: ""
```

Set both values in `CVE Radar - AI Risk Analysis` through Job Template Extra
Variables, Survey values, or launch Extra Variables:

```yaml
ai_model_url: "https://<model-gateway>/v1/chat/completions"
ai_model: "<exact-model-id>"
ai_show_model_responses: true
```

The Job fails before contacting the Model when either `ai_model_url` or
`ai_model` is empty.

With `ai_show_model_responses: true`, the Job includes a dedicated task named
`Show raw Model responses for comparison`. Each planner and final response
shows:

- requested Model ID
- provider-returned Model ID
- investigation round and attempt
- HTTP status and finish reason
- provider-exposed `reasoning_content`
- response `content`
- requested tool calls
- token usage
- complete raw provider response

This makes the behavior difference between the selected 4B and 30B models
visible without changing the Playbook or Execution Environment.


## ntfy UTF-8 JSON publishing

The ntfy Workflow Playbook uses the official JSON publish format. It derives
the server root and topic from the complete `ntfy_url`, then sends title,
message, tags, and priority in a UTF-8 JSON body instead of HTTP headers.

```yaml
ntfy_url: "https://ntfy.sh/tamday-user01-randomstring"
ntfy_title: "CVE Radar 修復完成"
ntfy_message: "網站已完成修復並通過驗證。"
ntfy_priority: default
ntfy_tags: "white_check_mark,robot"
```

Supported priority names are `min`, `low`, `default`, `high`, `max`, and
`urgent`.


## ntfy explicit JSON serialization

The Workflow Playbook explicitly serializes the payload with:

```yaml
ntfy_payload | ansible.builtin.to_json(
  ensure_ascii=true,
  preprocess_unsafe=false
)
```

It validates the resulting string with `from_json`, then sends it using
`body_format: raw` and the ASCII-only `Content-Type: application/json` header.
This avoids implicit `uri` JSON conversion differences between Execution
Environment / ansible-core versions and safely escapes Traditional Chinese
characters.
