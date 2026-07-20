# Instructor setup

## Project model

Use this repository as both the Automation Execution Project and the Automation Decisions Project. Each student Organization should own separate AAP objects, but all Project objects may point to the same public repository and fixed workshop tag or commit.

A public HTTPS repository does not require an SCM Credential.

The complete object list is available in `bootstrap/aap_objects.yml`.

## Per-student objects

Create these objects in each student's Organization:

- User and Team membership
- Inventory with a `cve_radar` group and the student's target host
- Machine Credential
- AI Model Credential
- RHEL MCP Credential
- Event Stream sender Credential
- Automation Execution Project
- Automation Decisions Project
- Job Templates
- Governed Web Remediation Workflow
- Suspicious Login Review Workflow
- Event Stream
- Disabled Rulebook Activation

## Credential injection

### AI Model Credential

The governed AI playbook reads the Model token only from `AI_RISK_WEBHOOK_TOKEN`. Inject the non-sensitive URL and TLS flag as Extra Variables.

```yaml
extra_vars:
  ai_model_url: '{{ ai_risk_webhook_url }}'
  ai_validate_certs: '{{ ai_validate_certs }}'
env:
  AI_RISK_WEBHOOK_TOKEN: '{{ ai_risk_webhook_token }}'
```

### RHEL MCP Credential

```yaml
extra_vars:
  rhel_mcp_url: '{{ rhel_mcp_url }}'
  rhel_mcp_validate_certs: '{{ rhel_mcp_validate_certs }}'
env:
  RHEL_MCP_TOKEN: '{{ rhel_mcp_token }}'
```

### Event Stream sender Credential

The same Credential can serve both Forwarder deployment and the AI proposal hand-off.

```yaml
extra_vars:
  eda_event_stream_url: '{{ eda_event_stream_url }}'
  eda_event_stream_token: '{{ eda_event_stream_token }}'
  eda_event_stream_auth_header: '{{ eda_event_stream_auth_header }}'
  eda_event_stream_verify_tls: '{{ eda_event_stream_verify_tls }}'
env:
  EDA_EVENT_STREAM_URL: '{{ eda_event_stream_url }}'
  EDA_EVENT_STREAM_TOKEN: '{{ eda_event_stream_token }}'
```

## Job Templates

### EDA and AI

1. `CVE Radar - Deploy Event Forwarder`
   - Playbook: `playbooks/deploy_forwarder.yml`
   - Inventory: student's inventory
   - Credentials: Machine and Event Stream sender
   - Extra Variables: empty

2. `CVE Radar - AI Risk Analysis`
   - Playbook: `playbooks/eda_ai_risk_analysis.yml`
   - Credentials: AI Model, RHEL MCP, and Event Stream sender
   - Enable Prompt on Launch for Variables
   - Extra Variables: empty

3. `CVE Radar - Record Suspicious Login Review`
   - Playbook: `playbooks/suspicious_login_review.yml`
   - Enable Prompt on Launch for Variables
   - No host-changing Credential is required

### Governed remediation

Create one Job Template for each playbook:

| Template | Playbook |
|---|---|
| CVE Radar - Enable Maintenance | `playbooks/enable_maintenance_page.yml` |
| CVE Radar - Deploy Repaired Website | `playbooks/sync_solution_from_git_and_deploy.yml` |
| CVE Radar - Verify Fixed Site Before Restore | `playbooks/verify_fixed_site_before_restore.yml` |
| CVE Radar - Restore Login Page | `playbooks/restore_login_page.yml` |
| CVE Radar - Verify Fixed Site | `playbooks/verify_fixed_site.yml` |
| CVE Radar - Reset Lab | `playbooks/sync_start_from_git_and_deploy.yml` |

Attach the student's Inventory and Machine Credential. Extra Variables can remain empty because the project defaults use the existing target-side `/opt/cve-radar/src/start` and `/opt/cve-radar/src/solution` folders.

## Workflows

### CVE Radar - Governed Web Remediation

Enable Prompt on Launch for Variables and Limit.

```text
Enable Maintenance
→ Approval: Approve governed web remediation
→ Deploy Repaired Website
→ Verify Fixed Site Before Restore
→ Restore Login Page
→ Verify Fixed Site
```

Keep the site in maintenance mode when deployment or pre-restore verification fails.

### CVE Radar - Suspicious Login Review

Enable Prompt on Launch for Variables. Do not require a host limit.

```text
Record Suspicious Login Review
→ Approval: Review suspicious successful login
→ optional notification
```

This Workflow must not lock the account, block an IP, or change the target host.

## Rulebook Activation

Rulebook:

```text
extensions/eda/rulebooks/cve_radar_authentication_anomaly.yml
```

Per-student Activation Variables:

```yaml
cve_radar_aap_organization: TAMDay-student01
cve_radar_ai_job_template_name: CVE Radar - AI Risk Analysis
cve_radar_web_remediation_workflow_name: CVE Radar - Governed Web Remediation
cve_radar_suspicious_login_review_workflow_name: CVE Radar - Suspicious Login Review
```

Create the Activation before class but leave it disabled. The student enables it after completing the Workflow exercise.

## Forwarder deployment

`playbooks/deploy_forwarder.yml` uses AAP Inventory and Machine Credential. No `host_passwords.yml` file is required.

The Forwarder watches:

```text
/var/log/kernel-cve-radar/auth-events.jsonl
```

Default behavior:

```text
admin login failure     → keep in the log; do not send to EDA
non-admin login success → keep in the log; do not send to EDA
admin login success     → send to EDA immediately
non-admin /admin access → send to EDA
```

## Validation

```bash
./tests/verify_project.sh
```
