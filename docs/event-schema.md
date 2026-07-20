# Active event contracts

## Lab 1: broken access control wake-up

```yaml
event_key: kernel-cve-radar.authorization.admin.access
event_source: application_auth_log
username: user1
user_role: user
event_outcome: allowed
url_path: /admin
collector:
  hostname: testclone
  source_file: /var/log/kernel-cve-radar/auth-events.jsonl
```

## Lab 2: successful admin login wake-up

The Forwarder sends every successful `admin` login without calculating a failure
count:

```yaml
event_key: kernel-cve-radar.authentication.admin.login.success
event_source: application_auth_log
event_type: authentication
event_action: login
event_outcome: success
username: admin
user_role: admin
effective_source_ip: 192.168.1.104
observed_at: 2026-07-18T10:05:00Z
collector:
  hostname: testclone
  source_file: /var/log/kernel-cve-radar/auth-events.jsonl
```

AI uses RHEL MCP to read the Auth Log and evaluates this window:

```text
window_start = observed_at - 5 minutes
window_end   = observed_at
username     = admin
threshold    = 3 failures
```

## AI suspicious-login review proposal

This event is published only when MCP evidence contains at least three matching
failures in the five-minute window:

```yaml
schema_version: kernel-cve-radar.ai-decision.v1
event_key: kernel-cve-radar.ai.review.proposed
event_source: ai_analysis
routing:
  approved: true
  workflow_key: suspicious_login_review
incident_type: suspicious_login_success
recommended_next_step: require_approval
trigger_context:
  username: admin
  failure_count: 3
  failure_threshold: 3
  failure_window_seconds: 300
review:
  automatic_account_action: false
```

When the count is below three, the AI result is `observe`; no decision event or
Review Workflow is created.
