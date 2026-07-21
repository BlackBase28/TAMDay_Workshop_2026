# Changelog

## 1.9.5-slim14

- Fix HTTPD ACL deployment so `/var/log/httpd` receives a non-default access ACL for directory traversal, not only a default inheritance ACL.
- Apply separate access and default ACL entries for both the Forwarder service account and the configured RHEL MCP SSH user.
- Grant read ACLs to each existing HTTPD access/error log and explicitly recalculate the ACL mask.
- Verify every existing HTTPD evidence log is readable while impersonating the MCP user.
- Preserve slim13 stable collector hostname, slim12 Machine Credential authentication, and all governed AI behavior.

## 1.9.5-slim13

- Add `cve_radar_collector_hostname`, defaulting to the AAP `inventory_hostname`.
- Render `COLLECTOR_HOSTNAME` into the Forwarder environment so Event Stream payloads no longer fall back to cloud-internal `socket.getfqdn()` values.
- Make direct Event Stream smoke tests reuse the deployed `COLLECTOR_HOSTNAME`.
- Update the Forwarder component trace version to `1.9.5-slim13`.
- Preserve slim12 Machine Credential authentication and slim11 MCP log ACL behavior.

## 1.9.5-slim12

- Remove the mandatory Project-local `vars/host_passwords.yml` dependency from `deploy_forwarder.yml`.
- Stop overriding `ansible_password` with `cve_radar_host_passwords[inventory_hostname]`.
- Use the AAP Machine Credential or inventory connection variables as the authoritative SSH authentication source.
- Preserve the slim11 MCP log-reader ACL behavior and all Forwarder/Event Stream settings.

## 1.9.5-slim11

- Grant the configured RHEL MCP SSH user read-only POSIX ACL access to application authentication evidence logs during Forwarder deployment.
- Optionally grant read-only access to existing HTTPD access and error logs, including default ACL inheritance for log rotation.
- Validate the MCP account and verify it can read the primary authentication log after deployment.
- Preserve existing file ownership and restrictive modes.

## 1.9.5-slim10

- Extract machine-readable Auth Log records from native MCP results before Model-facing character truncation.
- Prevent a successful but unparseable non-empty Auth Log response from being treated as proof of zero failures.
- Parse safe Python-literal and one-layer escaped JSON fragments used by some MCP result renderers.
- Preserve the Adapter-authoritative five-minute failure count and review-only Workflow handoff.

## 1.9.5-slim9

- Parse Auth Log JSON records even when the MCP transport wraps structured results in explanatory text.
- Remap `read_log_file` path aliases to the parameter advertised by the MCP schema, including `log_path`.
- Make the Adapter-authenticated failure count authoritative for Lab 2 and replace, rather than prepend to, Model-generated evidence summaries.
- Record Model/Adapter count disagreements in governed evidence without allowing the Model count to override Auth Log evidence.
- Pass the complete login-failure records and a formatted `workflow_review_summary` into the suspicious-login review Workflow.
- Publish the review summary and failure records through `set_stats` for downstream approval or notification nodes.

## 1.9.5-slim8

- Restore Model-planned MCP evidence collection for both active labs.
- Restrict the governed MCP tool allowlist to `read_log_file`, `get_journal_logs`, and `get_service_status`.
- Exclude `get_system_resources` from the Model-visible and executable tool set.
- Keep a bounded Auth Log read mandatory for Lab 2 even when the Model initially plans only supplementary evidence.
- Bound Journal result counts when the MCP tool schema exposes a supported count argument.
- Preserve the five-minute, three-failure Adapter threshold and review-only hand-off.

## 1.9.5-slim7

- Send every successful `admin` login from the Forwarder to EDA immediately.
- Remove Forwarder-side failure counters, time-window correlation state, and related environment variables.
- Keep login failures only in the application Auth Log for MCP evidence collection.
- Pre-seed one bounded `read_log_file` call for Lab 2, avoiding an unnecessary Model planning call.
- Count `admin` login failures during the five minutes before the successful login inside the governed Adapter.
- Publish `require_approval` only when the evidence count is at least three; otherwise return `observe` without starting a Workflow.
- Preserve the review-only policy: no account locking, source blocking, maintenance mode, or host changes.
- Preserve Lab 1 broken-access-control detection and governed web remediation.

## 1.9.5-slim5

- Remove the stale `GOVERNED_MAX_TOOL_CALLS` environment entry that referenced the deleted `governed_max_tool_calls_effective` variable.
- Keep `GOVERNED_MAX_TOOL_CALLS_PER_ROUND` and `GOVERNED_MAX_TOTAL_TOOL_CALLS` as the only active tool-call limits.
- Add a contract test that rejects any `_effective` variable reference without a matching Playbook definition.
- Preserve all V1.9.5-slim4 defaults, Credentials, Rulebook action variables, Model/MCP behavior, and Workflow hand-off.

## 1.9.5-slim4

- Make the AAP Organization, AI Job Template, and both remediation Workflow names overridable through Rulebook Activation Variables.
- Move non-sensitive AI, RHEL MCP, evidence, retry, trace, decision publication, and remediation defaults into `playbooks/vars/ai_risk_analysis_defaults.yml`.
- Preserve Job Template Extra Variables as the highest-precedence optional override layer over Git defaults.
- Consume only sensitive Model and Event Stream values from AAP Credentials; non-sensitive URL, TLS, and policy settings now come from Git.

## 1.9.5-slim3

- Ask both planning and final Model calls to use Traditional Chinese for reasoning and human-readable text.
- Preserve English JSON keys, tool names, and required enum values.
- Keep raw chain-of-thought out of the JSON response while allowing provider-exposed `reasoning_content` to follow the zh-TW language request.

## 1.9.5-slim2

- Reduce default log reads to 30 auth lines, 60 access lines, and 30 error lines.
- Cap one MCP tool result at 4,000 characters and total Model evidence at 12,000 characters.
- Retry transient Model transport errors, HTTP 408/429, and HTTP 5xx once with backoff.
- Keep 401/403, invalid Model responses, MCP permission errors, and MCP tool errors fail-closed without retry.
- Correctly classify a Model failure wrapped by an MCP TaskGroup as a Model failure.

## 1.9.5-slim1

- Preserve the proven V1.9.5 runtime behavior and variable contracts.
- Remove generated Python bytecode and historical upgrade-only files.
- Consolidate static regression checks into one project contract test.
- Replace the oversized Adapter trace test with a compact success-path test.
- Remove one unused Forwarder helper and shorten non-runtime documentation.
