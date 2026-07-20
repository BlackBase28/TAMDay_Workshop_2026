# TAM Day CVE Radar Workshop

Version: `1.0.0`

This is the single AAP Project used by students during the TAM Day CVE Radar workshop. It combines the authoritative EDA/AI investigation runtime and the authoritative governed remediation playbooks in one public Git repository.

## Included authoritative baselines

- EDA and governed AI investigation: `1.9.5-slim10`
- Ansible MCP remediation: `0.2.2`

The merged project keeps the two runtime implementations intact, except that `playbooks/deploy_forwarder.yml` now uses the AAP Inventory and Machine Credential instead of a repository-side host password map.

## Workshop scenarios

### Lab 1: Broken access control

```text
user1 accesses /admin
→ Forwarder sends the structured event to EDA
→ Rulebook launches CVE Radar - AI Risk Analysis
→ AI uses the governed RHEL MCP adapter to collect bounded evidence
→ AI sends a repair proposal back to the same Event Stream
→ Rulebook starts CVE Radar - Governed Web Remediation
→ Student approves the remediation Workflow
→ AAP deploys the solution version and verifies the repair
```

### Lab 2: Suspicious successful admin login

```text
admin login succeeds
→ Forwarder wakes EDA
→ AI reads bounded authentication evidence through RHEL MCP
├─ at least 3 admin failures in the previous 5 minutes
│  → start CVE Radar - Suspicious Login Review
└─ fewer than 3 failures
   → record observe; do not start a Workflow
```

Lab 2 is review-only. It does not lock accounts, block IP addresses, enable maintenance mode, or modify the target host.

## Main project entry points

| Purpose | Path |
|---|---|
| Deploy the Event Stream Forwarder | `playbooks/deploy_forwarder.yml` |
| Governed AI/MCP investigation | `playbooks/eda_ai_risk_analysis.yml` |
| Record suspicious-login review | `playbooks/suspicious_login_review.yml` |
| Enable maintenance page | `playbooks/enable_maintenance_page.yml` |
| Deploy fixed solution | `playbooks/sync_solution_from_git_and_deploy.yml` |
| Verify repaired backend before restore | `playbooks/verify_fixed_site_before_restore.yml` |
| Restore normal site | `playbooks/restore_login_page.yml` |
| Verify repaired public site | `playbooks/verify_fixed_site.yml` |
| Reset to vulnerable start version | `playbooks/sync_start_from_git_and_deploy.yml` |
| EDA Rulebook | `extensions/eda/rulebooks/cve_radar_authentication_anomaly.yml` |

## AAP design

Use the same public Git repository for both:

- Automation Execution Project
- Automation Decisions Project

No SCM Credential is required for a public HTTPS repository.

Each student should still have an independent Organization, Inventory, Machine Credential, Job Templates, Workflows, Event Stream, and Rulebook Activation. The AAP objects can be created in bulk through the Platform Gateway, Controller, and EDA APIs.

The recommended object definitions are listed in:

```text
bootstrap/aap_objects.yml
```

## Variables and credentials

Job Template Extra Variables can normally remain empty.

- Target host and SSH authentication: AAP Inventory and Machine Credential
- Model secret: AAP Custom Credential
- RHEL MCP secret: AAP Custom Credential
- Event Stream URL and token: AAP Custom Credential
- Non-sensitive AI defaults: `playbooks/vars/ai_risk_analysis_defaults.yml`
- Non-sensitive remediation defaults: `vars/project_defaults.yml`

## Validation

```bash
./tests/verify_project.sh
```

Student and instructor setup details are available in `docs/SETUP.md` and `docs/STUDENT_LAB.md`.
