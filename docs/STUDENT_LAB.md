# Student lab guide

All secrets, Projects, Inventory, Credentials, Job Templates, Event Stream, and the disabled Rulebook Activation are prepared before class.

## 1. Confirm your isolated Organization

After signing in to AAP, verify that you can see only your own:

- CVE Radar Inventory and host
- Job Templates
- Workflows
- Event Stream
- Rulebook Activation

## 2. Complete the governed remediation Workflow

Open `CVE Radar - Governed Web Remediation` and create or complete this path:

```text
CVE Radar - Enable Maintenance
→ Approval: Approve governed web remediation
→ CVE Radar - Deploy Repaired Website
→ CVE Radar - Verify Fixed Site Before Restore
→ CVE Radar - Restore Login Page
→ CVE Radar - Verify Fixed Site
```

Use success links between the normal steps. Do not connect a failed deployment or failed pre-restore verification directly to Restore Login Page.

## 3. Complete the suspicious-login review Workflow

Open `CVE Radar - Suspicious Login Review` and create or complete:

```text
CVE Radar - Record Suspicious Login Review
→ Approval: Review suspicious successful login
```

This is a review-only flow.

## 4. Enable the Rulebook Activation

Enable `CVE Radar Security Event Activation` and wait until its state is Running.

## 5. Run Lab 1

1. Sign in to CVE Radar as `user1`.
2. Access `/admin`.
3. In AAP, open the launched `CVE Radar - AI Risk Analysis` Job.
4. Review the bounded MCP evidence and the AI proposal.
5. Open `CVE Radar - Governed Web Remediation`.
6. Approve the pending Approval node.
7. Confirm that the solution is deployed and `user1` can no longer access `/admin`.

## 6. Run Lab 2

1. Generate three failed `admin` login attempts followed by one successful login within five minutes.
2. Review the launched AI Risk Analysis Job.
3. Confirm that `CVE Radar - Suspicious Login Review` starts only when the governed failure count is at least three.
4. Review and approve the record-only Workflow.

## 7. Reset the lab

Run `CVE Radar - Reset Lab` only when instructed. It deploys the vulnerable `start` version for the next exercise.
