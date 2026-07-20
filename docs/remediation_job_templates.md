# AAP Job Template Notes

Use AAP Inventory and Machine Credential for all target-host playbooks.

## Common Extra Vars

```yaml
target_hosts: cve_radar
kernel_cve_radar_server_name: testclone
```

## Optional application Git source

The start/solution deploy playbooks can sync application code from a remote Git repo, but it is optional.

```yaml
kernel_cve_radar_repo_url: "https://github.com/<org>/<kernel-cve-radar-app-repo>.git"
kernel_cve_radar_repo_version: main
```

If `kernel_cve_radar_repo_url` is empty or omitted, the playbooks use the existing target-side folders:

```text
/opt/cve-radar/src/start
/opt/cve-radar/src/solution
```

Workshop-wide defaults can be kept in:

```text
vars/project_defaults.yml
```

AAP Survey / Extra Vars can still override those defaults.

## Job Templates

Create one Job Template per playbook:

- `Switch Maintenance` → `playbooks/enable_maintenance_page.yml`
- `Sync Solution From Git and Deploy` → `playbooks/sync_solution_from_git_and_deploy.yml`
- `Verify Fixed Site Before Restore` → `playbooks/verify_fixed_site_before_restore.yml`
- `Restore Login Page` → `playbooks/restore_login_page.yml`
- `Verify Web Repair` → `playbooks/verify_fixed_site.yml` (auto mode: backend before restore, public URL after restore)
- `Verify Fixed Site Before Restore` → `playbooks/verify_fixed_site_before_restore.yml` (explicit pre-restore backend validation)
- `Reset to Start Version` → `playbooks/sync_start_from_git_and_deploy.yml`
- `Send Slack Alert` → `playbooks/send_slack_alert.yml`

## Slack secrets

Use AAP Credential injection to provide one of:

```text
SLACK_WEBHOOK_URL
SLACK_BOT_TOKEN
```


## Verify Web Repair behavior

`playbooks/verify_fixed_site.yml` defaults to auto mode. If the target is still in maintenance mode, it verifies the repaired backend directly at `http://127.0.0.1:8080` instead of the public URL, so it can be used before `Restore Login Page`.

To force post-restore public validation, add:

```yaml
kernel_cve_radar_verify_stage: post_restore
```
