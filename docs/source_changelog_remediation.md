# Changelog

## 0.2.2

- Changed `playbooks/verify_fixed_site.yml` to auto-detect maintenance mode instead of forcing post-restore validation.
- When maintenance mode is active, Verify Web Repair checks the local backend `http://127.0.0.1:8080` so it can validate repairs before restore.
- Kept explicit `verify_fixed_site_before_restore.yml` for workflows that prefer a dedicated pre-restore job template.
- Documented how to force strict public validation with `kernel_cve_radar_verify_stage: post_restore`.


## 0.2.1

- Made `kernel_cve_radar_repo_url` optional again for start/solution deploy playbooks.
- Added `vars/project_defaults.yml` for project-level defaults that can be edited in the AAP Project repo.
- When `kernel_cve_radar_repo_url` is empty, deploy playbooks use existing target-side folders under `/opt/cve-radar/src/start` or `/opt/cve-radar/src/solution`.
- Kept remote Git sync behavior when `kernel_cve_radar_repo_url` is set.
- Fixed the maintenance Apache template reference after the v0.2.0 slimming.

## 0.2.0

- Slimmed the project for the current TAM Day AI/MCP workflow.
- Removed legacy update-script deployment path.
- Removed lock/unlock user playbooks.
- Removed older redeploy-from-local-git behavior.
- Made remote Git application repo URL mandatory for start/solution sync deploys.
- Consolidated duplicated start/solution container deployment tasks into one generic task.
- Kept only core workflow playbooks and Slack notification.
