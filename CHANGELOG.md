# Changelog

## 1.0.0

- Merged authoritative `TAMDay_EDA-v1.9.5-slim10` with authoritative `tamday-ansible-mcp-remediation-0.2.2`.
- Preserved the governed AI adapter, Forwarder, Rulebook, AI analysis, suspicious-login review, remediation role, and discrete remediation playbooks.
- Added a combined `ansible.cfg` that resolves both `roles/` and `playbooks/roles/` in AAP.
- Unified `ansible.posix` requirements for Automation Execution and Decision Environment use.
- Removed the repository-side host password mapping from Forwarder deployment; AAP Inventory and Machine Credential are now authoritative.
- Added a single student-facing README, combined setup guide, student lab guide, source provenance, AAP object manifest, and remediation contract tests.
- Added the governed `repair_web_code` recommendation to the remediation dispatcher allow-list.

The original component changelogs are retained in `docs/source_changelog_eda.md` and `docs/source_changelog_remediation.md`.
