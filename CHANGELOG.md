# Changelog

## 1.9.5-slim22

- 以 GitHub `main` commit `024c5440690631cd9a11ddaac7cde2e6bcd526ca`
  與版本 `1.9.5-slim17` 作為來源基準。
- 保留目前有效的兩個 Lab、AI/EDA、Forwarder、五個 Remediation 動作與測試。
- 保留根目錄 `ansible.cfg` 的雙 Role Search Path。
- 新增獨立 `playbooks/send_ntfy_alert.yml`，供 AAP Workflow Job Template 使用。
- ntfy Topic URL 必須透過 Extra Variable `ntfy_url` 傳入。
- `ntfy_message` 未提供時可使用上游 `workflow_review_summary`。
- 移除 Slack、AI dispatch、pre-restore 相容入口、Decision Environment build 定義及
  根目錄重複 requirements。
- 新增 `SOURCE_BASE.md`，固定記錄 GitHub 來源 commit。

## 1.9.5-slim18

- 以 EDA/AI/Forwarder `1.9.5-slim17` 為基準整合目前的 Remediation Role。
- 納入根目錄與 `playbooks/roles` 的完整 `ansible.cfg` Role Search Path。
- 保留五個有效 Remediation 動作：維護、部署 solution、恢復、驗證與重設 start。
- 移除已淘汰的 pre-restore Job Template Playbook、Slack 與 AI dispatch 相容入口。
- 移除課前已由外部 AAP Execution Environment / Decision Environment 提供的 Image build 定義。
- 新增 Role 路徑與精簡內容合約測試。
