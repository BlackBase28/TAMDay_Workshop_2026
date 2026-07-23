# TAM Day CVE Radar Workshop

Version: `1.9.5-slim23`

本專案以 GitHub `main` commit
`024c5440690631cd9a11ddaac7cde2e6bcd526ca`（原版本 `1.9.5-slim17`）為來源基準，
作為學員在 AAP Automation Execution 與 Automation Decisions 共用的單一 Runtime Project。

只保留兩個 Lab 所需的 AI/EDA、Forwarder、Remediation、驗證元件，以及可加入
AAP Workflow 的獨立 ntfy 通知 Playbook。

## Lab 流程

### Lab 1：Broken access control

```text
user1 存取 /admin
→ Forwarder 送出事件
→ EDA 啟動 AI Risk Analysis
→ AI 透過受控 RHEL MCP 蒐證
→ EDA 啟動 Governed Web Remediation
→ 維護頁 → 部署 solution → 恢復網站 → 驗證
```

### Lab 2：Suspicious successful admin login

```text
admin 登入成功
→ Forwarder 喚醒 EDA
→ AI 檢查前 5 分鐘 Auth Log
├─ 失敗 >= 3：啟動 Suspicious Login Review
└─ 失敗 < 3：只記錄 observe
```

Lab 2 不鎖帳號、不封鎖 IP，也不修改目標主機。

## AAP 執行入口

| 用途 | Playbook |
|---|---|
| 部署 Forwarder 與 MCP 讀取權限 | `playbooks/deploy_forwarder.yml` |
| AI/MCP 調查 | `playbooks/eda_ai_risk_analysis.yml` |
| 記錄異常登入審查 | `playbooks/suspicious_login_review.yml` |
| 切換維護頁 | `playbooks/enable_maintenance_page.yml` |
| 部署修復版本 | `playbooks/sync_solution_from_git_and_deploy.yml` |
| 恢復正常網站 | `playbooks/restore_login_page.yml` |
| 驗證修復 | `playbooks/verify_fixed_site.yml` |
| 重設 vulnerable 版本 | `playbooks/sync_start_from_git_and_deploy.yml` |
| Workflow ntfy 通知節點 | `playbooks/send_ntfy_alert.yml` |
| EDA Rulebook | `extensions/eda/rulebooks/cve_radar_authentication_anomaly.yml` |

## Role 路徑

根目錄 `ansible.cfg` 保留 GitHub 主分支已修正的雙 Role Search Path：

```ini
roles_path = ./roles:./playbooks/roles:/runner/project/roles:/runner/project/playbooks/roles
```

- Remediation Role：`roles/kernel_cve_radar_remediation`
- Forwarder Role：`playbooks/roles/cve_radar_eda_forwarder`

## ntfy Workflow 節點

`playbooks/send_ntfy_alert.yml` 是獨立 Playbook：

- 在 `localhost` 執行。
- 不載入 `kernel_cve_radar_remediation` Role。
- 不需要目標主機 Machine Credential。
- 可作為 Workflow 中的通知節點。

必要 Extra Variable：

```yaml
ntfy_url: "https://ntfy.sh/<topic>"
```

可選 Extra Variables：

```yaml
ntfy_message: "Kernel CVE Radar remediation completed."
ntfy_title: "Kernel CVE Radar"
ntfy_priority: default
ntfy_tags: "white_check_mark,robot"
ntfy_validate_certs: true
ntfy_timeout: 30
ntfy_no_log: true
```

若未提供 `ntfy_message`，Playbook 會優先使用上游 Workflow 節點透過
`set_stats` 傳入的 `workflow_review_summary`。

## Remediation 動作

Remediation Role 僅保留：

```text
enable_maintenance
sync_solution_from_git_and_deploy
restore_site
verify_fixed_site
sync_start_from_git_and_deploy
```

ntfy 不屬於 Remediation action。

## 已移除

- `playbooks/verify_fixed_site_before_restore.yml`
- `playbooks/ai_dispatch_remediation.yml`
- `playbooks/send_slack_alert.yml`
- `roles/kernel_cve_radar_remediation/tasks/send_slack_alert.yml`
- `decision-environment/`
- 根目錄重複的 `requirements.yml`

Custom AI EE 繼續使用既有的 `CVE Radar AI EE 1.8.2`；不在學員 Runtime
Project 內重建。

## 驗證

```bash
./tests/verify_project.sh
```

來源版本資訊請見 `SOURCE_BASE.md`。


## Model selection and comparison

`ai_model_url` and `ai_model` have no Project defaults. The AI Analysis Job
Template must set both values explicitly. The default
`ai_show_model_responses: true` adds a dedicated Job Output task that displays
the raw planner and final Model responses, including content, provider-exposed
reasoning content, tool calls, finish reason, usage, and provider model ID.
