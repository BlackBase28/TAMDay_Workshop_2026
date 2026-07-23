# TAM Day CVE Radar Workshop

Version: `1.9.5-slim26`

本專案作為學員在 AAP Automation Execution 與 Automation Decisions 共用的單一 Runtime Project。

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
