# TAM Day CVE Radar Workshop

Version: `1.0.2`

Repository name: `TAMDay_Workshop`

此 Repository 是學員在 TAM Day Workshop 中使用的單一 AAP Project，只保留 Lab 執行與學員設定所需的 EDA Rulebook、AI/MCP 分析 Playbook、Forwarder、Remediation Playbook／Role、Runtime dependency 定義及學員操作文件。

課前 AAP 大量布建工具、帳號清單、Credential 建立邏輯與 AAP 物件定義不包含在本專案中，請使用獨立的 `TAMDay_Workshop-bootstrap` 套件。

## 專案來源

- EDA / Governed AI investigation：`1.9.5-slim10`
- Ansible MCP remediation：`0.2.2`

## AAP Project 使用方式

Automation Execution Project 與 Automation Decisions Project 可共同指向這個 Public Git Repository；透過 HTTPS 讀取公開 Repository 時不需要 SCM Credential。

每位學員仍使用各自獨立的 Organization、Inventory、Credential、Job Template、Workflow、Event Stream 與 Rulebook Activation。這些物件由課前 Bootstrap 套件建立。

## 已包含的必要元件

| 類別 | 內容 |
|---|---|
| EDA | Event Stream Rulebook 與事件契約 |
| Event Forwarder | Forwarder 部署 Playbook、Role、Python 程式、systemd 與環境檔模板 |
| AI / MCP | AI Risk Analysis Playbook、Governed Adapter 與受控預設值 |
| Remediation | 維護頁、solution 部署、修復驗證、恢復服務與 Lab Reset Playbook／Role |
| Review flow | Suspicious Login Review 記錄 Playbook |
| Dependencies | Ansible Collection requirements 與 Custom Runtime Image build definition |
| Student guide | Workflow、Activation、Lab 觸發與驗證步驟 |

`decision-environment/` 內的 `execution-environment.yml`、Python requirements 與 system dependencies 是 Governed Adapter 所需的 Custom Runtime Image build definition。課前需將建立完成的映像註冊為 AAP Execution Environment，並可同時作為 EDA Decision Environment 使用；學員不需要自行建立映像。

## Lab 1：Broken access control

```text
user1 存取 /admin
→ Forwarder 將事件送入 Event Stream
→ Rulebook 啟動 AI Risk Analysis
→ AI 透過受控 RHEL MCP 蒐集有限證據
→ AI 回送 repair_web_code 提案
→ Rulebook 啟動 Governed Web Remediation Workflow
→ 學員執行 Approval
→ AAP 部署 solution 並驗證修復
```

## Lab 2：Suspicious successful admin login

```text
admin 登入成功
→ Forwarder 喚醒 EDA
→ AI 透過 RHEL MCP 檢查最近 5 分鐘的登入紀錄
├─ admin 登入失敗至少 3 次：啟動 Suspicious Login Review Workflow
└─ 未達門檻：只記錄觀察結果，不啟動 Workflow
```

此情境只進行審查與紀錄，不鎖定帳號、不封鎖 IP，也不修改目標主機。

## AAP 執行入口

| 用途 | 路徑 |
|---|---|
| 部署 Event Stream Forwarder | `playbooks/deploy_forwarder.yml` |
| AI／MCP 調查 | `playbooks/eda_ai_risk_analysis.yml` |
| 記錄異常登入審查 | `playbooks/suspicious_login_review.yml` |
| 切換維護頁 | `playbooks/enable_maintenance_page.yml` |
| 部署修復版本 | `playbooks/sync_solution_from_git_and_deploy.yml` |
| 修復後、恢復服務前驗證 | `playbooks/verify_fixed_site_before_restore.yml` |
| 恢復正常登入頁 | `playbooks/restore_login_page.yml` |
| 驗證公開站台 | `playbooks/verify_fixed_site.yml` |
| 重設為 vulnerable start 版本 | `playbooks/sync_start_from_git_and_deploy.yml` |
| EDA Rulebook | `extensions/eda/rulebooks/cve_radar_authentication_anomaly.yml` |

相容性入口 `playbooks/ai_dispatch_remediation.yml` 與選用的 `playbooks/send_slack_alert.yml` 亦保留在專案中，但不屬於學員主要 Lab 操作路徑。

## 變數與 Credential 原則

Job Template 的 Extra Variables 預設可維持空白：

- 目標主機與 SSH：AAP Inventory 與 Machine Credential
- AI Model：AAP Custom Credential
- RHEL MCP：AAP Custom Credential
- Event Stream URL／Token：AAP Custom Credential
- 非敏感 AI 預設值：`playbooks/vars/ai_risk_analysis_defaults.yml`
- 非敏感 Remediation 預設值：`vars/project_defaults.yml`

只有 EDA 啟動 Job／Workflow 時產生的事件資料會以 Runtime Extra Variables 自動傳入，學員不需要手動貼入。

學員操作流程請參考 `docs/STUDENT_LAB.md`；事件格式請參考 `docs/event-schema.md`。
