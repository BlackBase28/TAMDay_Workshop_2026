# TAM Day CVE Radar Workshop

Version: `1.9.5-slim28`

本專案提供 TAM Day Workshop 使用的 AAP / EDA / AI Runtime，示範事件偵測、
AI 分析、RHEL MCP 蒐證、受控修復與 ntfy 通知。

## Workshop 流程

### Lab 1：Broken Access Control

```text
異常存取 → EDA → AI Analysis + RHEL MCP → 受控修復 → 驗證
```

### Lab 2：Suspicious Admin Login

```text
管理員登入成功 → EDA → AI Analysis + RHEL MCP → 人工審查 → ntfy
```

Lab 2 僅進行分析與審查，不會自動鎖定帳號或封鎖 IP。

## 主要 Playbook

| 用途 | Playbook |
|---|---|
| 部署 Event Forwarder | `playbooks/deploy_forwarder.yml` |
| AI / MCP 分析 | `playbooks/eda_ai_risk_analysis.yml` |
| 可疑登入審查 | `playbooks/suspicious_login_review.yml` |
| 啟用維護頁 | `playbooks/enable_maintenance_page.yml` |
| 部署修復版本 | `playbooks/sync_solution_from_git_and_deploy.yml` |
| 恢復登入頁 | `playbooks/restore_login_page.yml` |
| 驗證修復 | `playbooks/verify_fixed_site.yml` |
| ntfy 通知 | `playbooks/send_ntfy_alert.yml` |

## AI Analysis 必要設定

專案不預設 AI Model 與 RHEL MCP 的連線位置，請從 AAP Job Template、
Credential、Survey 或 Launch Variables 提供：

```yaml
ai_model_url: "https://<model-endpoint>"
ai_model: "<model-id>"
rhel_mcp_url: "http://<rhel-mcp-host>:8000/mcp"
```

AI Analysis 的 Job Output 會顯示 Model 的分析結果，方便比較不同模型。

## ntfy

至少設定：

```yaml
ntfy_url: "https://ntfy.sh/<topic>"
```

若 Workflow 已帶入 AI 分析摘要，且沒有另外設定 `ntfy_message`，
ntfy 會直接使用該 AI 分析結果作為通知內容。

## 驗證

```bash
./tests/verify_project.sh
```
