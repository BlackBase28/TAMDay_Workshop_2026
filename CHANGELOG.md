# Changelog

## 1.0.2

- 將學員 Git Project 與封裝根目錄正式改名為 `TAMDay_Workshop`。
- 移除文件內舊的學員專案名稱。
- 重新檢查 Rulebook、Forwarder、AI/MCP Adapter、Remediation、Dependency 與學員操作文件的完整性。
- Runtime 邏輯維持 1.0.1，不變更 EDA 與 Remediation 的執行行為。

## 1.0.1

- 將課前 AAP Bootstrap API Script、AAP 物件定義與講師設定文件移出學員 Project。
- 學員 Project 僅保留 AAP 執行所需的 Rulebook、Playbook、Role、Dependency 與 Lab 文件。
- Runtime 邏輯維持 1.0.0：EDA `1.9.5-slim10`、Remediation `0.2.2`。

## 1.0.0

- 合併 EDA／AI investigation 與 governed remediation 為單一 Public Git Project。
- Forwarder 改用 AAP Inventory 與 Machine Credential。
- 將 `repair_web_code` 對應至受控的 solution 部署流程。
