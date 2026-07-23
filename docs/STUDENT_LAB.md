# Student Lab Runtime Map

學員不需要修改 Repository 內的 Token 或密碼。SSH、AI Model、RHEL MCP 與 Event Stream 秘密均由 AAP Credential 注入。

## Lab 1

1. 啟用 Rulebook Activation。
2. 以 `user1` 登入並存取 `/admin`。
3. 確認 `CVE Radar - AI Risk Analysis` 啟動。
4. 在 `CVE Radar - Governed Web Remediation` 完成 Approval。
5. Workflow 依序執行維護、部署 solution、恢復與驗證。

## Lab 2

1. 連續輸入至少三次錯誤 admin 密碼。
2. 再以正確 admin 密碼登入。
3. 確認 AI 透過 RHEL MCP 讀取 `/var/log/kernel-cve-radar/auth-events.jsonl`。
4. 達門檻時檢查 `CVE Radar - Suspicious Login Review` 的調查摘要。
