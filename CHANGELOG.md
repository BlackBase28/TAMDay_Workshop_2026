# Changelog

## 1.9.5-slim26

- Fix Ansible Native Jinja converting `ntfy_payload_json` back into a dict,
  which caused `from_json` to fail with `the JSON object must be str, bytes or
  bytearray, not dict`.
- Render the ntfy JSON payload into a temporary file using
  `playbooks/templates/ntfy_payload.json.j2`.
- Validate the actual rendered file with `slurp` and `from_json`.
- Upload the validated file through `ansible.builtin.uri` `src`.
- Remove the temporary payload file through an `always` block.
- Preserve the existing Job Template Extra Variables and UTF-8-safe JSON
  fields.


## 1.9.5-slim26

- Fix ntfy HTTP 400 `request body must be valid JSON` errors.
- Stop relying on `ansible.builtin.uri` implicit `body_format: json`
  serialization.
- Build a structured payload, explicitly serialize it with
  `ansible.builtin.to_json(ensure_ascii=true, preprocess_unsafe=false)`, and
  validate it locally with `from_json`.
- Send the serialized JSON with `body_format: raw` and an ASCII-only
  `Content-Type: application/json` header.
- Preserve the complete `ntfy_url` Extra Variable and UTF-8 title/message
  support from slim24.


## 1.9.5-slim26

- Fix ntfy failures when Traditional Chinese titles are encoded as HTTP
  headers (`'latin-1' codec can't encode characters`).
- Switch the standalone ntfy Workflow Playbook to the official JSON publish
  API with UTF-8 title and message fields.
- Keep accepting a complete `ntfy_url` topic URL and derive the server root and
  topic automatically.
- Map `min`, `low`, `default`, `high`, `max`, and `urgent` to ntfy JSON
  priorities.
- Preserve slim23 explicit AI Model selection and raw response comparison.


## 1.9.5-slim26

- Remove the Project defaults for `ai_model_url` and `ai_model`; both must be
  selected explicitly by the AI Analysis Job Template or launch.
- Add `ai_show_model_responses` with a default of `true`.
- Add the dedicated `Show raw Model responses for comparison` Job Output task.
- Display planner/final raw provider responses with requested/provider model,
  rounds, content, provider-exposed reasoning content, tool calls, finish
  reason, usage, and raw response data.
- Publish the explicitly selected Model ID as `cve_radar_ai_model`.
- Preserve the slim22 GitHub baseline, standalone ntfy Workflow Playbook,
  governed MCP controls, and corrected dual Role paths.


## 1.9.5-slim26

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
