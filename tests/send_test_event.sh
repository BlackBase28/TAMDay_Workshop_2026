#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  send_test_event.sh admin-access [user] [ip] [path]
  send_test_event.sh admin-login-success [ip]
  send_test_event.sh append-login-sequence [ip] [failure_count] [auth_log]
EOF
}

load_env() {
  local env_file="${EDA_TEST_ENV_FILE:-/etc/cve-radar-eda-forwarder.env}"
  if [[ -z "${EDA_EVENT_STREAM_URL:-}" || -z "${EDA_EVENT_STREAM_TOKEN:-}" ]]; then
    [[ -r "$env_file" ]] && { set -a; source "$env_file"; set +a; }
  fi
  : "${EDA_EVENT_STREAM_URL:?Set EDA_EVENT_STREAM_URL or provide $env_file}"
  : "${EDA_EVENT_STREAM_TOKEN:?Set EDA_EVENT_STREAM_TOKEN or provide $env_file}"
  EDA_EVENT_STREAM_HEADER="${EDA_EVENT_STREAM_HEADER:-${EDA_AUTH_HEADER:-X-CVE-Radar-Token}}"
  [[ "${EDA_VERIFY_TLS:-true}" == false ]] && EDA_CURL_INSECURE=true
}

post_event() {
  local payload="$1" args=(--fail-with-body --silent --show-error)
  [[ "${EDA_CURL_INSECURE:-false}" == true ]] && args+=(--insecure)
  curl "${args[@]}" -X POST "$EDA_EVENT_STREAM_URL" \
    -H 'Content-Type: application/json' \
    -H "${EDA_EVENT_STREAM_HEADER}: ${EDA_EVENT_STREAM_TOKEN}" \
    --data "$payload"
}

collector_hostname() {
  printf '%s' "${EDA_TEST_COLLECTOR_HOSTNAME:-${COLLECTOR_HOSTNAME:-$(hostname -f 2>/dev/null || hostname)}}"
}

admin_event() {
  local user="$1" ip="$2" path="$3"
  local ts id seq host
  ts="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
  id="admin-access-$(date +%s%3N)-${RANDOM}"
  seq="$(date +%s%3N)"
  host="$(collector_hostname)"
  post_event "$(cat <<JSON
{"schema_version":"kernel-cve-radar.event.v1","observed_at":"$ts","event_id":"$id","application":"kernel-cve-radar","event_type":"authorization","event_source":"application_auth_log","event_action":"admin_access","event_outcome":"allowed","username":"$user","user_role":"user","source_ip":"$ip","effective_source_ip":"$ip","url_path":"$path","status_code":200,"event_key":"kernel-cve-radar.authorization.admin.access","collector":{"name":"manual-test","version":"1.9.5-slim24","hostname":"$host","source_file":"/var/log/kernel-cve-radar/auth-events.jsonl","sequence":$seq}}
JSON
)"
}

admin_login_success_event() {
  local ip="$1"
  local ts id seq host
  ts="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
  id="admin-login-success-$(date +%s%3N)-${RANDOM}"
  seq="$(date +%s%3N)"
  host="$(collector_hostname)"
  post_event "$(cat <<JSON
{"schema_version":"kernel-cve-radar.event.v1","observed_at":"$ts","event_id":"$id","application":"kernel-cve-radar","event_type":"authentication","event_source":"application_auth_log","event_action":"login","event_outcome":"success","username":"admin","user_role":"admin","source_ip":"$ip","effective_source_ip":"$ip","url_path":"/login","status_code":200,"event_key":"kernel-cve-radar.authentication.admin.login.success","collector":{"name":"manual-test","version":"1.9.5-slim24","hostname":"$host","source_file":"/var/log/kernel-cve-radar/auth-events.jsonl","sequence":$seq}}
JSON
)"
}

append_auth_line() {
  local file="$1" line="$2"
  if [[ -w "$file" ]]; then
    printf '%s\n' "$line" >> "$file"
  else
    printf '%s\n' "$line" | sudo tee -a "$file" >/dev/null
  fi
}

append_login_sequence() {
  local ip="$1" failures="$2" log_file="$3"
  local i ts request_id
  for i in $(seq 1 "$failures"); do
    ts="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
    request_id="lab2-fail-$(date +%s%3N)-${i}-${RANDOM}"
    append_auth_line "$log_file" "{\"timestamp\":\"$ts\",\"event\":\"login_failure\",\"outcome\":\"failed\",\"user\":\"admin\",\"source_ip\":\"$ip\",\"path\":\"/login\",\"status\":401,\"reason\":\"invalid_credentials\",\"request_id\":\"$request_id\"}"
    sleep 0.4
  done
  ts="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
  request_id="lab2-success-$(date +%s%3N)-${RANDOM}"
  append_auth_line "$log_file" "{\"timestamp\":\"$ts\",\"event\":\"login_success\",\"outcome\":\"success\",\"user\":\"admin\",\"role\":\"admin\",\"source_ip\":\"$ip\",\"path\":\"/login\",\"status\":200,\"request_id\":\"$request_id\"}"
  echo "Appended $failures admin login failures followed by one admin login success to $log_file"
}

[[ $# -gt 0 ]] || { usage; exit 2; }
mode="$1"; shift
case "$mode" in
  admin-access|admin_access)
    load_env
    admin_event "${1:-user1}" "${2:-203.0.113.10}" "${3:-/admin}"
    ;;
  admin-login-success|admin_login_success)
    load_env
    admin_login_success_event "${1:-203.0.113.20}"
    ;;
  append-login-sequence|append_login_sequence)
    append_login_sequence \
      "${1:-203.0.113.20}" \
      "${2:-3}" \
      "${3:-/var/log/kernel-cve-radar/auth-events.jsonl}"
    ;;
  *) usage; exit 2 ;;
esac
