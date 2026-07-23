#!/usr/bin/env python3
"""Run a bounded, read-only AI investigation through RHEL MCP.

The adapter validates Model and MCP responses, restricts tools and log reads,
and returns one normalized decision envelope. Technical dependency failures
are returned as fail-closed error envelopes for the AAP Playbook to stop on.
"""

from __future__ import annotations

import ast
import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
import re
import sys
import traceback
from typing import Any

import httpx

try:
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client
except Exception:  # pragma: no cover - allows fallback envelope if EE is incomplete
    ClientSession = None  # type: ignore[assignment]
    streamablehttp_client = None  # type: ignore[assignment]

ALLOWED_ASSESSMENTS = {
    "insufficient_context",
    "likely_user_error",
    "suspicious",
    "highly_suspicious",
}
ALLOWED_INCIDENT_TYPES = {
    "unknown",
    "user_error",
    "broken_access_control",
    "admin_content_exposure",
    "suspicious_login_success",
    "possible_account_compromise",
}
ALLOWED_NEXT_STEPS = {
    "observe",
    "collect_more_evidence",
    "alert",
    "require_approval",
    "repair_web_code",
}
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}
DEFAULT_ALLOWED_MCP_TOOLS = {
    "read_log_file",
    "get_journal_logs",
    "get_service_status",
}
LOG_LINE_ARGUMENT_KEYS = (
    "lines",
    "tail_lines",
    "max_lines",
    "limit",
    "count",
    "n",
    "num_lines",
    "entries",
    "max_entries",
)
HOST_ARGUMENT_KEYS = ("host", "hostname", "target_host", "server")
PATH_ARGUMENT_KEYS = ("path", "log_path", "file", "filename")
WRITE_LIKE_PATTERNS = re.compile(
    r"\b(rm|mv|cp|chmod|chown|truncate|dd|mkfs|reboot|shutdown|systemctl\s+(restart|stop|start|disable|enable)|"
    r"firewall-cmd|iptables|nft|podman\s+(rm|stop|kill)|sed\s+-i|tee\s+|>|>>|curl\s+.*(-X\s+POST|-X\s+PUT|-X\s+DELETE))\b",
    re.IGNORECASE,
)
JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)
THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def as_bool(value: str | None, default: bool = True) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def bounded_int(value: str | int | None, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value) if value not in (None, "") else default
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def bounded_float(
    value: str | float | int | None,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    try:
        parsed = float(value) if value not in (None, "") else default
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def configured_allowed_tools() -> set[str]:
    raw = os.getenv("GOVERNED_ALLOWED_MCP_TOOLS", "").strip()
    if not raw:
        return set(DEFAULT_ALLOWED_MCP_TOOLS)
    return {item.strip() for item in raw.split(",") if item.strip()}


def configured_evidence_loop() -> dict[str, Any]:
    per_round_raw = os.getenv("GOVERNED_MAX_TOOL_CALLS_PER_ROUND", "").strip()
    if not per_round_raw:
        per_round_raw = os.getenv("GOVERNED_MAX_TOOL_CALLS", "4")
    per_round = bounded_int(per_round_raw, 4, 1, 8)
    max_rounds = bounded_int(os.getenv("GOVERNED_MAX_INVESTIGATION_ROUNDS"), 3, 1, 5)
    total_calls = bounded_int(os.getenv("GOVERNED_MAX_TOTAL_TOOL_CALLS"), 10, 1, 20)
    total_calls = max(per_round, total_calls)
    try:
        min_confidence = float(os.getenv("GOVERNED_MIN_CONFIDENCE_FOR_ACTION", "0.60"))
    except ValueError:
        min_confidence = 0.60
    min_confidence = min(1.0, max(0.0, min_confidence))
    return {
        "enabled": as_bool(os.getenv("GOVERNED_EVIDENCE_LOOP_ENABLED"), True),
        "max_rounds": max_rounds,
        "max_tool_calls_per_round": per_round,
        "max_total_tool_calls": total_calls,
        "min_confidence_for_action": min_confidence,
    }


def build_log_policy(request: dict[str, Any]) -> dict[str, dict[str, Any]]:
    investigation = request.get("investigation", {}) if isinstance(request, dict) else {}
    max_lines = bounded_int(os.getenv("GOVERNED_MAX_LOG_LINES"), 60, 1, 200)
    model_can_override = as_bool(os.getenv("GOVERNED_MODEL_CAN_OVERRIDE_LINES"), False)
    entries = (
        (
            str(investigation.get("auth_log_path", "/var/log/kernel-cve-radar/auth-events.jsonl")),
            bounded_int(os.getenv("GOVERNED_AUTH_LOG_TAIL_LINES"), 30, 1, max_lines),
        ),
        (
            str(investigation.get("web_access_log_path", "/var/log/httpd/access_log")),
            bounded_int(os.getenv("GOVERNED_ACCESS_LOG_TAIL_LINES"), 60, 1, max_lines),
        ),
        (
            str(investigation.get("web_error_log_path", "/var/log/httpd/error_log")),
            bounded_int(os.getenv("GOVERNED_ERROR_LOG_TAIL_LINES"), 30, 1, max_lines),
        ),
    )
    return {
        path: {
            "default_tail_lines": default_lines,
            "max_lines": max_lines,
            "model_can_override_lines": model_can_override,
        }
        for path, default_lines in entries
        if path
    }


def _tail_json_value(value: Any, line_limit: int) -> Any:
    if isinstance(value, list):
        return [_tail_json_value(item, line_limit) for item in value[-line_limit:]]
    if isinstance(value, dict):
        return {str(key): _tail_json_value(item, line_limit) for key, item in value.items()}
    if isinstance(value, str) and "\n" in value:
        return "\n".join(value.splitlines()[-line_limit:])
    return value


def tail_text(text: str, line_limit: int, char_limit: int = 12000) -> str:
    source = text or ""
    try:
        parsed = json.loads(source)
    except (json.JSONDecodeError, TypeError):
        bounded = "\n".join(source.splitlines()[-max(1, line_limit):])
    else:
        bounded = json.dumps(_tail_json_value(parsed, max(1, line_limit)), ensure_ascii=False, default=str)
    if len(bounded) > char_limit:
        bounded = bounded[-char_limit:]
        return "...[leading tool output removed by governed adapter]\n" + bounded
    return bounded


def configured_evidence_limits() -> dict[str, int]:
    return {
        "tool_result_max_chars": bounded_int(
            os.getenv("GOVERNED_TOOL_RESULT_MAX_CHARS"), 4000, 500, 12000
        ),
        "max_evidence_chars": bounded_int(
            os.getenv("GOVERNED_MAX_EVIDENCE_CHARS"), 12000, 2000, 50000
        ),
    }


def _tail_chars(text: str, limit: int, marker: str) -> str:
    if len(text) <= limit:
        return text
    keep = max(1, limit - len(marker))
    return marker + text[-keep:]


def compact_evidence_for_model(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Bound MCP evidence sent to the Model while preserving record metadata."""
    limits = configured_evidence_limits()
    per_result = limits["tool_result_max_chars"]
    total_limit = limits["max_evidence_chars"]

    def compact_records(result_budget: int) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for original in evidence:
            if not isinstance(original, dict):
                records.append({"result": str(original)[:result_budget]})
                continue
            record = dict(original)
            # Parsed records are Adapter-only machine evidence.  Do not duplicate
            # them into the Model prompt; the bounded display result remains the
            # Model-visible source.
            record.pop("parsed_log_records", None)
            if isinstance(record.get("result"), str):
                record["result"] = _tail_chars(
                    record["result"],
                    result_budget,
                    "...[earlier evidence omitted]\n",
                )
            if isinstance(record.get("error"), str):
                record["error"] = record["error"][:600]
            records.append(record)
        return records

    budget = per_result
    compact = compact_records(budget)
    for _ in range(8):
        serialized = json.dumps(compact, ensure_ascii=False, default=str)
        if len(serialized) <= total_limit:
            return compact
        if budget <= 300:
            break
        budget = max(300, int(budget * 0.65))
        compact = compact_records(budget)

    omitted = 0
    while len(compact) > 2 and len(
        json.dumps(compact, ensure_ascii=False, default=str)
    ) > total_limit:
        compact.pop(1)
        omitted += 1
    if omitted:
        compact.insert(1, {"evidence_records_omitted": omitted})

    serialized = json.dumps(compact, ensure_ascii=False, default=str)
    if len(serialized) <= total_limit:
        return compact
    return [
        {
            "evidence_truncated": True,
            "original_record_count": len(evidence),
            "preview": serialized[: max(500, total_limit - 200)],
        }
    ]


SENSITIVE_KEY_RE = re.compile(
    r"(^|[_-])(authorization|access[_-]?token|refresh[_-]?token|token|api[_-]?key|apikey|password|passwd|secret|cookie|credential)([_-]|$)",
    re.IGNORECASE,
)
BEARER_RE = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+\-/=]+")
INLINE_SECRET_RE = re.compile(
    r"""(?ix)
    (authorization|api[_-]?key|apikey|password|passwd|secret|access[_-]?token|
     refresh[_-]?token|token|cookie|credential)
    (\s*[:=]\s*)
    ("[^"]*"|'[^']*'|[^\s,;}}]+)
    """,
)


def _trace_max_chars() -> int:
    try:
        value = int(os.getenv("GOVERNED_TRACE_MAX_CHARS", "12000"))
    except ValueError:
        value = 12000
    return max(1000, min(50000, value))


def _redact_trace_value(value: Any, key_hint: str = "") -> Any:
    if key_hint and SENSITIVE_KEY_RE.search(key_hint):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(key): _redact_trace_value(item, str(key)) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_trace_value(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_trace_value(item) for item in value]
    if isinstance(value, str):
        masked = BEARER_RE.sub(r"\1<redacted>", value)
        stripped = masked.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (
            stripped.startswith("[") and stripped.endswith("]")
        ):
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                pass
            else:
                return _redact_trace_value(parsed)
        return INLINE_SECRET_RE.sub(r"\1\2<redacted>", masked)
    return value


def emit_trace(stage: str, data: Any) -> None:
    """Emit one sanitized JSON trace record without exposing credentials."""
    if not as_bool(os.getenv("GOVERNED_DEBUG_TRACE"), False):
        return
    sanitized = _redact_trace_value(data)
    serialized = json.dumps(sanitized, ensure_ascii=False, default=str)
    max_chars = _trace_max_chars()
    if len(serialized) > max_chars:
        sanitized = {
            "truncated": True,
            "original_length": len(serialized),
            "preview": serialized[:max_chars] + "...[trace truncated]",
        }
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "data": sanitized,
    }
    line = json.dumps(record, ensure_ascii=False, default=str)
    trace_file = os.getenv("GOVERNED_TRACE_FILE", "").strip()
    if trace_file:
        try:
            with open(trace_file, "a", encoding="utf-8") as stream:
                stream.write(line + "\n")
            try:
                os.chmod(trace_file, 0o600)
            except OSError:
                pass
            return
        except OSError as exc:
            print(
                "CVE_RADAR_TRACE_WARNING="
                + json.dumps({"stage": stage, "error": str(exc)}, ensure_ascii=False),
                file=sys.stderr,
                flush=True,
            )
    print("CVE_RADAR_TRACE=" + line, file=sys.stderr, flush=True)


def fail_envelope(reason: str, request: dict[str, Any] | None = None, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    trigger = (request or {}).get("trigger_event", {}) if isinstance(request, dict) else {}
    return {
        "assessment": "insufficient_context",
        "incident_type": "unknown",
        "confidence": 0.35,
        "recommended_next_step": "collect_more_evidence",
        "reason": reason,
        "evidence": evidence or {
            "adapter_error": reason,
            "trigger_event_key": trigger.get("event_key", "unknown") if isinstance(trigger, dict) else "unknown",
        },
        "mcp_tools_used": [],
    }


def extract_json_object(text: str) -> dict[str, Any] | None:
    clean = THINK_RE.sub("", text or "").strip()
    clean = re.sub(r"^```(?:json)?\s*", "", clean, flags=re.IGNORECASE).strip()
    clean = re.sub(r"\s*```$", "", clean).strip()
    candidates = []
    start = None
    depth = 0
    in_string = False
    escaped = False
    for idx, char in enumerate(clean):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                start = idx
            depth += 1
        elif char == "}":
            if depth:
                depth -= 1
                if depth == 0 and start is not None:
                    candidates.append(clean[start : idx + 1])
                    start = None
    if not candidates:
        match = JSON_OBJECT_RE.search(clean)
        if match:
            candidates.append(match.group(0))
    for candidate in candidates:
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
    return None



def configured_structured_admin_policy() -> dict[str, Any]:
    """Return the bounded policy for first-party admin authorization events."""
    try:
        confidence_floor = float(os.getenv("GOVERNED_ADMIN_TRIGGER_CONFIDENCE_FLOOR", "0.85"))
    except ValueError:
        confidence_floor = 0.85
    return {
        "enabled": as_bool(os.getenv("GOVERNED_TRUST_STRUCTURED_ADMIN_TRIGGER"), True),
        "confidence_floor": min(0.95, max(0.70, confidence_floor)),
    }


def _first_text(mapping: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return str(value).strip()
    return ""


def evaluate_structured_admin_trigger(request: dict[str, Any] | None) -> dict[str, Any]:
    """Validate a complete first-party non-admin /admin success event.

    Apache access logs are supplementary evidence because they normally do not
    carry the authenticated application username or role. A complete structured
    application authorization event is therefore allowed to establish a bounded
    confidence floor without relying on the web access log containing the same
    request.
    """
    trigger = request.get("trigger_event", {}) if isinstance(request, dict) else {}
    if not isinstance(trigger, dict):
        return {"matched": False}

    event_key = _first_text(trigger, "event_key")
    username = _first_text(trigger, "username", "user")
    role = _first_text(trigger, "user_role", "role").lower()
    path = _first_text(trigger, "http_path", "url_path", "path")
    outcome = _first_text(trigger, "event_outcome", "result", "outcome").lower()
    source_ip = _first_text(trigger, "effective_source_ip", "source_ip", "ip")

    matched = (
        event_key in {
            "kernel-cve-radar.authorization.admin.access",
            "kernel-cve-radar.authorization.admin_content.exposure",
        }
        and bool(username)
        and bool(role)
        and role not in {"admin", "administrator"}
        and (path == "/admin" or path.startswith("/admin/"))
        and outcome in {"allowed", "allow", "success", "succeeded"}
    )
    return {
        "matched": matched,
        "event_key": event_key,
        "username": username,
        "user_role": role,
        "path": path,
        "outcome": outcome,
        "source_ip": source_ip,
    }


def evaluate_structured_admin_login_success(request: dict[str, Any] | None) -> dict[str, Any]:
    """Validate the Lab 2 wake-up event without treating it as a verdict."""
    trigger = request.get("trigger_event", {}) if isinstance(request, dict) else {}
    if not isinstance(trigger, dict):
        return {"matched": False}
    event_key = _first_text(trigger, "event_key")
    username = _first_text(trigger, "username", "user")
    role = _first_text(trigger, "user_role", "role").lower()
    source_ip = _first_text(trigger, "effective_source_ip", "source_ip", "ip")
    outcome = _first_text(trigger, "event_outcome", "outcome", "result").lower()
    success_at = _first_text(trigger, "success_at", "observed_at", "timestamp")
    matched = (
        event_key == "kernel-cve-radar.authentication.admin.login.success"
        and username.lower() in {"admin", "administrator"}
        and role in {"", "admin", "administrator"}
        and outcome in {"success", "successful", "succeeded", "allowed"}
        and bool(success_at)
    )
    return {
        "matched": matched,
        "event_key": event_key,
        "username": username,
        "user_role": role,
        "source_ip": source_ip,
        "outcome": outcome,
        "success_at": success_at,
    }


def _parse_iso_datetime(value: Any) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iter_log_records(value: Any):
    """Yield JSON-like records from nested, JSONL, or text-wrapped MCP output.

    MCP transports may return native structured content, JSON strings, Python
    ``repr`` strings, Markdown-wrapped JSONL, or a character-truncated outer
    JSON object whose embedded log lines remain backslash escaped.  Parse each
    representation deterministically so governed counting sees the same bounded
    Auth Log evidence that is visible to the Model.
    """
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _iter_log_records(child)
        return
    if isinstance(value, list):
        for child in value:
            yield from _iter_log_records(child)
        return
    if not isinstance(value, str):
        return
    raw = value.strip()
    if not raw:
        return

    # First prefer strict JSON, then a safe Python-literal fallback used by
    # some MCP/FastMCP result renderers.
    for parser in (json.loads, ast.literal_eval):
        try:
            parsed = parser(raw)
        except (json.JSONDecodeError, ValueError, SyntaxError, TypeError):
            continue
        else:
            if parsed != raw:
                yield from _iter_log_records(parsed)
                return

    decoder = json.JSONDecoder()

    def scan(text: str) -> bool:
        decoded_any = False
        cursor = 0
        while cursor < len(text):
            object_positions = [pos for pos in (text.find("{", cursor), text.find("[", cursor)) if pos >= 0]
            if not object_positions:
                break
            start = min(object_positions)
            try:
                parsed_value, finish = decoder.raw_decode(text, start)
            except json.JSONDecodeError:
                cursor = start + 1
                continue
            decoded_any = True
            yield from _iter_log_records(parsed_value)
            cursor = max(finish, start + 1)
        return decoded_any

    decoded = yield from scan(raw)
    if decoded:
        return

    # When the outer structuredContent JSON was truncated, embedded JSONL can
    # remain as escaped fragments such as {\"ts\":...}.  Unescape one layer
    # and scan again without evaluating arbitrary code.
    if '\\"' in raw or '\\n' in raw or '\\t' in raw:
        unescaped = (
            raw.replace('\\"', '"')
            .replace('\\n', '\n')
            .replace('\\t', '\t')
            .replace('\\r', '\r')
        )
        if unescaped != raw:
            yield from scan(unescaped)


def _looks_like_log_record(record: dict[str, Any]) -> bool:
    """Return true for an application log record rather than a wrapper object."""
    if not isinstance(record, dict):
        return False
    timestamp_present = any(key in record for key in ("observed_at", "timestamp", "ts", "@timestamp"))
    event_present = any(
        key in record
        for key in (
            "event_key", "event", "event_type", "event_action", "event_outcome",
            "outcome", "status", "status_code", "path", "url_path", "message",
        )
    )
    identity_present = any(
        key in record
        for key in (
            "username", "user", "login_user", "remote_user", "source_ip",
            "effective_source_ip", "ip", "request_id", "event_id",
        )
    )
    return bool(timestamp_present and (event_present or identity_present))


def extract_log_records_from_tool_result(result: Any, max_records: int = 200) -> list[dict[str, Any]]:
    """Extract bounded machine-readable records before display serialization.

    This runs before the 4,000-character Model evidence cap is applied.  It
    prevents a truncated outer ``structuredContent`` object from turning valid
    Auth Log evidence into a false zero count.
    """
    payloads: list[Any] = []
    structured = getattr(result, "structuredContent", None)
    if structured is not None:
        payloads.append(structured)
    for item in getattr(result, "content", []) or []:
        if hasattr(item, "text"):
            payloads.append(str(item.text))
        elif hasattr(item, "model_dump"):
            payloads.append(item.model_dump())
        else:
            payloads.append(str(item))

    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for payload in payloads:
        for record in _iter_log_records(payload):
            if not _looks_like_log_record(record):
                continue
            fingerprint = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            records.append(record)
            if len(records) >= max_records:
                return records
    return records

def _record_is_login_failure(record: dict[str, Any]) -> bool:
    key = _first_text(record, "event_key", "key")
    event = _first_text(record, "event", "name").lower()
    event_type = _first_text(record, "event_type", "type").lower()
    action = _first_text(record, "event_action", "action").lower()
    path = _first_text(record, "url_path", "path", "uri", "request_path").split("?", 1)[0].lower()
    outcome = _first_text(record, "event_outcome", "outcome", "result").lower()
    try:
        status = int(record.get("status_code", record.get("status", 0)) or 0)
    except (TypeError, ValueError):
        status = 0
    explicit_login = (
        key == "kernel-cve-radar.authentication.login.failure"
        or event in {"login_failure", "login_failed", "failed_login"}
        or path in {"/login", "/api/login"}
        or (event_type in {"authentication", "auth", "login"} and action in {"login", "authenticate", "authentication"})
    )
    failed = (
        key == "kernel-cve-radar.authentication.login.failure"
        or event in {"login_failure", "login_failed", "failed_login"}
        or outcome in {"deny", "denied", "fail", "failed", "failure", "invalid", "invalid_credentials", "unauthorized"}
        or status in {401, 403}
    )
    return explicit_login and failed


def evaluate_recent_admin_login_failures(
    request: dict[str, Any] | None,
    mcp_evidence: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Count admin login failures in the five minutes before the success event."""
    trigger = evaluate_structured_admin_login_success(request)
    if not trigger.get("matched"):
        return {"matched": False, "evidence_sufficient": False}

    investigation = request.get("investigation", {}) if isinstance(request, dict) else {}
    detection = request.get("detection_context", {}) if isinstance(request, dict) else {}
    try:
        lookback_minutes = int(investigation.get("lookback_minutes", 5))
    except (TypeError, ValueError):
        lookback_minutes = 5
    lookback_minutes = max(1, min(60, lookback_minutes))
    try:
        threshold = int(detection.get("detection_threshold", 3))
    except (TypeError, ValueError):
        threshold = 3
    threshold = max(1, threshold)

    success_dt = _parse_iso_datetime(trigger.get("success_at"))
    if success_dt is None:
        return {**trigger, "matched": True, "evidence_sufficient": False, "failure_count": None}
    window_start = success_dt - timedelta(minutes=lookback_minutes)
    auth_path = str(investigation.get("auth_log_path", "/var/log/kernel-cve-radar/auth-events.jsonl"))

    failures: list[dict[str, Any]] = []
    seen: set[str] = set()
    auth_log_read = False
    for evidence_record in mcp_evidence or []:
        if not isinstance(evidence_record, dict) or evidence_record.get("tool") != "read_log_file":
            continue
        arguments = evidence_record.get("arguments", {})
        if not isinstance(arguments, dict):
            continue
        path = _first_text(arguments, "path", "log_path", "file", "filename")
        if path != auth_path or "result" not in evidence_record:
            continue
        parsed_records = evidence_record.get("parsed_log_records")
        parse_status = str(evidence_record.get("log_record_parse_status", "") or "")
        if isinstance(parsed_records, list):
            candidate_records = [item for item in parsed_records if isinstance(item, dict)]
            auth_log_read = parse_status in {"parsed", "parsed_empty"} or bool(candidate_records)
        else:
            candidate_records = [
                item for item in _iter_log_records(evidence_record.get("result"))
                if isinstance(item, dict) and _looks_like_log_record(item)
            ]
            # A successful non-empty Auth Log read that yields no parseable log
            # records is insufficient evidence, not proof of zero failures.
            raw_result = str(evidence_record.get("result", "") or "").strip()
            auth_log_read = bool(candidate_records) or not raw_result
        for record in candidate_records:
            username = _first_text(record, "username", "user", "login_user", "remote_user")
            if username.lower() != str(trigger.get("username", "")).lower():
                continue
            if not _record_is_login_failure(record):
                continue
            observed = _parse_iso_datetime(
                record.get("observed_at", record.get("timestamp", record.get("ts", record.get("@timestamp"))))
            )
            if observed is None or observed < window_start or observed >= success_dt:
                continue
            source_ip = _first_text(record, "effective_source_ip", "source_ip", "client_ip", "remote_addr", "ip")
            identity = _first_text(record, "event_id", "request_id") or json.dumps(
                [observed.isoformat(), username, source_ip, _first_text(record, "failure_reason", "reason", "message")],
                ensure_ascii=False,
            )
            if identity in seen:
                continue
            seen.add(identity)
            failures.append(
                {
                    "timestamp": observed.isoformat().replace("+00:00", "Z"),
                    "username": username,
                    "source_ip": source_ip,
                    "failure_reason": _first_text(record, "failure_reason", "reason", "message", "error"),
                }
            )

    return {
        **trigger,
        "matched": True,
        "evidence_sufficient": auth_log_read,
        "failure_count": len(failures) if auth_log_read else None,
        "failure_threshold": threshold,
        "lookback_minutes": lookback_minutes,
        "window_start": window_start.isoformat().replace("+00:00", "Z"),
        "window_end": success_dt.isoformat().replace("+00:00", "Z"),
        "failures": failures,
    }


def _admin_login_evidence_summary(
    admin_login: dict[str, Any],
    failure_count: int | None,
    threshold: int,
) -> list[str]:
    """Build one Adapter-authoritative Lab 2 summary without Model conflicts."""
    lookback = int(admin_login.get("lookback_minutes", 5) or 5)
    success_at = str(admin_login.get("success_at", "") or "")
    failures = admin_login.get("failures", [])
    if not isinstance(failures, list):
        failures = []

    if failure_count is None:
        summary = [
            f"admin 已於 {success_at} 登入成功，但目前無法從 Auth Log 計算成功前 {lookback} 分鐘內的登入失敗次數。"
        ]
    elif failure_count >= threshold:
        summary = [
            f"admin 登入成功前 {lookback} 分鐘內找到 {failure_count} 次登入失敗，已達 {threshold} 次門檻。"
        ]
    else:
        summary = [
            f"admin 登入成功前 {lookback} 分鐘內只找到 {failure_count} 次登入失敗，未達 {threshold} 次門檻。"
        ]

    if success_at:
        summary.append(f"成功登入時間: {success_at}")
    timestamps = [str(item.get("timestamp", "")).strip() for item in failures if isinstance(item, dict)]
    timestamps = [item for item in timestamps if item]
    if timestamps:
        summary.append("登入失敗時間: " + ", ".join(timestamps))
    reasons = []
    ips = []
    trigger_ip = str(admin_login.get("source_ip", "") or "").strip()
    if trigger_ip:
        ips.append(trigger_ip)
    for item in failures:
        if not isinstance(item, dict):
            continue
        reason = str(item.get("failure_reason", "") or "").strip()
        source_ip = str(item.get("source_ip", "") or "").strip()
        if reason and reason not in reasons:
            reasons.append(reason)
        if source_ip and source_ip not in ips:
            ips.append(source_ip)
    if reasons:
        summary.append("失敗原因: " + ", ".join(reasons))
    if ips:
        summary.append("登入來源 IP: " + ", ".join(ips))
    return summary


def _model_reported_failure_count(value: dict[str, Any]) -> int | None:
    evidence = value.get("evidence", {})
    if not isinstance(evidence, dict):
        return None
    for key in (
        "recent_admin_login_failure_count",
        "admin_login_failure_count",
        "recent_failed_login_count",
        "failed_login_count",
        "failure_count",
    ):
        if key not in evidence:
            continue
        try:
            return max(0, int(evidence[key]))
        except (TypeError, ValueError):
            continue
    return None



def normalize_envelope(
    value: dict[str, Any],
    used_tools: list[str],
    *,
    min_confidence_for_action: float | None = None,
    request: dict[str, Any] | None = None,
    mcp_evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    assessment = str(value.get("assessment", "insufficient_context")).strip().lower()
    incident_type = str(value.get("incident_type", "unknown")).strip().lower()
    next_step = str(value.get("recommended_next_step", "collect_more_evidence")).strip().lower()
    severity = str(value.get("severity", "medium")).strip().lower()

    assessment_aliases = {
        "中等信心": "suspicious",
        "低信心": "insufficient_context",
        "高信心": "highly_suspicious",
    }
    assessment = assessment_aliases.get(assessment, assessment)
    if assessment not in ALLOWED_ASSESSMENTS:
        assessment = "insufficient_context"
    if incident_type not in ALLOWED_INCIDENT_TYPES:
        incident_type = "unknown"
    next_step_aliases = {
        "collect_more_data": "collect_more_evidence",
        "collect_additional_evidence": "collect_more_evidence",
    }
    next_step = next_step_aliases.get(next_step, next_step)
    if next_step not in ALLOWED_NEXT_STEPS:
        next_step = "collect_more_evidence"
    if severity not in ALLOWED_SEVERITIES:
        severity = "medium"

    raw_confidence = value.get("confidence", 0.35)
    confidence_aliases = {
        "low": 0.35,
        "medium": 0.60,
        "high": 0.85,
        "低": 0.35,
        "中": 0.60,
        "高": 0.85,
    }
    try:
        confidence = float(confidence_aliases.get(str(raw_confidence).strip().lower(), raw_confidence))
    except (TypeError, ValueError):
        confidence = 0.35
    confidence = min(1.0, max(0.0, confidence))

    evidence = value.get("evidence", {})
    if not isinstance(evidence, dict):
        evidence = {"raw_evidence": evidence}
    evidence_summary = value.get("evidence_summary", [])
    if isinstance(evidence_summary, str):
        evidence_summary = [evidence_summary]
    if not isinstance(evidence_summary, list):
        evidence_summary = []
    source_ips = value.get("source_ips", [])
    if isinstance(source_ips, str):
        source_ips = [source_ips]
    if not isinstance(source_ips, list):
        source_ips = []
    affected_user = str(value.get("affected_user", "") or "")
    reason = str(value.get("reason") or "AI did not provide a reason. Treating the result conservatively.")

    evidence_gaps = value.get("evidence_gaps", [])
    if isinstance(evidence_gaps, str):
        evidence_gaps = [evidence_gaps]
    if not isinstance(evidence_gaps, list):
        evidence_gaps = []

    raw_requests = value.get("additional_evidence_requests", [])
    if not isinstance(raw_requests, list):
        raw_requests = []
    additional_requests: list[dict[str, Any]] = []
    for item in raw_requests[:10]:
        if not isinstance(item, dict):
            continue
        tool = str(item.get("tool", "")).strip()
        arguments = item.get("arguments", {})
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                arguments = {}
        if tool and isinstance(arguments, dict):
            additional_requests.append({"tool": tool, "arguments": arguments})

    if min_confidence_for_action is None:
        try:
            min_confidence_for_action = float(os.getenv("GOVERNED_MIN_CONFIDENCE_FOR_ACTION", "0.60"))
        except ValueError:
            min_confidence_for_action = 0.60
    min_confidence_for_action = min(1.0, max(0.0, float(min_confidence_for_action)))

    governance_policy_applied: list[str] = []
    structured_policy = configured_structured_admin_policy()
    structured_admin = evaluate_structured_admin_trigger(request)
    admin_login = evaluate_recent_admin_login_failures(request, mcp_evidence)

    if structured_policy["enabled"] and structured_admin.get("matched"):
        # A complete application-generated authorization event is first-party
        # evidence. Apache logs are only supplementary and their absence must not
        # negate the authenticated username, role, path, and allowed outcome.
        assessment = "highly_suspicious"
        incident_type = "broken_access_control"
        confidence = max(confidence, float(structured_policy["confidence_floor"]))
        severity = "high"
        next_step = "repair_web_code"
        affected_user = structured_admin["username"]
        if structured_admin.get("source_ip") and structured_admin["source_ip"] not in source_ips:
            source_ips.insert(0, structured_admin["source_ip"])
        direct_summary = (
            f"結構化應用程式授權事件確認一般角色 {structured_admin['user_role']} 的使用者 "
            f"{structured_admin['username']} 成功存取 {structured_admin['path']}。"
        )
        if direct_summary not in evidence_summary:
            evidence_summary.insert(0, direct_summary)
        evidence = dict(evidence)
        evidence["structured_admin_trigger"] = {
            "event_key": structured_admin["event_key"],
            "username": structured_admin["username"],
            "user_role": structured_admin["user_role"],
            "path": structured_admin["path"],
            "outcome": structured_admin["outcome"],
            "source_ip": structured_admin.get("source_ip", ""),
            "confidence_floor": structured_policy["confidence_floor"],
        }
        evidence_gaps = []
        additional_requests = []
        reason = (
            f"第一方結構化授權事件已確認非管理者 {structured_admin['username']} "
            f"以角色 {structured_admin['user_role']} 成功存取 {structured_admin['path']}；"
            "Apache access log 未出現相同請求只能視為缺少額外佐證，不能推翻此應用程式事件。"
        )
        governance_policy_applied.append("structured_admin_trigger_confidence_floor")
    elif admin_login.get("matched"):
        model_count = _model_reported_failure_count(value)
        evidence_sufficient = bool(admin_login.get("evidence_sufficient"))
        failure_count = admin_login.get("failure_count") if evidence_sufficient else model_count
        threshold = int(admin_login.get("failure_threshold", 3))
        affected_user = str(admin_login.get("username", ""))
        if admin_login.get("source_ip") and admin_login["source_ip"] not in source_ips:
            source_ips.insert(0, admin_login["source_ip"])
        evidence = dict(evidence)
        if evidence_sufficient and model_count is not None and int(model_count) != int(failure_count):
            evidence["model_adapter_failure_count_mismatch"] = {
                "model_reported": int(model_count),
                "adapter_counted": int(failure_count),
            }
            governance_policy_applied.append("adapter_auth_log_count_overrides_model_count")
        evidence["recent_admin_login_check"] = {
            "username": affected_user,
            "success_at": admin_login.get("success_at", ""),
            "lookback_minutes": admin_login.get("lookback_minutes", 5),
            "window_start": admin_login.get("window_start", ""),
            "window_end": admin_login.get("window_end", ""),
            "failure_threshold": threshold,
            "failure_count": failure_count,
            "failures": admin_login.get("failures", []),
            "count_source": "adapter_mcp_evidence" if evidence_sufficient else ("model_evidence" if model_count is not None else "unavailable"),
        }
        # Lab 2 evidence_summary is rebuilt from governed Auth Log evidence.
        # Never append Adapter findings to a potentially contradictory Model list.
        evidence_summary = _admin_login_evidence_summary(admin_login, failure_count, threshold)
        for failure in admin_login.get("failures", []):
            if not isinstance(failure, dict):
                continue
            failure_ip = str(failure.get("source_ip", "") or "")
            if failure_ip and failure_ip not in source_ips:
                source_ips.append(failure_ip)

        if failure_count is None:
            assessment = "insufficient_context"
            incident_type = "unknown"
            confidence = min(confidence, 0.50)
            next_step = "collect_more_evidence"
            reason = (
                "admin 已成功登入，但目前無法從 MCP 證據確認成功前五分鐘內的登入失敗次數；"
                "需要重新讀取 authentication log，不能只根據登入成功事件判定異常。"
            )
            evidence_gaps = ["缺少可計數的最近五分鐘 admin 登入失敗紀錄"]
            governance_policy_applied.append("admin_login_trigger_requires_mcp_evidence")
        elif int(failure_count) >= threshold:
            assessment = "suspicious" if assessment != "highly_suspicious" else assessment
            incident_type = (
                incident_type
                if incident_type in {"suspicious_login_success", "possible_account_compromise"}
                else "suspicious_login_success"
            )
            confidence = max(confidence, 0.75)
            severity = "high" if severity in {"high", "critical"} else "medium"
            next_step = "require_approval"
            summary = evidence_summary[0]
            additional_requests = []
            reason = (
                summary
                + " 此情境只提出人工審核，不自動鎖定帳號、封鎖來源或修改系統。 "
                + reason
            ).strip()
            governance_policy_applied.append("admin_login_recent_failures_requires_human_review")
        else:
            assessment = "likely_user_error"
            incident_type = "user_error"
            confidence = max(confidence, 0.75)
            severity = "low"
            next_step = "observe"
            summary = evidence_summary[0]
            evidence_gaps = []
            additional_requests = []
            reason = summary + " 不建立 Review Workflow，僅保留本次 AI 調查紀錄。"
            governance_policy_applied.append("admin_login_below_failure_threshold_observe")
    else:
        # Conservative action guardrails. Only broken access control may propose
        # an automated remediation. Login investigations remain review-only.
        if assessment == "insufficient_context" or confidence < min_confidence_for_action:
            next_step = "collect_more_evidence"
        elif next_step == "repair_web_code" and incident_type not in {"broken_access_control", "admin_content_exposure"}:
            next_step = "require_approval"
        elif incident_type in {"suspicious_login_success", "possible_account_compromise"}:
            next_step = "require_approval"

    return {
        "assessment": assessment,
        "incident_type": incident_type,
        "confidence": confidence,
        "severity": severity,
        "recommended_next_step": next_step,
        "reason": reason,
        "affected_user": affected_user,
        "source_ips": [str(item) for item in source_ips[:20]],
        "evidence_summary": [str(item) for item in evidence_summary[:20]],
        "evidence_gaps": [str(item) for item in evidence_gaps[:20]],
        "additional_evidence_requests": additional_requests,
        "evidence": evidence,
        "governance_policy_applied": governance_policy_applied,
        "mcp_tools_used": used_tools,
    }


def message_content_to_object(message: dict[str, Any]) -> dict[str, Any] | None:
    content = message.get("content", "") if isinstance(message, dict) else ""
    if isinstance(content, dict):
        return content
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parsed = extract_json_object(item["text"])
                if parsed:
                    return parsed
        return None
    return extract_json_object(str(content))


class ModelInvocationError(RuntimeError):
    """Model endpoint failure that must never be treated as an MCP failure."""

    def __init__(
        self,
        message: str,
        *,
        stage: str,
        category: str,
        status_code: int | None = None,
        response_text: str = "",
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.category = category
        self.status_code = status_code
        self.response_text = response_text[:1000]


def finalize_model_failure(
    request: dict[str, Any],
    exc: ModelInvocationError,
) -> dict[str, Any]:
    """Fail closed when the AI model is unavailable or unauthenticated."""
    status = exc.status_code
    investigation_status = (
        "model_auth_error"
        if status in {401, 403}
        else "model_http_error"
        if status is not None
        else "model_transport_error"
        if exc.category == "transport_error"
        else "model_configuration_error"
        if exc.category == "configuration_error"
        else "model_response_error"
    )
    safe_error = {
        "category": exc.category,
        "stage": exc.stage,
        "http_status": status,
        "message": str(exc)[:1000],
        "response_text": exc.response_text,
    }
    emit_trace("model_failure", safe_error)
    trigger = request.get("trigger_event", {}) if isinstance(request, dict) else {}
    result = {
        "assessment": "insufficient_context",
        "incident_type": "unknown",
        "confidence": 0.0,
        "severity": "medium",
        "recommended_next_step": "require_approval",
        "reason": (
            "AI Model 呼叫失敗，已停止自動修復並採 fail-closed 處理。"
            f" stage={exc.stage}, category={exc.category}"
            + (f", HTTP={status}" if status is not None else "")
            + "。請修正 Model Credential、Endpoint 或回應格式後重試。"
        ),
        "affected_user": str(trigger.get("username", "") or ""),
        "source_ips": [],
        "evidence_summary": [],
        "evidence_gaps": ["AI Model 未成功完成規劃與最終判斷"],
        "additional_evidence_requests": [],
        "evidence": {
            "model_error": safe_error,
            "trigger_event_key": trigger.get("event_key", "unknown")
            if isinstance(trigger, dict)
            else "unknown",
        },
        "governance_policy_applied": ["model_failure_fail_closed"],
        "mcp_tools_used": [],
        "investigation_status": investigation_status,
        "model_error_stage": exc.stage,
        "model_error_category": exc.category,
        "model_http_status": status,
        "investigation_rounds": 0,
        "total_mcp_tool_calls": 0,
    }
    emit_trace("normalized_final_output", result)
    return result


async def call_model(
    messages: list[dict[str, Any]],
    *,
    tools: list[dict[str, Any]] | None = None,
    trace_stage: str = "model",
    trace_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = os.getenv("AI_MODEL_URL", "").strip()
    token = os.getenv("AI_API_TOKEN", "").strip()
    model = os.getenv("AI_MODEL", "").strip()
    if not url:
        raise ModelInvocationError(
            "AI_MODEL_URL is not configured",
            stage=trace_stage,
            category="configuration_error",
        )
    if not model:
        raise ModelInvocationError(
            "AI_MODEL is not configured",
            stage=trace_stage,
            category="configuration_error",
        )
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": 1400,
        "stream": False,
    }
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    verify = as_bool(os.getenv("AI_VALIDATE_CERTS"), True)
    timeout = bounded_float(os.getenv("AI_TIMEOUT"), 180.0, 30.0, 600.0)
    max_retries = bounded_int(os.getenv("AI_MODEL_MAX_RETRIES"), 1, 0, 3)
    retry_delay = bounded_float(
        os.getenv("AI_MODEL_RETRY_DELAY_SECONDS"), 1.5, 0.1, 10.0
    )
    retryable_statuses = {408, 429, 500, 502, 503, 504}

    for attempt in range(max_retries + 1):
        attempt_number = attempt + 1
        input_trace = {
            "endpoint": url,
            "validate_certs": verify,
            "timeout": timeout,
            "attempt": attempt_number,
            "max_attempts": max_retries + 1,
            "request": payload,
        }
        if trace_context:
            input_trace.update(trace_context)
        emit_trace(f"{trace_stage}_input", input_trace)

        try:
            async with httpx.AsyncClient(verify=verify, timeout=timeout) as client:
                response = await client.post(url, headers=headers, json=payload)
        except httpx.TransportError as exc:
            if attempt < max_retries:
                delay = retry_delay * (2 ** attempt)
                emit_trace(
                    f"{trace_stage}_retry",
                    {
                        "reason": "transport_error",
                        "error_type": type(exc).__name__,
                        "message": str(exc)[:500],
                        "attempt": attempt_number,
                        "next_attempt": attempt_number + 1,
                        "delay_seconds": delay,
                    },
                )
                await asyncio.sleep(delay)
                continue
            emit_trace(
                f"{trace_stage}_transport_error",
                {
                    "error_type": type(exc).__name__,
                    "message": str(exc)[:500],
                    "attempts": attempt_number,
                },
            )
            raise ModelInvocationError(
                f"AI model transport failed after {attempt_number} attempt(s): "
                f"{type(exc).__name__}: {exc}",
                stage=trace_stage,
                category="transport_error",
            ) from exc
        except httpx.HTTPError as exc:
            emit_trace(
                f"{trace_stage}_transport_error",
                {
                    "error_type": type(exc).__name__,
                    "message": str(exc)[:500],
                    "attempts": attempt_number,
                },
            )
            raise ModelInvocationError(
                f"AI model request failed: {type(exc).__name__}: {exc}",
                stage=trace_stage,
                category="transport_error",
            ) from exc

        if response.status_code != 200:
            if response.status_code in retryable_statuses and attempt < max_retries:
                delay = retry_delay * (2 ** attempt)
                retry_after = getattr(response, "headers", {}).get("Retry-After", "")
                try:
                    delay = max(delay, min(10.0, float(retry_after)))
                except (TypeError, ValueError):
                    pass
                emit_trace(
                    f"{trace_stage}_retry",
                    {
                        "reason": "retryable_http_status",
                        "http_status": response.status_code,
                        "attempt": attempt_number,
                        "next_attempt": attempt_number + 1,
                        "delay_seconds": delay,
                    },
                )
                await asyncio.sleep(delay)
                continue
            category = "auth_error" if response.status_code in {401, 403} else "http_error"
            emit_trace(
                f"{trace_stage}_http_error",
                {
                    "http_status": response.status_code,
                    "response_text": response.text[:500],
                    "attempts": attempt_number,
                },
            )
            raise ModelInvocationError(
                f"AI model endpoint returned HTTP {response.status_code}",
                stage=trace_stage,
                category=category,
                status_code=response.status_code,
                response_text=response.text[:500],
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise ModelInvocationError(
                "AI model endpoint returned invalid JSON",
                stage=trace_stage,
                category="response_error",
                status_code=response.status_code,
                response_text=response.text[:500],
            ) from exc
        output_trace = {
            "http_status": response.status_code,
            "attempt": attempt_number,
            "response": data,
        }
        if trace_context:
            output_trace.update(trace_context)
        emit_trace(f"{trace_stage}_output", output_trace)
        try:
            message = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ModelInvocationError(
                "AI response did not contain choices[0].message",
                stage=trace_stage,
                category="response_error",
                status_code=response.status_code,
                response_text=json.dumps(data, ensure_ascii=False, default=str)[:500],
            ) from exc
        if not isinstance(message, dict):
            raise ModelInvocationError(
                "AI response message is not an object",
                stage=trace_stage,
                category="response_error",
                status_code=response.status_code,
                response_text=json.dumps(data, ensure_ascii=False, default=str)[:500],
            )
        return message

    raise ModelInvocationError(
        "AI model retry loop ended unexpectedly",
        stage=trace_stage,
        category="transport_error",
    )

def tool_to_openai(tool: Any) -> dict[str, Any]:
    name = str(getattr(tool, "name", ""))
    description = str(getattr(tool, "description", "") or f"RHEL MCP read-only tool {name}")
    schema = getattr(tool, "inputSchema", None) or {"type": "object", "properties": {}}
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", name)[:64] or "mcp_tool"
    return {
        "type": "function",
        "function": {
            "name": safe_name,
            "description": description,
            "parameters": schema,
        },
    }


def serialize_tool_result(result: Any, limit: int | None = None) -> str:
    if limit is None:
        limit = configured_evidence_limits()["tool_result_max_chars"]
    if getattr(result, "structuredContent", None) is not None:
        text = json.dumps(result.structuredContent, ensure_ascii=False, default=str)
    else:
        parts: list[str] = []
        for item in getattr(result, "content", []) or []:
            if hasattr(item, "text"):
                parts.append(str(item.text))
            elif hasattr(item, "model_dump"):
                parts.append(json.dumps(item.model_dump(), ensure_ascii=False, default=str))
            else:
                parts.append(str(item))
        text = "\n".join(parts)
    if len(text) > limit:
        marker = "...[earlier tool output omitted by governed adapter]\n"
        return marker + text[-max(1, limit - len(marker)):]
    return text


def _schema_properties(schema: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(schema, dict):
        return {}
    properties = schema.get("properties", {})
    return properties if isinstance(properties, dict) else {}


def _first_argument(arguments: dict[str, Any], keys: tuple[str, ...]) -> tuple[str | None, Any]:
    for key in keys:
        if key in arguments:
            return key, arguments[key]
    return None, None


def govern_tool_call(
    tool_name: str,
    arguments: dict[str, Any],
    target_host: str,
    tool_schema: dict[str, Any] | None,
    log_policy: dict[str, dict[str, Any]],
    allowed_tools: set[str],
) -> tuple[bool, str, dict[str, Any], dict[str, Any]]:
    normalized = dict(arguments)
    policy_applied: dict[str, Any] = {}
    if tool_name not in allowed_tools:
        return False, f"tool '{tool_name}' is not in the governed allowlist", normalized, policy_applied

    lowered_name = tool_name.lower()
    if any(word in lowered_name for word in ["write", "delete", "remove", "modify", "restart", "stop", "start", "execute"]):
        return False, f"tool '{tool_name}' appears to be non-read-only", normalized, policy_applied
    serialized = json.dumps(normalized, ensure_ascii=False, default=str)
    if WRITE_LIKE_PATTERNS.search(serialized):
        return False, f"tool '{tool_name}' arguments contain write-like operations", normalized, policy_applied

    properties = _schema_properties(tool_schema)
    for key in HOST_ARGUMENT_KEYS:
        if key in normalized and str(normalized[key]) not in {"", target_host}:
            return False, f"tool '{tool_name}' targets a different host via '{key}'", normalized, policy_applied
    host_key = next((key for key in HOST_ARGUMENT_KEYS if key in properties), None)
    if host_key:
        normalized[host_key] = target_host
        policy_applied["fixed_host_argument"] = host_key

    is_log_reader = tool_name == "read_log_file" or ("log" in lowered_name and "read" in lowered_name)
    is_journal_reader = tool_name == "get_journal_logs"
    if is_log_reader:
        path_key, path_value = _first_argument(normalized, PATH_ARGUMENT_KEYS)
        if not path_key or not path_value:
            return False, f"tool '{tool_name}' did not provide a log path", normalized, policy_applied
        path = str(path_value)
        if path not in log_policy:
            return False, f"tool '{tool_name}' path '{path}' is not allowlisted", normalized, policy_applied
        path_settings = log_policy[path]
        max_lines = int(path_settings["max_lines"])
        default_lines = int(path_settings["default_tail_lines"])
        can_override = bool(path_settings["model_can_override_lines"])

        requested_lines = None
        for key in LOG_LINE_ARGUMENT_KEYS:
            if key in normalized:
                try:
                    requested_lines = int(normalized[key])
                except (TypeError, ValueError):
                    requested_lines = None
                normalized.pop(key, None)
        applied_lines = default_lines
        if can_override and requested_lines is not None:
            applied_lines = max(1, min(max_lines, requested_lines))

        line_key = next((key for key in LOG_LINE_ARGUMENT_KEYS if key in properties), None)
        if line_key:
            normalized[line_key] = applied_lines
        else:
            # linux-mcp-server currently accepts `lines`; retain a safe fallback
            # when the advertised schema omits an explicit count property.
            normalized["lines"] = applied_lines
        schema_path_key = next((key for key in PATH_ARGUMENT_KEYS if key in properties), None)
        applied_path_key = schema_path_key or path_key
        for alias in PATH_ARGUMENT_KEYS:
            if alias != applied_path_key:
                normalized.pop(alias, None)
        normalized[applied_path_key] = path
        policy_applied["applied_log_path_argument"] = applied_path_key
        policy_applied.update(
            {
                "log_path": path,
                "tail_only": True,
                "requested_lines": requested_lines,
                "applied_lines": applied_lines,
                "max_lines": max_lines,
                "model_can_override_lines": can_override,
            }
        )
    elif is_journal_reader:
        # Journal access is read-only and bounded when the MCP schema exposes a
        # count argument. Never allow a Model-requested count above the global
        # log cap.
        max_lines = max(1, max(int(item["max_lines"]) for item in log_policy.values()))
        default_lines = min(30, max_lines)
        requested_lines = None
        for key in LOG_LINE_ARGUMENT_KEYS:
            if key in normalized:
                try:
                    requested_lines = int(normalized[key])
                except (TypeError, ValueError):
                    requested_lines = None
                normalized.pop(key, None)
        applied_lines = default_lines
        if requested_lines is not None:
            applied_lines = max(1, min(max_lines, requested_lines))
        line_key = next((key for key in LOG_LINE_ARGUMENT_KEYS if key in properties), None)
        if line_key:
            normalized[line_key] = applied_lines
        policy_applied.update(
            {
                "journal_read_only": True,
                "requested_lines": requested_lines,
                "applied_lines": applied_lines if line_key else None,
                "max_lines": max_lines,
            }
        )

    return True, "ok", normalized, policy_applied


def build_plan_messages(
    request: dict[str, Any],
    tools: list[dict[str, Any]],
    max_calls: int,
    log_policy: dict[str, dict[str, Any]],
    allowed_tools: set[str],
    *,
    round_number: int = 1,
    max_rounds: int = 1,
    prior_assessment: dict[str, Any] | None = None,
    accumulated_evidence: list[dict[str, Any]] | None = None,
    completed_queries: set[str] | None = None,
    remaining_tool_budget: int | None = None,
) -> list[dict[str, Any]]:
    compact_tools = [
        {
            "name": item["function"]["name"],
            "description": item["function"].get("description", "")[:300],
            "parameters": item["function"].get("parameters", {}),
        }
        for item in tools[:30]
        if item["function"]["name"] in allowed_tools
    ]
    system = f"""You are a bounded, governed RHEL investigation planner.
Use Traditional Chinese (zh-TW) for all reasoning and human-readable text, including any provider-exposed reasoning_content. Keep JSON keys, tool names, and enum-like values exactly as specified in English.
Create a read-only investigation plan for CVE Radar round {round_number} of at most {max_rounds}, with at most {max_calls} MCP tool calls in this round.
Use only tools in the supplied allowlist and only the fixed target host. Never request remediation, commands, restarts, code changes, firewall changes, service changes, or writes.
Log reads are tail-only. Do not choose or enlarge line counts: the adapter enforces the per-path policy and may rewrite your arguments.
Prefer the smallest NEW evidence set needed for the active scenario. Do not repeat completed queries. In later rounds, focus only on unresolved evidence gaps from the prior assessment.
For admin_login_success, the first useful evidence set must include read_log_file for investigation.auth_log_path so the adapter can count admin failures during the five minutes before the successful login. get_journal_logs and get_service_status are optional supplementary evidence only. Never use service tools to change service state.
Return only JSON:
{{"tool_calls":[{{"tool":"name","arguments":{{}}}}]}}
If no useful new evidence query exists, return {{"tool_calls":[]}}."""
    user = {
        "request": request,
        "investigation_round": {
            "current_round": round_number,
            "max_rounds": max_rounds,
            "remaining_tool_budget": remaining_tool_budget,
        },
        "prior_assessment": prior_assessment or {},
        "accumulated_mcp_evidence": compact_evidence_for_model(accumulated_evidence or []),
        "completed_query_fingerprints": sorted(completed_queries or set()),
        "governance_policy": {
            "allowed_tools": sorted(allowed_tools),
            "fixed_target_host": request.get("investigation", {}).get("target_host", ""),
            "log_reads": log_policy,
            "maximum_tool_calls_this_round": max_calls,
        },
        "available_tools": compact_tools,
    }
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user, ensure_ascii=False, default=str)},
    ]


def build_final_messages(
    request: dict[str, Any],
    evidence: list[dict[str, Any]],
    *,
    round_number: int = 1,
    max_rounds: int = 1,
    remaining_tool_budget: int | None = None,
) -> list[dict[str, Any]]:
    system = """You are the final security analyst for the Red Hat TAM Day CVE Radar demo.
Use Traditional Chinese (zh-TW) for all reasoning and human-readable text, including any provider-exposed reasoning_content. Keep JSON keys and all required enum values exactly as specified in English. Do not put chain-of-thought inside the JSON response.
EDA supplied only a wake-up signal. Independently evaluate the trigger and MCP evidence; do not adopt detection_context.scenario or expected_follow_up as the verdict unless the evidence supports it.
A complete structured event with event_key authorization.admin.access/admin_content.exposure, a non-admin username and role, an /admin path, and an allowed/success outcome is first-party application authorization evidence. Apache access logs normally do not contain application username or role context, so absence of the same request in Apache logs is not contradictory evidence and must not reduce confidence by itself.
Classify broken access control, suspicious successful login after repeated failures, possible account compromise, likely user error, or unknown.
For admin_login_success, always read the authentication log and count failures for the same admin account during the five minutes immediately before trigger_event.observed_at. The successful login event alone is not suspicious. If the count is at least three, return suspicious_login_success with require_approval. If the count is below three, return likely_user_error with observe. Never recommend account locking, blocking, maintenance mode, or any automatic system change for this scenario. Include recent_admin_login_failure_count as an integer in evidence.
Return exactly one JSON object with these fields:
assessment: insufficient_context | likely_user_error | suspicious | highly_suspicious
incident_type: one supported project incident type
confidence: number from 0 to 1
severity: low | medium | high | critical
recommended_next_step: observe | collect_more_evidence | alert | require_approval | repair_web_code
reason: concise Traditional Chinese explanation
affected_user: exact username only when supported, otherwise empty string
source_ips: array of objectively observed IP addresses
evidence_summary: concise array of objective findings
evidence: JSON object of objective findings
evidence_gaps: array of specific missing facts; empty when the evidence is sufficient
additional_evidence_requests: when recommended_next_step is collect_more_evidence, provide a minimal array of NEW read-only MCP requests as {"tool":"name","arguments":{}}; otherwise return []
mcp_tools_used: array (the adapter replaces this with the actual tools)
Do not repeat a query already represented in the supplied evidence. Do not include Markdown, hidden reasoning, or text outside the JSON object."""
    user = {
        "investigation_request": request,
        "investigation_round": {
            "current_round": round_number,
            "max_rounds": max_rounds,
            "remaining_tool_budget": remaining_tool_budget,
        },
        "mcp_evidence": compact_evidence_for_model(evidence),
    }
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user, ensure_ascii=False, default=str)},
    ]


def query_fingerprint(tool_name: str, arguments: dict[str, Any]) -> str:
    return tool_name + ":" + json.dumps(arguments, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _coerce_plan_calls(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        tool = str(item.get("tool", "")).strip()
        arguments = item.get("arguments", {})
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                arguments = {}
        if tool and isinstance(arguments, dict):
            result.append({"tool": tool, "arguments": arguments})
    return result


def ensure_admin_login_auth_log_plan(
    request: dict[str, Any],
    plan_calls: list[dict[str, Any]],
    accumulated_evidence: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], bool]:
    """Keep Model planning while guaranteeing the evidence required by Lab 2."""
    trigger = evaluate_structured_admin_login_success(request)
    if not trigger.get("matched"):
        return plan_calls, False
    if evaluate_recent_admin_login_failures(request, accumulated_evidence).get("evidence_sufficient"):
        return plan_calls, False

    investigation = request.get("investigation", {})
    auth_path = str(
        investigation.get(
            "auth_log_path",
            "/var/log/kernel-cve-radar/auth-events.jsonl",
        )
    )
    for call in plan_calls:
        if str(call.get("tool", "")) != "read_log_file":
            continue
        arguments = call.get("arguments", {})
        if not isinstance(arguments, dict):
            continue
        _path_key, path_value = _first_argument(arguments, PATH_ARGUMENT_KEYS)
        if str(path_value or "") == auth_path:
            return plan_calls, False

    required_call = {
        "tool": "read_log_file",
        "arguments": {
            "host": str(investigation.get("target_host", "")),
            "log_path": auth_path,
        },
    }
    return [required_call, *plan_calls], True


async def _execute_plan_calls(
    *,
    session: Any,
    plan_calls: list[dict[str, Any]],
    round_number: int,
    source: str,
    target_host: str,
    safe_to_original: dict[str, str],
    schema_by_original: dict[str, dict[str, Any]],
    log_policy: dict[str, dict[str, Any]],
    allowed_tools: set[str],
    completed_queries: set[str],
    max_calls: int,
) -> tuple[list[dict[str, Any]], list[str], int]:
    evidence: list[dict[str, Any]] = []
    used_tools: list[str] = []
    executed = 0
    for item in plan_calls[:max_calls]:
        safe_name = str(item.get("tool", ""))
        original_name = safe_to_original.get(safe_name, safe_name)
        args = item.get("arguments", {})
        if not isinstance(args, dict):
            args = {}
        emit_trace(
            "mcp_tool_requested",
            {"round": round_number, "plan_source": source, "tool": original_name, "arguments": args},
        )
        ok, reason, governed_args, policy_applied = govern_tool_call(
            original_name,
            args,
            target_host,
            schema_by_original.get(original_name, {}),
            log_policy,
            allowed_tools,
        )
        if not ok:
            evidence.append(
                {"round": round_number, "tool": original_name, "skipped": True, "reason": reason}
            )
            emit_trace(
                "mcp_tool_blocked",
                {
                    "round": round_number,
                    "plan_source": source,
                    "tool": original_name,
                    "arguments": args,
                    "allowed": False,
                    "reason": reason,
                },
            )
            continue

        fingerprint = query_fingerprint(original_name, governed_args)
        if fingerprint in completed_queries:
            reason = "duplicate governed MCP query was not executed again"
            evidence.append(
                {
                    "round": round_number,
                    "tool": original_name,
                    "arguments": governed_args,
                    "skipped": True,
                    "reason": reason,
                }
            )
            emit_trace(
                "mcp_tool_duplicate",
                {
                    "round": round_number,
                    "plan_source": source,
                    "tool": original_name,
                    "governed_arguments": governed_args,
                    "reason": reason,
                },
            )
            continue

        emit_trace(
            "mcp_tool_allowed",
            {
                "round": round_number,
                "plan_source": source,
                "tool": original_name,
                "requested_arguments": args,
                "governed_arguments": governed_args,
                "policy_applied": policy_applied,
                "allowed": True,
            },
        )
        completed_queries.add(fingerprint)
        executed += 1
        try:
            result = await session.call_tool(original_name, governed_args)
            result_limit = configured_evidence_limits()["tool_result_max_chars"]
            serialized_result = serialize_tool_result(result, result_limit)
            if bool(getattr(result, "isError", False)):
                raise RuntimeError(
                    f"RHEL MCP tool {original_name} returned an error result: "
                    f"{serialized_result[:600]}"
                )
            if policy_applied.get("tail_only"):
                serialized_result = tail_text(
                    serialized_result,
                    int(policy_applied.get("applied_lines", 30)),
                    char_limit=result_limit,
                )
            used_tools.append(original_name)
            parsed_log_records: list[dict[str, Any]] = []
            log_record_parse_status = "not_applicable"
            if original_name == "read_log_file":
                parsed_log_records = extract_log_records_from_tool_result(result)
                if parsed_log_records:
                    log_record_parse_status = "parsed"
                elif not serialized_result.strip():
                    log_record_parse_status = "parsed_empty"
                else:
                    log_record_parse_status = "unparsed_nonempty"
            record = {
                "round": round_number,
                "tool": original_name,
                "arguments": governed_args,
                "policy_applied": policy_applied,
                "result": serialized_result,
            }
            if original_name == "read_log_file":
                record["parsed_log_records"] = parsed_log_records
                record["log_record_parse_status"] = log_record_parse_status
            evidence.append(record)
            if as_bool(os.getenv("GOVERNED_TRACE_INCLUDE_MCP_RESULTS"), True):
                emit_trace("mcp_tool_result", record)
            else:
                emit_trace(
                    "mcp_tool_result",
                    {
                        "round": round_number,
                        "tool": original_name,
                        "arguments": governed_args,
                        "policy_applied": policy_applied,
                        "result_hidden": True,
                        "result_length": len(serialized_result),
                        "log_record_parse_status": log_record_parse_status,
                        "parsed_log_record_count": len(parsed_log_records),
                    },
                )
        except Exception as exc:
            error_record = {
                "round": round_number,
                "tool": original_name,
                "arguments": governed_args,
                "policy_applied": policy_applied,
                "error": str(exc)[:600],
            }
            emit_trace("mcp_tool_error", error_record)
            raise RuntimeError(
                f"RHEL MCP tool {original_name} failed: {type(exc).__name__}: {exc}"
            ) from exc
    return evidence, used_tools, executed


def _finalize_evidence_limit(
    normalized: dict[str, Any],
    *,
    reason_suffix: str,
    rounds_completed: int,
    total_tool_calls: int,
    max_rounds: int,
    max_total_tool_calls: int,
) -> dict[str, Any]:
    result = dict(normalized)
    result["assessment"] = "insufficient_context"
    result["recommended_next_step"] = "require_approval"
    result["reason"] = (str(result.get("reason", "")).rstrip() + " " + reason_suffix).strip()
    result["investigation_status"] = "evidence_limit_reached"
    result["investigation_rounds"] = rounds_completed
    result["total_mcp_tool_calls"] = total_tool_calls
    result["investigation_limits"] = {
        "max_rounds": max_rounds,
        "max_total_tool_calls": max_total_tool_calls,
    }
    return result


def find_nested_exception(
    exc: BaseException,
    exception_type: type[BaseException],
) -> BaseException | None:
    if isinstance(exc, exception_type):
        return exc
    nested = getattr(exc, "exceptions", None)
    if nested and isinstance(nested, (list, tuple)):
        for child in nested:
            if isinstance(child, BaseException):
                found = find_nested_exception(child, exception_type)
                if found is not None:
                    return found
    return None


def describe_exception_tree(exc: BaseException) -> dict[str, Any]:
    """Return actionable leaf errors from ExceptionGroup/TaskGroup failures."""
    leaves: list[dict[str, str]] = []

    def walk(item: BaseException) -> None:
        nested = getattr(item, "exceptions", None)
        if nested and isinstance(nested, (list, tuple)):
            for child in nested:
                if isinstance(child, BaseException):
                    walk(child)
            return
        if isinstance(item, asyncio.CancelledError):
            return
        leaves.append(
            {
                "type": type(item).__name__,
                "message": str(item)[:1000],
            }
        )

    walk(exc)
    if not leaves:
        leaves.append({"type": type(exc).__name__, "message": str(exc)[:1000]})
    summary = "; ".join(
        f"{item['type']}: {item['message']}" for item in leaves[:8]
    )
    return {
        "top_level_type": type(exc).__name__,
        "top_level_message": str(exc)[:1000],
        "root_errors": leaves[:8],
        "summary": summary[:3000],
        "traceback": "".join(traceback.format_exception(exc))[-12000:],
    }


def finalize_mcp_transport_failure(
    request: dict[str, Any],
    exc: BaseException,
    *,
    stage: str,
) -> dict[str, Any]:
    """Fail closed on any RHEL MCP connection, initialization, or tool error."""
    details = describe_exception_tree(exc)
    emit_trace(
        "mcp_error",
        {
            "stage": stage,
            **details,
        },
    )
    trigger = request.get("trigger_event", {}) if isinstance(request, dict) else {}
    result = {
        "assessment": "insufficient_context",
        "incident_type": "unknown",
        "confidence": 0.0,
        "severity": "medium",
        "recommended_next_step": "require_approval",
        "reason": (
            "RHEL MCP 呼叫失敗，AI 調查無法取得必要證據，"
            "已停止自動修復並讓 Job fail closed。"
            f" stage={stage}; root_cause={details['summary']}"
        ),
        "affected_user": str(trigger.get("username", "") or "")
        if isinstance(trigger, dict)
        else "",
        "source_ips": [],
        "evidence_summary": [],
        "evidence_gaps": ["RHEL MCP 未成功完成受控蒐證"],
        "additional_evidence_requests": [],
        "evidence": {
            "mcp_error": details["summary"],
            "mcp_error_stage": stage,
            "mcp_root_errors": details["root_errors"],
        },
        "governance_policy_applied": ["mcp_failure_fail_closed"],
        "mcp_tools_used": [],
        "investigation_status": "mcp_error",
        "mcp_error": details["summary"],
        "mcp_error_stage": stage,
        "mcp_root_errors": details["root_errors"],
        "investigation_rounds": 0,
        "total_mcp_tool_calls": 0,
    }
    emit_trace("normalized_final_output", result)
    return result


async def run_governed_investigation(request: dict[str, Any]) -> dict[str, Any]:
    if ClientSession is None or streamablehttp_client is None:
        error = RuntimeError("mcp Python package is not available in the execution environment")
        return finalize_mcp_transport_failure(request, error, stage="configuration")

    url = os.getenv("RHEL_MCP_URL", "").strip()
    if not url:
        error = RuntimeError("RHEL_MCP_URL is not configured")
        return finalize_mcp_transport_failure(request, error, stage="configuration")

    headers: dict[str, str] = {}
    token = os.getenv("RHEL_MCP_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    target_host = str(request.get("investigation", {}).get("target_host", ""))
    try:
        mcp_timeout = max(1.0, float(os.getenv("RHEL_MCP_TIMEOUT", "30")))
    except ValueError:
        mcp_timeout = 30.0
    try:
        mcp_sse_read_timeout = max(1.0, float(os.getenv("RHEL_MCP_SSE_READ_TIMEOUT", "300")))
    except ValueError:
        mcp_sse_read_timeout = 300.0
    loop_policy = configured_evidence_loop()
    log_policy = build_log_policy(request)
    allowed_tools = configured_allowed_tools()
    accumulated_evidence: list[dict[str, Any]] = []
    used_tools: list[str] = []
    completed_queries: set[str] = set()
    total_tool_calls = 0
    prior_assessment: dict[str, Any] | None = None
    pending_requests: list[dict[str, Any]] = []
    admin_login_trigger = evaluate_structured_admin_login_success(request)
    if admin_login_trigger.get("matched") and "read_log_file" not in allowed_tools:
        error = RuntimeError(
            "admin_login_success investigation requires read_log_file in the governed MCP allowlist"
        )
        return finalize_mcp_transport_failure(request, error, stage="configuration")

    emit_trace(
        "mcp_connection_input",
        {
            "endpoint": url,
            "target_host": target_host,
            "timeout_seconds": mcp_timeout,
            "sse_read_timeout_seconds": mcp_sse_read_timeout,
            "allowed_tools": sorted(allowed_tools),
            "log_read_policy": log_policy,
            "evidence_loop": loop_policy,
        },
    )

    mcp_stage = "connect"
    try:
        transport_kwargs: dict[str, Any] = {"headers": headers or None}
        # mcp 1.x accepts timedelta for these parameters; newer compatible
        # releases accept the same values while retaining backward compatibility.
        transport_kwargs["timeout"] = timedelta(seconds=mcp_timeout)
        transport_kwargs["sse_read_timeout"] = timedelta(seconds=mcp_sse_read_timeout)
        async with streamablehttp_client(url, **transport_kwargs) as (read_stream, write_stream, _get_session_id):
            mcp_stage = "initialize"
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                mcp_stage = "list_tools"
                listed = await session.list_tools()
                mcp_stage = "investigation_round"
                tools = list(getattr(listed, "tools", []) or [])
                tool_records: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
                for tool in tools:
                    converted = tool_to_openai(tool)
                    original_name = str(getattr(tool, "name", ""))
                    tool_records.append((original_name, converted, getattr(tool, "inputSchema", None) or {}))
                openai_tools = [record[1] for record in tool_records if record[0] in allowed_tools]
                if not openai_tools:
                    raise RuntimeError(
                        "RHEL MCP did not expose any tool from the governed allowlist"
                    )
                safe_to_original = {record[1]["function"]["name"]: record[0] for record in tool_records}
                schema_by_original = {record[0]: record[2] for record in tool_records}
                emit_trace(
                    "mcp_available_tools",
                    {
                        "server_tool_count": len(tool_records),
                        "allowed_tool_count": len(openai_tools),
                        "tools": openai_tools,
                    },
                )

                for round_number in range(1, int(loop_policy["max_rounds"]) + 1):
                    remaining_total = int(loop_policy["max_total_tool_calls"]) - total_tool_calls
                    if remaining_total <= 0:
                        break
                    round_budget = min(int(loop_policy["max_tool_calls_per_round"]), remaining_total)
                    emit_trace(
                        "investigation_round_start",
                        {
                            "round": round_number,
                            "max_rounds": loop_policy["max_rounds"],
                            "round_tool_budget": round_budget,
                            "remaining_total_tool_budget": remaining_total,
                            "prior_evidence_gaps": (prior_assessment or {}).get("evidence_gaps", []),
                        },
                    )

                    plan_source = "assessment_requests" if pending_requests else "model_planner"
                    plan_calls = list(pending_requests)
                    pending_requests = []
                    if not plan_calls:
                        plan_messages = build_plan_messages(
                            request,
                            openai_tools,
                            round_budget,
                            log_policy,
                            allowed_tools,
                            round_number=round_number,
                            max_rounds=int(loop_policy["max_rounds"]),
                            prior_assessment=prior_assessment,
                            accumulated_evidence=accumulated_evidence,
                            completed_queries=completed_queries,
                            remaining_tool_budget=remaining_total,
                        )
                        plan_message = await call_model(
                            plan_messages,
                            trace_stage="model_plan",
                            trace_context={"round": round_number, "max_rounds": loop_policy["max_rounds"]},
                        )
                        plan_obj = message_content_to_object(plan_message)
                        if not plan_obj:
                            raise ModelInvocationError(
                                "AI model planner did not return a valid JSON object",
                                stage="model_plan",
                                category="response_error",
                            )
                        plan_calls = _coerce_plan_calls(plan_obj.get("tool_calls", []))
                    plan_calls, required_auth_log_added = ensure_admin_login_auth_log_plan(
                        request,
                        plan_calls,
                        accumulated_evidence,
                    )
                    if required_auth_log_added:
                        emit_trace(
                            "admin_login_required_evidence_added",
                            {
                                "round": round_number,
                                "username": admin_login_trigger.get("username", ""),
                                "success_at": admin_login_trigger.get("success_at", ""),
                                "lookback_minutes": request.get("investigation", {}).get("lookback_minutes", 5),
                                "required_tool": "read_log_file",
                            },
                        )
                    emit_trace(
                        "mcp_plan_parsed",
                        {
                            "round": round_number,
                            "plan_source": plan_source,
                            "required_auth_log_added": required_auth_log_added,
                            "tool_calls": plan_calls[:round_budget],
                        },
                    )

                    round_evidence, round_tools, executed = await _execute_plan_calls(
                        session=session,
                        plan_calls=plan_calls,
                        round_number=round_number,
                        source=plan_source,
                        target_host=target_host,
                        safe_to_original=safe_to_original,
                        schema_by_original=schema_by_original,
                        log_policy=log_policy,
                        allowed_tools=allowed_tools,
                        completed_queries=completed_queries,
                        max_calls=round_budget,
                    )

                    # If model-provided follow-up requests were all blocked or duplicate,
                    # ask the planner once for an alternative NEW evidence set.
                    if executed == 0 and plan_source == "assessment_requests" and round_budget > 0:
                        fallback_messages = build_plan_messages(
                            request,
                            openai_tools,
                            round_budget,
                            log_policy,
                            allowed_tools,
                            round_number=round_number,
                            max_rounds=int(loop_policy["max_rounds"]),
                            prior_assessment=prior_assessment,
                            accumulated_evidence=accumulated_evidence + round_evidence,
                            completed_queries=completed_queries,
                            remaining_tool_budget=remaining_total,
                        )
                        fallback_message = await call_model(
                            fallback_messages,
                            trace_stage="model_plan",
                            trace_context={
                                "round": round_number,
                                "max_rounds": loop_policy["max_rounds"],
                                "fallback_after_invalid_requests": True,
                            },
                        )
                        fallback_obj = message_content_to_object(fallback_message)
                        if not fallback_obj:
                            raise ModelInvocationError(
                                "AI model fallback planner did not return a valid JSON object",
                                stage="model_plan",
                                category="response_error",
                            )
                        fallback_calls = _coerce_plan_calls(fallback_obj.get("tool_calls", []))
                        emit_trace(
                            "mcp_plan_parsed",
                            {
                                "round": round_number,
                                "plan_source": "model_planner_fallback",
                                "tool_calls": fallback_calls[:round_budget],
                            },
                        )
                        fallback_evidence, fallback_tools, fallback_executed = await _execute_plan_calls(
                            session=session,
                            plan_calls=fallback_calls,
                            round_number=round_number,
                            source="model_planner_fallback",
                            target_host=target_host,
                            safe_to_original=safe_to_original,
                            schema_by_original=schema_by_original,
                            log_policy=log_policy,
                            allowed_tools=allowed_tools,
                            completed_queries=completed_queries,
                            max_calls=round_budget,
                        )
                        round_evidence.extend(fallback_evidence)
                        round_tools.extend(fallback_tools)
                        executed += fallback_executed

                    accumulated_evidence.extend(round_evidence)
                    used_tools.extend(round_tools)
                    total_tool_calls += executed
                    remaining_after_round = int(loop_policy["max_total_tool_calls"]) - total_tool_calls

                    final_messages = build_final_messages(
                        request,
                        accumulated_evidence,
                        round_number=round_number,
                        max_rounds=int(loop_policy["max_rounds"]),
                        remaining_tool_budget=remaining_after_round,
                    )
                    final_message = await call_model(
                        final_messages,
                        trace_stage="model_final",
                        trace_context={
                            "round": round_number,
                            "max_rounds": loop_policy["max_rounds"],
                            "remaining_tool_budget": remaining_after_round,
                        },
                    )
                    final_obj = message_content_to_object(final_message)
                    if not final_obj:
                        raise ModelInvocationError(
                            "AI model did not return a valid final JSON envelope",
                            stage="model_final",
                            category="response_error",
                        )
                    normalized = normalize_envelope(
                        final_obj,
                        used_tools,
                        min_confidence_for_action=float(loop_policy["min_confidence_for_action"]),
                        request=request,
                        mcp_evidence=accumulated_evidence,
                    )
                    if "structured_admin_trigger_confidence_floor" in normalized.get(
                        "governance_policy_applied", []
                    ):
                        emit_trace(
                            "structured_admin_trigger_policy_applied",
                            {
                                "round": round_number,
                                "trigger": evaluate_structured_admin_trigger(request),
                                "confidence": normalized.get("confidence"),
                                "recommended_next_step": normalized.get("recommended_next_step"),
                            },
                        )
                    normalized["investigation_rounds"] = round_number
                    normalized["total_mcp_tool_calls"] = total_tool_calls
                    normalized["investigation_status"] = (
                        "action_proposed"
                        if normalized["recommended_next_step"] != "collect_more_evidence"
                        else "evidence_required"
                    )
                    emit_trace(
                        "normalized_round_output",
                        {"round": round_number, "result": normalized},
                    )

                    if normalized["recommended_next_step"] != "collect_more_evidence":
                        emit_trace("investigation_round_complete", {"round": round_number, "continue": False})
                        emit_trace("normalized_final_output", normalized)
                        return normalized

                    emit_trace(
                        "evidence_gap_detected",
                        {
                            "round": round_number,
                            "evidence_gaps": normalized.get("evidence_gaps", []),
                            "additional_evidence_requests": normalized.get("additional_evidence_requests", []),
                            "remaining_tool_budget": remaining_after_round,
                        },
                    )

                    if not bool(loop_policy["enabled"]):
                        normalized["investigation_status"] = "evidence_loop_disabled"
                        emit_trace("investigation_round_complete", {"round": round_number, "continue": False})
                        emit_trace("normalized_final_output", normalized)
                        return normalized

                    if round_number >= int(loop_policy["max_rounds"]) or remaining_after_round <= 0:
                        limited = _finalize_evidence_limit(
                            normalized,
                            reason_suffix=(
                                "已達受控蒐證輪數或 MCP 工具呼叫上限，停止自動擴大調查並交由人工審核。"
                            ),
                            rounds_completed=round_number,
                            total_tool_calls=total_tool_calls,
                            max_rounds=int(loop_policy["max_rounds"]),
                            max_total_tool_calls=int(loop_policy["max_total_tool_calls"]),
                        )
                        emit_trace("investigation_round_complete", {"round": round_number, "continue": False})
                        emit_trace("normalized_final_output", limited)
                        return limited

                    pending_requests = _coerce_plan_calls(normalized.get("additional_evidence_requests", []))
                    prior_assessment = normalized
                    emit_trace(
                        "investigation_round_complete",
                        {
                            "round": round_number,
                            "continue": True,
                            "next_round": round_number + 1,
                            "pending_request_count": len(pending_requests),
                        },
                    )

    except ModelInvocationError as exc:
        return finalize_model_failure(request, exc)
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        nested_model_error = find_nested_exception(exc, ModelInvocationError)
        if isinstance(nested_model_error, ModelInvocationError):
            return finalize_model_failure(request, nested_model_error)
        return finalize_mcp_transport_failure(request, exc, stage=mcp_stage)

    result = fail_envelope("No governed investigation round could be completed.", request)
    result["recommended_next_step"] = "require_approval"
    result["investigation_status"] = "evidence_limit_reached"
    result["investigation_rounds"] = 0
    result["total_mcp_tool_calls"] = total_tool_calls
    emit_trace("normalized_final_output", result)
    return result


async def main() -> int:
    try:
        request = json.loads(sys.stdin.read() or "{}")
        emit_trace("adapter_input", request)
    except json.JSONDecodeError as exc:
        result = fail_envelope(f"stdin is not valid JSON: {exc}")
        result["investigation_status"] = "adapter_input_error"
        result["confidence"] = 0.0
        result["recommended_next_step"] = "require_approval"
        print(json.dumps(result, ensure_ascii=False))
        return 0
    try:
        result = await run_governed_investigation(request)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except Exception as exc:
        result = fail_envelope(f"Governed adapter failed: {exc}", request)
        result["investigation_status"] = "adapter_error"
        result["confidence"] = 0.0
        result["recommended_next_step"] = "require_approval"
        print(json.dumps(result, ensure_ascii=False))
        return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
