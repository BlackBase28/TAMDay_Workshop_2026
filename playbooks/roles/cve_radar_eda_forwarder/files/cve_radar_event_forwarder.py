#!/usr/bin/env python3
"""Normalize CVE Radar security logs and forward them to an AAP Event Stream."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import ssl
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

VERSION = "1.9.5-slim16"

LOGIN_FAILURE_KEY = "kernel-cve-radar.authentication.login.failure"
LOGIN_SUCCESS_KEY = "kernel-cve-radar.authentication.login.success"
ADMIN_LOGIN_SUCCESS_KEY = "kernel-cve-radar.authentication.admin.login.success"
ADMIN_ACCESS_KEY = "kernel-cve-radar.authorization.admin.access"
HTTP_ACCESS_KEY = "kernel-cve-radar.http.access"

DEFAULT_AUTH_LOGS = ("/var/log/kernel-cve-radar/auth-events.jsonl",)
DEFAULT_HTTP_LOGS = (
    "/var/log/kernel-cve-radar/access.log",
    "/var/log/httpd/access_log",
    "/var/log/httpd/ssl_access_log",
)

DEFAULT_HTTP_IGNORE_PREFIXES = (
    "/static/",
    "/assets/",
    "/favicon.ico",
    "/robots.txt",
    "/health",
    "/healthz",
)
DEFAULT_HTTP_IGNORE_SUFFIXES = (
    ".css",
    ".js",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
)

SUCCESS_WORDS = {"allow", "allowed", "success", "successful", "succeeded", "ok"}
FAILURE_WORDS = {"deny", "denied", "fail", "failed", "failure", "invalid", "invalid_credentials", "unauthorized"}

APACHE_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<remote_user>\S+)\s+'
    r'\[(?P<timestamp>[^]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/(?P<http_version>[^"]+))?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

LOG = logging.getLogger("cve-radar-eda-forwarder")
STOP_REQUESTED = False


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def csv_values(value: str | None, defaults: Iterable[str]) -> list[str]:
    if value is None or not value.strip():
        return list(defaults)
    return [item.strip() for item in value.split(",") if item.strip()]


def text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()


def lower(value: Any) -> str:
    return text(value).lower()


def first(source: dict[str, Any], *names: str, default: Any = "") -> Any:
    for name in names:
        if name in source and source[name] not in (None, ""):
            return source[name]
    return default


def parse_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default






def split_forwarded_for(value: Any) -> str:
    raw = text(value)
    if not raw:
        return ""
    return raw.split(",", 1)[0].strip()




def configured_trusted_proxy_networks() -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for item in csv_values(os.getenv("TRUSTED_PROXY_NETWORKS"), ()):
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            LOG.warning("Ignoring invalid trusted proxy network: %s", item)
    return networks


def configured_admin_path_prefixes() -> tuple[str, ...]:
    values = csv_values(os.getenv("ADMIN_PATH_PREFIXES"), ("/admin",))
    return tuple(value if value.startswith("/") else f"/{value}" for value in values)


def configured_admin_usernames() -> set[str]:
    return {value.lower() for value in csv_values(os.getenv("ADMIN_USERNAMES"), ("admin", "administrator"))}


def configured_auth_event_logs() -> set[str]:
    """Return canonical files allowed to emit authorization/admin events."""
    return {
        os.path.realpath(path)
        for path in csv_values(os.getenv("AUTH_EVENT_LOGS"), DEFAULT_AUTH_LOGS)
    }


def is_auth_event_source(source_file: str) -> bool:
    return os.path.realpath(source_file) in configured_auth_event_logs()


def configured_http_ignore_prefixes() -> tuple[str, ...]:
    values = csv_values(os.getenv("HTTP_IGNORE_PATH_PREFIXES"), DEFAULT_HTTP_IGNORE_PREFIXES)
    return tuple(value.lower() for value in values)


def configured_http_ignore_suffixes() -> tuple[str, ...]:
    values = csv_values(os.getenv("HTTP_IGNORE_PATH_SUFFIXES"), DEFAULT_HTTP_IGNORE_SUFFIXES)
    return tuple(value.lower() for value in values)


def should_ignore_http_path(path: Any) -> bool:
    normalized = text(path, "/").split("?", 1)[0].lower()
    return (
        any(normalized.startswith(prefix) for prefix in configured_http_ignore_prefixes())
        or any(normalized.endswith(suffix) for suffix in configured_http_ignore_suffixes())
    )


def trusted_forwarded_for(source: dict[str, Any]) -> str:
    forwarded_for = split_forwarded_for(first(source, "forwarded_for", "x_forwarded_for"))
    if not forwarded_for:
        return ""
    networks = configured_trusted_proxy_networks()
    if not networks:
        return forwarded_for
    connection_ip = text(first(source, "connection_ip", "remote_addr", "source_ip", "client_ip", "ip"))
    try:
        address = ipaddress.ip_address(connection_ip)
    except ValueError:
        return ""
    return forwarded_for if any(address in network for network in networks) else ""



def base_event(
    source: dict[str, Any],
    *,
    sequence: int,
    hostname: str,
    source_file: str,
    event_key: str,
) -> dict[str, Any]:
    timestamp = text(first(source, "ts", "timestamp", "observed_at", "@timestamp"), utc_now())
    event_id = text(source.get("event_id"), str(uuid.uuid4()))
    return {
        "schema_version": "kernel-cve-radar.event.v1",
        "event_id": event_id,
        "event_key": event_key,
        "observed_at": timestamp,
        "application": "kernel-cve-radar",
        "collector": {
            "hostname": hostname,
            "sequence": sequence,
            "source_file": source_file,
            "forwarder_version": VERSION,
        },
        "raw": source,
    }



def login_attempt_outcome(source: dict[str, Any]) -> str:
    key = text(first(source, "event_key", "key"))
    event = lower(first(source, "event", "name"))
    outcome = lower(first(source, "event_outcome", "outcome", "result"))
    status = parse_int(first(source, "status_code", "status", "http_status"), 0)
    if key == LOGIN_FAILURE_KEY or event in {"login_failure", "login_failed", "failed_login"}:
        return "failure"
    if key in {LOGIN_SUCCESS_KEY, ADMIN_LOGIN_SUCCESS_KEY} or event in {"login_success", "login_succeeded", "successful_login"}:
        return "success"
    if outcome in FAILURE_WORDS or status in {401, 403}:
        return "failure"
    if outcome in SUCCESS_WORDS or 200 <= status < 400:
        return "success"
    return ""


def looks_like_login_attempt(source: dict[str, Any]) -> bool:
    key = text(first(source, "event_key", "key"))
    event = lower(first(source, "event", "name"))
    event_type = lower(source.get("event_type"))
    action = lower(first(source, "event_action", "action"))
    path = lower(first(source, "url_path", "path", "uri", "request_path"))
    explicit_login = (
        key in {LOGIN_FAILURE_KEY, LOGIN_SUCCESS_KEY, ADMIN_LOGIN_SUCCESS_KEY}
        or event in {"login_failure", "login_failed", "failed_login", "login_success", "login_succeeded", "successful_login"}
        or (event_type in {"authentication", "auth", "login"} and action in {"login", "authenticate", "authentication"})
        or path in {"/login", "/api/login"}
    )
    return bool(explicit_login and login_attempt_outcome(source))


def normalize_login_attempt(
    source: dict[str, Any], *, sequence: int, hostname: str, source_file: str
) -> dict[str, Any]:
    outcome = login_attempt_outcome(source)
    username = text(first(source, "username", "user", "login_user", "remote_user"), "unknown")
    role = text(first(source, "user_role", "role"), "unknown")
    if outcome == "success" and username.lower() == "admin":
        event_key = ADMIN_LOGIN_SUCCESS_KEY
    else:
        event_key = LOGIN_SUCCESS_KEY if outcome == "success" else LOGIN_FAILURE_KEY
    forwarded_for = trusted_forwarded_for(source)
    source_ip = text(first(source, "effective_source_ip", "source_ip", "client_ip", "remote_addr", "ip"))
    effective_ip = forwarded_for or source_ip or "unknown"
    path = text(first(source, "url_path", "path", "uri", "request_path"), "/login")
    event = base_event(
        source,
        sequence=sequence,
        hostname=hostname,
        source_file=source_file,
        event_key=event_key,
    )
    event.update(
        {
            "event_source": "application_auth_log",
            "event_type": "authentication",
            "event_action": "login",
            "event_outcome": outcome,
            "username": username,
            "user_role": role,
            "effective_source_ip": effective_ip,
            "source_ip": source_ip or effective_ip,
            "forwarded_for": forwarded_for,
            "url_path": path,
            "status_code": parse_int(first(source, "status_code", "status", "http_status"), 0),
            "user_agent": text(first(source, "user_agent", "http_user_agent")),
            "session_id": text(source.get("session_id")),
            "request_id": text(source.get("request_id")),
            "failure_reason": text(first(source, "reason", "message", "error")),
        }
    )
    return event




def normalize_admin_access(
    source: dict[str, Any], *, sequence: int, hostname: str, source_file: str
) -> dict[str, Any]:
    username = text(first(source, "username", "user", "login_user"), "unknown")
    role = text(first(source, "user_role", "role"), "unknown")
    forwarded_for = trusted_forwarded_for(source)
    source_ip = text(first(source, "effective_source_ip", "source_ip", "client_ip", "remote_addr", "ip"))
    effective_ip = forwarded_for or source_ip or "unknown"
    path = text(first(source, "url_path", "path", "uri", "request_path"), "/admin")
    outcome_raw = lower(first(source, "event_outcome", "outcome", "result"))
    outcome = "allowed" if outcome_raw in SUCCESS_WORDS or not outcome_raw else outcome_raw
    event = base_event(
        source,
        sequence=sequence,
        hostname=hostname,
        source_file=source_file,
        event_key=ADMIN_ACCESS_KEY,
    )
    event.update(
        {
            "event_source": "application_auth_log",
            "event_type": "authorization",
            "event_action": "admin_access",
            "event_outcome": outcome,
            "username": username,
            "user_role": role,
            "effective_source_ip": effective_ip,
            "source_ip": source_ip or effective_ip,
            "forwarded_for": forwarded_for,
            "url_path": path,
        }
    )
    return event


def http_outcome(status: int) -> str:
    if status >= 500:
        return "server_error"
    if status >= 400:
        return "client_error"
    return "success"


def normalize_http_access(
    source: dict[str, Any], *, sequence: int, hostname: str, source_file: str
) -> dict[str, Any]:
    forwarded_for = trusted_forwarded_for(source)
    source_ip = text(first(source, "effective_source_ip", "source_ip", "client_ip", "remote_addr", "ip"))
    effective_ip = forwarded_for or source_ip or "unknown"
    status = parse_int(first(source, "status_code", "status", "http_status"), 0)
    path = text(first(source, "url_path", "path", "uri", "request_path", "url"), "/")
    method = text(first(source, "http_method", "method", "request_method"), "GET").upper()
    event = base_event(
        source,
        sequence=sequence,
        hostname=hostname,
        source_file=source_file,
        event_key=HTTP_ACCESS_KEY,
    )
    event.update(
        {
            "event_type": "http",
            "event_action": "access",
            "event_outcome": http_outcome(status),
            "effective_source_ip": effective_ip,
            "source_ip": source_ip or effective_ip,
            "forwarded_for": forwarded_for,
            "http_method": method,
            "url_path": path,
            "status_code": status,
            "response_bytes": parse_int(first(source, "response_bytes", "bytes", "body_bytes_sent"), 0),
            "user_agent": text(first(source, "user_agent", "http_user_agent")),
            "referer": text(first(source, "referer", "referrer", "http_referer")),
            "username": text(first(source, "username", "user", "remote_user")),
        }
    )
    return event



def looks_like_admin_access(source: dict[str, Any]) -> bool:
    event = lower(first(source, "event", "name"))
    event_type = lower(source.get("event_type"))
    action = lower(first(source, "event_action", "action"))
    path = lower(first(source, "url_path", "path", "uri", "request_path"))
    username = lower(first(source, "username", "user", "remote_user"))
    outcome = lower(first(source, "event_outcome", "outcome", "result"))
    status = parse_int(first(source, "status_code", "status", "http_status"), 0)
    key = text(first(source, "event_key", "key"))
    if key == ADMIN_ACCESS_KEY:
        return True
    if event in {"admin_access", "admin_content_access", "authorization_bypass"}:
        return True
    admin_path = any(path.startswith(prefix.lower()) for prefix in configured_admin_path_prefixes())
    if event_type == "authorization" and action in {"admin_access", "access"} and admin_path:
        return True
    # Generic application/http access records can also reveal broken access
    # control when a non-admin authenticated user receives a successful result.
    success = outcome in SUCCESS_WORDS or 200 <= status < 400
    return bool(admin_path and username and username not in configured_admin_usernames() and success)


def looks_like_http_access(source: dict[str, Any]) -> bool:
    event_type = lower(source.get("event_type"))
    action = lower(first(source, "event_action", "action"))
    key = text(first(source, "event_key", "key"))
    if key == HTTP_ACCESS_KEY:
        return True
    if event_type in {"http", "web", "request"} and action in {"access", "request"}:
        return True
    has_path = any(name in source for name in ("path", "uri", "url_path", "request_path", "url"))
    has_status = any(name in source for name in ("status", "status_code", "http_status"))
    return has_path and has_status


def normalize_json_event(
    source: dict[str, Any], *, sequence: int, hostname: str, source_file: str
) -> dict[str, Any] | None:
    # Authorization findings are trusted only from the dedicated structured
    # application auth log. Overlapping application/http access logs remain
    # HTTP observations and cannot create a second admin-access trigger.
    if is_auth_event_source(source_file) and looks_like_admin_access(source):
        return normalize_admin_access(source, sequence=sequence, hostname=hostname, source_file=source_file)
    if is_auth_event_source(source_file) and looks_like_login_attempt(source):
        return normalize_login_attempt(source, sequence=sequence, hostname=hostname, source_file=source_file)
    if looks_like_http_access(source):
        path = first(source, "url_path", "path", "uri", "request_path", "url", default="/")
        if should_ignore_http_path(path):
            return None
        return normalize_http_access(source, sequence=sequence, hostname=hostname, source_file=source_file)
    return None


def parse_apache_access_line(line: str) -> dict[str, Any] | None:
    match = APACHE_COMBINED_RE.match(line.strip())
    if not match:
        return None
    record = match.groupdict()
    return {
        "timestamp": record.get("timestamp", ""),
        "ip": record.get("ip", ""),
        "remote_user": "" if record.get("remote_user") == "-" else record.get("remote_user", ""),
        "method": record.get("method", "GET"),
        "path": record.get("path", "/"),
        "http_version": record.get("http_version", ""),
        "status": parse_int(record.get("status"), 0),
        "bytes": 0 if record.get("bytes") == "-" else parse_int(record.get("bytes"), 0),
        "referer": record.get("referer") or "",
        "user_agent": record.get("user_agent") or "",
        "source_format": "apache_combined",
    }


def normalize_line(
    line: str, *, sequence: int, hostname: str, source_file: str
) -> dict[str, Any] | None:
    stripped = line.strip()
    if not stripped:
        return None
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError:
        value = None
    if isinstance(value, dict):
        return normalize_json_event(value, sequence=sequence, hostname=hostname, source_file=source_file)
    apache = parse_apache_access_line(stripped)
    if apache is not None:
        if should_ignore_http_path(apache.get("path", "/")):
            return None
        return normalize_http_access(apache, sequence=sequence, hostname=hostname, source_file=source_file)
    return None


@dataclass
class FileCursor:
    path: str
    inode: int = 0
    offset: int = 0
    initialized: bool = False
    partial: str = ""


@dataclass
class StateStore:
    path: Path
    cursors: dict[str, FileCursor] = field(default_factory=dict)
    sequence: int = 0

    def load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return
        self.sequence = parse_int(raw.get("sequence"), 0)
        for path, data in raw.get("files", {}).items():
            if isinstance(data, dict):
                self.cursors[path] = FileCursor(
                    path=path,
                    inode=parse_int(data.get("inode"), 0),
                    offset=parse_int(data.get("offset"), 0),
                    initialized=True,
                )

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "sequence": self.sequence,
            "files": {
                path: {"inode": cursor.inode, "offset": cursor.offset}
                for path, cursor in self.cursors.items()
            },
        }
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temporary, self.path)

    def next_sequence(self) -> int:
        self.sequence += 1
        return self.sequence


class EventSender:
    def __init__(self) -> None:
        self.url = os.getenv("EDA_EVENT_STREAM_URL", "").strip()
        if not self.url:
            raise RuntimeError("EDA_EVENT_STREAM_URL is required")
        self.token = os.getenv("EDA_EVENT_STREAM_TOKEN", "").strip()
        self.header_name = os.getenv("EDA_AUTH_HEADER", "X-CVE-Radar-Token").strip() or "X-CVE-Radar-Token"
        self.auth_scheme = os.getenv("EDA_AUTH_SCHEME", "").strip()
        self.timeout = float(os.getenv("EDA_HTTP_TIMEOUT", "20"))
        self.verify_tls = as_bool(os.getenv("EDA_VERIFY_TLS"), True)
        self.ca_file = os.getenv("EDA_CA_FILE", "").strip()
        self.max_retries = max(1, parse_int(os.getenv("EDA_MAX_RETRIES"), 5))
        try:
            extra = json.loads(os.getenv("EDA_EXTRA_HEADERS_JSON", "{}"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"EDA_EXTRA_HEADERS_JSON is invalid: {exc}") from exc
        self.extra_headers = extra if isinstance(extra, dict) else {}
        if self.verify_tls:
            self.ssl_context = ssl.create_default_context(cafile=self.ca_file or None)
        else:
            self.ssl_context = ssl._create_unverified_context()

    def send(self, event: dict[str, Any]) -> None:
        body = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"cve-radar-eda-forwarder/{VERSION}",
            "X-Request-ID": text(event.get("event_id")),
        }
        headers.update({str(k): str(v) for k, v in self.extra_headers.items()})
        if self.token:
            auth_value = f"{self.auth_scheme} {self.token}".strip() if self.auth_scheme else self.token
            headers[self.header_name] = auth_value
        request = Request(self.url, data=body, headers=headers, method="POST")
        for attempt in range(1, self.max_retries + 1):
            try:
                with urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                    status = getattr(response, "status", 200)
                    if 200 <= status < 300:
                        return
                    raise RuntimeError(f"Event Stream returned HTTP {status}")
            except HTTPError as exc:
                detail = exc.read(512).decode("utf-8", errors="replace")
                error: Exception = RuntimeError(f"Event Stream HTTP {exc.code}: {detail}")
                retryable = exc.code >= 500 or exc.code == 429
            except (URLError, TimeoutError, OSError) as exc:
                error = exc
                retryable = True
            if attempt >= self.max_retries or not retryable:
                raise RuntimeError(f"Unable to send event after {attempt} attempt(s): {error}") from error
            delay = min(30.0, 2.0 ** (attempt - 1))
            LOG.warning("Send attempt %d failed: %s; retrying in %.1fs", attempt, error, delay)
            time.sleep(delay)


class RecentEventCache:
    """Suppress exact duplicate normalized events from overlapping access logs."""

    def __init__(self, ttl_seconds: float = 2.0) -> None:
        self.ttl = ttl_seconds
        self.items: dict[str, float] = {}

    @staticmethod
    def fingerprint(event: dict[str, Any]) -> str:
        fingerprint_fields = {
            "event_key": event.get("event_key"),
            "observed_at": event.get("observed_at"),
            "source": event.get("effective_source_ip"),
            "method": event.get("http_method"),
            "path": event.get("url_path"),
            "status": event.get("status_code"),
            "username": event.get("username"),
            "outcome": event.get("event_outcome"),
            "failure_count": event.get("failure_count"),
        }
        return hashlib.sha256(
            json.dumps(fingerprint_fields, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()

    def _expire(self, now: float) -> None:
        self.items = {key: expiry for key, expiry in self.items.items() if expiry > now}

    def is_duplicate(self, event: dict[str, Any]) -> bool:
        now = time.monotonic()
        self._expire(now)
        return self.fingerprint(event) in self.items

    def remember(self, event: dict[str, Any]) -> None:
        now = time.monotonic()
        self._expire(now)
        self.items[self.fingerprint(event)] = now + self.ttl


class Forwarder:
    def __init__(self) -> None:
        auth_logs = csv_values(os.getenv("AUTH_EVENT_LOGS"), DEFAULT_AUTH_LOGS)
        forward_http = as_bool(os.getenv("FORWARD_HTTP_ACCESS_EVENTS"), False)
        http_logs = csv_values(os.getenv("HTTP_ACCESS_LOGS"), DEFAULT_HTTP_LOGS) if forward_http else []
        # Preserve order while removing duplicates.
        self.paths = list(dict.fromkeys(auth_logs + http_logs))
        self.poll_interval = max(0.1, float(os.getenv("FORWARDER_POLL_INTERVAL", "1.0")))
        self.start_at_end = as_bool(os.getenv("FORWARDER_START_AT_END"), True)
        self.hostname = os.getenv("COLLECTOR_HOSTNAME", "").strip() or socket.getfqdn() or socket.gethostname()
        self.state = StateStore(Path(os.getenv("FORWARDER_STATE_FILE", "/var/lib/cve-radar-eda-forwarder/state.json")))
        self.state.load()
        self.sender = EventSender()
        self.dedup = RecentEventCache(float(os.getenv("FORWARDER_DEDUP_TTL", "2.0")))
        for path in self.paths:
            self.state.cursors.setdefault(path, FileCursor(path=path))

    def initialize_cursor(self, cursor: FileCursor, stat_result: os.stat_result) -> None:
        if cursor.initialized and cursor.inode == stat_result.st_ino and cursor.offset <= stat_result.st_size:
            return
        rotated = cursor.initialized and cursor.inode and cursor.inode != stat_result.st_ino
        truncated = cursor.initialized and cursor.inode == stat_result.st_ino and cursor.offset > stat_result.st_size
        cursor.inode = stat_result.st_ino
        if rotated or truncated:
            cursor.offset = 0
            LOG.info("Reopened rotated/truncated log: %s", cursor.path)
        elif not cursor.initialized:
            cursor.offset = stat_result.st_size if self.start_at_end else 0
            LOG.info(
                "Started monitoring %s at offset %d (%s)",
                cursor.path,
                cursor.offset,
                "new events only" if self.start_at_end else "from beginning",
            )
        cursor.initialized = True
        cursor.partial = ""

    def process_path(self, cursor: FileCursor) -> bool:
        try:
            stat_result = os.stat(cursor.path)
        except FileNotFoundError:
            if cursor.initialized:
                LOG.warning("Monitored file disappeared; waiting for recreation: %s", cursor.path)
                cursor.initialized = False
                cursor.inode = 0
                cursor.offset = 0
                cursor.partial = ""
            return False
        except PermissionError as exc:
            LOG.error("Permission denied reading %s: %s", cursor.path, exc)
            return False

        self.initialize_cursor(cursor, stat_result)
        if stat_result.st_size <= cursor.offset:
            return False

        sent_any = False
        with open(cursor.path, "r", encoding="utf-8", errors="replace") as handle:
            handle.seek(cursor.offset)
            while True:
                line = handle.readline()
                if not line:
                    break
                # Leave an incomplete final line unread until its newline arrives.
                if not line.endswith("\n"):
                    break
                line_end_offset = handle.tell()
                content = line
                sequence = self.state.next_sequence()
                event = normalize_line(
                    content,
                    sequence=sequence,
                    hostname=self.hostname,
                    source_file=cursor.path,
                )
                if event is None:
                    cursor.offset = line_end_offset
                    LOG.debug("Ignored unsupported line from %s", cursor.path)
                    continue
                # Login failures and non-admin login successes remain in the
                # application log for MCP evidence collection, but do not wake EDA.
                # Every successful admin login is forwarded immediately; AI decides
                # whether the preceding five-minute window contains >=3 failures.
                if event.get("event_key") in {LOGIN_FAILURE_KEY, LOGIN_SUCCESS_KEY}:
                    cursor.offset = line_end_offset
                    LOG.debug("Recorded login attempt without emitting an EDA wake-up event")
                    continue
                if self.dedup.is_duplicate(event):
                    cursor.offset = line_end_offset
                    LOG.debug("Suppressed duplicate event from %s", cursor.path)
                    continue
                LOG.info(
                    "Recognized event_key=%s user=%r source=%s path=%s",
                    event.get("event_key", ""),
                    event.get("username", ""),
                    event.get("effective_source_ip", "unknown"),
                    event.get("url_path", ""),
                )
                # Advance and persist the cursor only after a successful delivery.
                # A transient Event Stream failure therefore retries the same line.
                self.sender.send(event)
                cursor.offset = line_end_offset
                self.dedup.remember(event)
                self.state.save()
                LOG.info(
                    "Sent event_key=%s event_id=%s sequence=%s",
                    event.get("event_key", ""),
                    event.get("event_id", ""),
                    event.get("collector", {}).get("sequence", ""),
                )
                sent_any = True
        self.state.save()
        return sent_any

    def run(self) -> None:
        LOG.info("Starting cve-radar-eda-forwarder v%s", VERSION)
        LOG.info("Monitoring %d files: %s", len(self.paths), ", ".join(self.paths))
        while not STOP_REQUESTED:
            for cursor in self.state.cursors.values():
                try:
                    self.process_path(cursor)
                except Exception:
                    LOG.exception("Failed while processing %s", cursor.path)
            time.sleep(self.poll_interval)
        self.state.save()
        LOG.info("Forwarder stopped")


def request_stop(signum: int, _frame: Any) -> None:
    global STOP_REQUESTED
    LOG.info("Received signal %s; stopping", signum)
    STOP_REQUESTED = True


def configure_logging() -> None:
    level_name = os.getenv("FORWARDER_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        stream=sys.stderr,
    )


def main() -> int:
    configure_logging()
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        Forwarder().run()
    except Exception as exc:
        LOG.exception("Forwarder startup/runtime failure: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
