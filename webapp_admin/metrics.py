import json
import os
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil


_APP_STARTED_AT = time.time()
_REQUEST_TIMESTAMPS: deque[float] = deque()
_REQUEST_HISTORY_SECONDS = 60
_TPS_WINDOW_SECONDS = 15
_FILE_LOCK = threading.Lock()
_MONITOR_LOCK = threading.Lock()
_MONITOR_STARTED = False
_LAST_ALERT_AT: dict[str, float] = {}


def record_request() -> None:
    now = time.time()
    _REQUEST_TIMESTAMPS.append(now)
    _prune_requests(now)


def record_error_response(status_code: int, request_info: dict[str, Any]) -> None:
    if status_code < 500:
        return
    record_incident(
        kind="http_error",
        severity="critical",
        title=f"HTTP {status_code}",
        message="管理UIで 5xx レスポンスが発生しました。",
        metadata={"status_code": status_code, **request_info},
    )


def record_exception(exception: BaseException, request_info: dict[str, Any]) -> None:
    record_incident(
        kind="exception",
        severity="critical",
        title=type(exception).__name__,
        message=str(exception)[:500] or "Unhandled exception",
        metadata=request_info,
    )


def start_background_monitor(logger: Any | None = None) -> None:
    global _MONITOR_STARTED
    with _MONITOR_LOCK:
        if _MONITOR_STARTED:
            return
        _MONITOR_STARTED = True

    try:
        _monitor_dir().mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        if logger:
            logger.warning("admin monitor dir init failed: %s", exc)

    thread = threading.Thread(
        target=_monitor_loop,
        args=(logger,),
        name="admin-health-monitor",
        daemon=True,
    )
    thread.start()


def load_tone(percent: float, alert_at: float) -> str:
    """メーターの色。しきい値（アラートを記録する値）と同じ物差しで決める。

    色を固定にしていると、90% でも 5% でも同じ見た目になり、
    「色が付いている＝何かある」という読み方ができなくなる。
    """
    if percent >= alert_at:
        return "danger"
    if percent >= alert_at * 0.8:
        return "warning"
    return "success"


def sla_tone(percent: float) -> str:
    if percent >= 99.9:
        return "success"
    if percent >= 99.0:
        return "warning"
    return "danger"


def collect_host_metrics() -> dict:
    now = time.time()
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    tps = _request_tps(now)
    tps_target = max(_env_float("ADMIN_TPS_TARGET", 50.0), 0.01)
    tps_percent = _clamp_percent((tps / tps_target) * 100)
    boot_time = psutil.boot_time()
    sla_percent = _month_to_date_sla_percent(now)

    return {
        "updated_at": datetime.now().strftime("%H:%M:%S"),
        "metrics": {
            "cpu": {
                "label": "CPU",
                "percent": _clamp_percent(cpu_percent),
                "display": f"{cpu_percent:.1f}%",
                "detail": f"論理コア {psutil.cpu_count(logical=True) or 1}",
                "tone": load_tone(cpu_percent, _env_float("ADMIN_CPU_ALERT_PERCENT", 90.0)),
            },
            "memory": {
                "label": "Memory",
                "percent": _clamp_percent(memory.percent),
                "display": f"{memory.percent:.1f}%",
                "detail": f"{_format_bytes(memory.used)} / {_format_bytes(memory.total)}",
                "tone": load_tone(memory.percent, _env_float("ADMIN_MEMORY_ALERT_PERCENT", 90.0)),
            },
            "tps": {
                "label": "TPS",
                "percent": tps_percent,
                # 目盛りは目標に対する割合、数字は実測値。"0.4%" とだけ出ていると
                # 秒間リクエスト数が 0.4 なのか、目標の 0.4% なのか読めない。
                "display": f"{tps:.2f} req/s",
                "detail": f"目標 {tps_target:g} req/s の {tps_percent:.0f}%",
                "tone": load_tone(tps_percent, _env_float("ADMIN_TPS_ALERT_PERCENT", 100.0)),
            },
            "sla": {
                "label": "SLA",
                "percent": _clamp_percent(sla_percent),
                "display": f"{sla_percent:.2f}%",
                "detail": f"記録済み停止 {_format_duration(_downtime_seconds_month_to_date(now))}",
                "tone": sla_tone(sla_percent),
            },
        },
        "runtime": {
            "admin_app": _format_duration(now - _APP_STARTED_AT),
            "host": _format_duration(now - boot_time),
        },
    }


def list_incidents(limit: int = 20) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 200))
    path = _incidents_file()
    if not path.exists():
        return []

    with _FILE_LOCK:
        lines = path.read_text(encoding="utf-8").splitlines()

    incidents: list[dict[str, Any]] = []
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            incident = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(incident, dict):
            incidents.append(_public_incident(incident))
        if len(incidents) >= limit:
            break
    return incidents


def record_incident(
    *,
    kind: str,
    severity: str,
    title: str,
    message: str,
    metadata: dict[str, Any] | None = None,
    start_epoch: float | None = None,
    end_epoch: float | None = None,
    duration_seconds: float | None = None,
) -> dict[str, Any]:
    now = time.time()
    incident = {
        "id": uuid.uuid4().hex,
        "kind": kind,
        "severity": severity,
        "title": title,
        "message": message,
        "created_epoch": now,
        "created_at": _iso(now),
        "start_epoch": start_epoch,
        "start_at": _iso(start_epoch) if start_epoch else None,
        "end_epoch": end_epoch,
        "end_at": _iso(end_epoch) if end_epoch else None,
        "duration_seconds": round(duration_seconds, 3) if duration_seconds is not None else None,
        "metadata": metadata or {},
    }
    _append_jsonl(_incidents_file(), incident)
    return incident


def _monitor_loop(logger: Any | None) -> None:
    try:
        _record_startup_downtime()
        _write_heartbeat()
    except Exception as exc:
        if logger:
            logger.warning("admin monitor startup failed: %s", exc)

    interval = max(_env_float("ADMIN_MONITOR_INTERVAL_SECONDS", 30.0), 5.0)
    while True:
        time.sleep(interval)
        try:
            metrics = collect_host_metrics()
            _write_heartbeat()
            _record_threshold_alerts(metrics)
        except Exception as exc:
            if logger:
                logger.warning("admin monitor tick failed: %s", exc)


def _record_startup_downtime() -> None:
    heartbeat = _read_json(_heartbeat_file())
    last_seen = heartbeat.get("last_seen_epoch") if isinstance(heartbeat, dict) else None
    if not isinstance(last_seen, (int, float)):
        return

    now = time.time()
    grace = max(_env_float("ADMIN_DOWNTIME_GRACE_SECONDS", 120.0), 1.0)
    downtime = now - float(last_seen)
    if downtime <= grace:
        return

    record_incident(
        kind="downtime",
        severity="critical",
        title="管理UIダウンタイム",
        message="前回 heartbeat から復帰までの空白をダウンタイムとして記録しました。",
        start_epoch=float(last_seen),
        end_epoch=now,
        duration_seconds=downtime,
        metadata={"grace_seconds": grace, "source": "startup_heartbeat_gap"},
    )


def _record_threshold_alerts(metrics: dict[str, Any]) -> None:
    thresholds = {
        "cpu": _env_float("ADMIN_CPU_ALERT_PERCENT", 90.0),
        "memory": _env_float("ADMIN_MEMORY_ALERT_PERCENT", 90.0),
        "tps": _env_float("ADMIN_TPS_ALERT_PERCENT", 100.0),
    }
    metric_map = metrics.get("metrics", {})
    if not isinstance(metric_map, dict):
        return

    for key, threshold in thresholds.items():
        metric = metric_map.get(key)
        if not isinstance(metric, dict):
            continue
        percent = float(metric.get("percent") or 0)
        if percent < threshold:
            continue
        _record_alert_with_cooldown(
            key=f"threshold:{key}",
            kind="resource_alert",
            severity="warning",
            title=f"{metric.get('label', key)} 使用率アラート",
            # display は指標ごとに単位が違う（TPS は req/s）。しきい値は割合なので割合で書く
            message=f"{percent:.1f}% がしきい値 {threshold:g}% を超えました。",
            metadata={"metric": key, "percent": percent, "threshold": threshold, "detail": metric.get("detail")},
        )


def _record_alert_with_cooldown(
    *,
    key: str,
    kind: str,
    severity: str,
    title: str,
    message: str,
    metadata: dict[str, Any],
) -> None:
    now = time.time()
    cooldown = max(_env_float("ADMIN_MONITOR_ALERT_COOLDOWN_SECONDS", 300.0), 0.0)
    last_at = _LAST_ALERT_AT.get(key, 0)
    if now - last_at < cooldown:
        return
    _LAST_ALERT_AT[key] = now
    record_incident(kind=kind, severity=severity, title=title, message=message, metadata=metadata)


def _write_heartbeat() -> None:
    now = time.time()
    _write_json(
        _heartbeat_file(),
        {
            "last_seen_epoch": now,
            "last_seen_at": _iso(now),
            "pid": os.getpid(),
            "app_started_epoch": _APP_STARTED_AT,
            "app_started_at": _iso(_APP_STARTED_AT),
        },
    )


def _request_tps(now: float) -> float:
    _prune_requests(now)
    window_start = now - _TPS_WINDOW_SECONDS
    count = sum(1 for timestamp in _REQUEST_TIMESTAMPS if timestamp >= window_start)
    return count / _TPS_WINDOW_SECONDS


def _prune_requests(now: float) -> None:
    cutoff = now - _REQUEST_HISTORY_SECONDS
    while _REQUEST_TIMESTAMPS and _REQUEST_TIMESTAMPS[0] < cutoff:
        _REQUEST_TIMESTAMPS.popleft()


def _month_to_date_sla_percent(now: float) -> float:
    current = datetime.fromtimestamp(now, timezone.utc)
    month_start = current.replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp()
    period_seconds = max(now - month_start, 1)
    downtime = _downtime_seconds_for_period(month_start, now)
    uptime = max(period_seconds - downtime, 0)
    return _clamp_percent((uptime / period_seconds) * 100)


def _downtime_seconds_month_to_date(now: float) -> float:
    current = datetime.fromtimestamp(now, timezone.utc)
    month_start = current.replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp()
    return _downtime_seconds_for_period(month_start, now)


def _downtime_seconds_for_period(period_start: float, period_end: float) -> float:
    total = 0.0
    for incident in _iter_incidents():
        if incident.get("kind") != "downtime":
            continue
        start = incident.get("start_epoch")
        end = incident.get("end_epoch")
        if not isinstance(start, (int, float)) or not isinstance(end, (int, float)):
            continue
        overlap_start = max(float(start), period_start)
        overlap_end = min(float(end), period_end)
        if overlap_end > overlap_start:
            total += overlap_end - overlap_start
    return total


def _iter_incidents() -> list[dict[str, Any]]:
    path = _incidents_file()
    if not path.exists():
        return []

    incidents: list[dict[str, Any]] = []
    with _FILE_LOCK:
        lines = path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        try:
            incident = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(incident, dict):
            incidents.append(incident)
    return incidents


def _public_incident(incident: dict[str, Any]) -> dict[str, Any]:
    duration = incident.get("duration_seconds")
    return {
        "id": incident.get("id"),
        "kind": incident.get("kind", "unknown"),
        "severity": incident.get("severity", "info"),
        "title": incident.get("title", "Incident"),
        "message": incident.get("message", ""),
        "created_at": incident.get("created_at", ""),
        "duration": _format_duration(duration) if isinstance(duration, (int, float)) else None,
        "metadata": incident.get("metadata", {}),
    }


def _monitor_dir() -> Path:
    default_dir = Path(__file__).resolve().parent.parent / "data"
    settings_dir = Path(os.getenv("SETTINGS_DIR", str(default_dir)))
    return Path(os.getenv("ADMIN_MONITOR_DIR", str(settings_dir / "admin_monitor")))


def _heartbeat_file() -> Path:
    return _monitor_dir() / "heartbeat.json"


def _incidents_file() -> Path:
    return _monitor_dir() / "incidents.jsonl"


def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    with _FILE_LOCK:
        with path.open("a", encoding="utf-8") as file:
            file.write(line + "\n")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with _FILE_LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with _FILE_LOCK:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
    return data if isinstance(data, dict) else {}


def _iso(epoch: float | None = None) -> str:
    value = time.time() if epoch is None else epoch
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _clamp_percent(value: float) -> float:
    return round(min(max(float(value), 0.0), 100.0), 2)


def _format_bytes(value: float) -> str:
    units = ("B", "KB", "MB", "GB", "TB")
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _format_duration(seconds: float) -> str:
    total = max(int(seconds), 0)
    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"
