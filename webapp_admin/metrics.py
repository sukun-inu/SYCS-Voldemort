import os
import time
from collections import deque
from datetime import datetime, timezone

import psutil


_APP_STARTED_AT = time.time()
_REQUEST_TIMESTAMPS: deque[float] = deque()
_REQUEST_HISTORY_SECONDS = 60
_TPS_WINDOW_SECONDS = 15


def record_request() -> None:
    now = time.time()
    _REQUEST_TIMESTAMPS.append(now)
    _prune_requests(now)


def collect_host_metrics() -> dict:
    now = time.time()
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    tps = _request_tps(now)
    tps_target = _env_float("ADMIN_TPS_TARGET", 50.0)
    boot_time = psutil.boot_time()
    sla_percent = _month_to_date_sla_percent(now, boot_time)

    return {
        "updated_at": datetime.now().strftime("%H:%M:%S"),
        "metrics": {
            "cpu": {
                "label": "CPU",
                "percent": _clamp_percent(cpu_percent),
                "display": f"{cpu_percent:.1f}%",
                "detail": f"論理コア {psutil.cpu_count(logical=True) or 1}",
                "tone": "accent",
            },
            "memory": {
                "label": "Memory",
                "percent": _clamp_percent(memory.percent),
                "display": f"{memory.percent:.1f}%",
                "detail": f"{_format_bytes(memory.used)} / {_format_bytes(memory.total)}",
                "tone": "success",
            },
            "tps": {
                "label": "TPS",
                "percent": _clamp_percent((tps / tps_target) * 100 if tps_target else 0),
                "display": f"{_clamp_percent((tps / tps_target) * 100 if tps_target else 0):.1f}%",
                "detail": f"{tps:.2f} req/s / 目標 {tps_target:g}",
                "tone": "info",
            },
            "sla": {
                "label": "SLA",
                "percent": _clamp_percent(sla_percent),
                "display": f"{sla_percent:.2f}%",
                "detail": f"ホスト稼働 {_format_duration(now - boot_time)}",
                "tone": "warning",
            },
        },
        "runtime": {
            "admin_app": _format_duration(now - _APP_STARTED_AT),
            "host": _format_duration(now - boot_time),
        },
    }


def _request_tps(now: float) -> float:
    _prune_requests(now)
    window_start = now - _TPS_WINDOW_SECONDS
    count = sum(1 for timestamp in _REQUEST_TIMESTAMPS if timestamp >= window_start)
    return count / _TPS_WINDOW_SECONDS


def _prune_requests(now: float) -> None:
    cutoff = now - _REQUEST_HISTORY_SECONDS
    while _REQUEST_TIMESTAMPS and _REQUEST_TIMESTAMPS[0] < cutoff:
        _REQUEST_TIMESTAMPS.popleft()


def _month_to_date_sla_percent(now: float, boot_time: float) -> float:
    current = datetime.fromtimestamp(now, timezone.utc)
    month_start = current.replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp()
    period_seconds = max(now - month_start, 1)
    uptime_in_period = max(now - max(boot_time, month_start), 0)
    return _clamp_percent((uptime_in_period / period_seconds) * 100)


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
    minutes, _ = divmod(remainder, 60)

    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"
