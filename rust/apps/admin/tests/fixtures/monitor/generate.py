"""管理画面の監視（webapp_admin/metrics.py）の基準（expected.json）を、本物の Python で作る。

Rust の管理画面（rust/apps/admin）の tests/monitor_golden.rs が読む。例は cases.json に 6 つの節で書く:

- cases（API）: GET /admin/api/metrics・/admin/api/incidents を、本物の管理画面（webapp_admin/app.py の app）に
  starlette の TestClient で通す（../admin_harness.py の run_cases。セッション・確かめ・エラーの答え・見出しも本物）。
  差し替えるのは webapp_admin.metrics の中の名前だけ: psutil（例の host の値を返す偽物）・time（例の now で止めた
  時計）・datetime（now を地方時〔日本時間〕にした「いま」）・_APP_STARTED_AT（例の started）・_REQUEST_TIMESTAMPS（例の
  requests）。インシデントのファイルは例の incidents（無い・文字・行の並び・16 進のバイト）を、例ごとの置き場
  （ADMIN_MONITOR_DIR）に置く。しきい値などの環境変数は例の env
- functions: 整形の関数（_format_duration・_format_bytes・load_tone・sla_tone・_clamp_percent）と、Python の
  format(x, ".Nf")・format(x, "g")・round(x, N)・sum(小数)。小数は repr の文字で渡し、答えの小数も repr で書く
  （JSON の数の読み方の違いに左右されないように）
- procfs: 偽物の /proc（stat・meminfo・zoneinfo）を psutil の PROCFS_PATH に向けて、本物の psutil 7.2.2 に読ませた
  virtual_memory()・boot_time()・cpu_percent()（stat から stat_after までの割合）
- downtime: 心拍のファイル（heartbeat.json）を置いて _record_startup_downtime() を呼び、書かれたインシデントの行
- heartbeat: _write_heartbeat() が書いた heartbeat.json の中身と、置き場に残ったファイル
- alerts: _record_threshold_alerts() を時刻を進めながら呼び、書かれたインシデントの行（間隔をあけるのも含めて）

インシデントの ID（uuid4）は例ごとに 1 から f"{ID_BASE + n:032x}"。本物の監視のスレッド（app を読み込むと始まる）は、
間隔をとても長くし、起動のときの処理（心拍を書く）が済むのを待ってから例を回す（例の置き場に書かれないように）。
例は 2 回作ってバイトまで同じになる（時刻・ID・置き場の中身をどれも例で決める）。

作り直すとき（本番と同じ依存 requirements.txt で。CI の「基準」が tools/fixtures/regen.py から回す）:

    python rust/apps/admin/tests/fixtures/monitor/generate.py

**`from __future__ import annotations` を書かないこと**（管理画面の道具の決まり。FastAPI が注釈を引けなくなる）。
"""

import json
import os
import sys
import tempfile
import time
import warnings
from collections import deque
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import admin_harness as harness  # noqa: E402

CASES = HERE / "cases.json"
OUTPUT = HERE / "expected.json"
GENERATED_BY = "rust/apps/admin/tests/fixtures/monitor/generate.py"
# インシデントの ID の頭（例ごとに 1 から足す）。
ID_BASE = 0xA7000000
# 監視の振る舞いを変える環境変数。CI や手元に残っていても基準が変わらないよう、最初に消す（要る例は env で渡す）。
MONITOR_ENV = (
    "ADMIN_TPS_TARGET",
    "ADMIN_CPU_ALERT_PERCENT",
    "ADMIN_MEMORY_ALERT_PERCENT",
    "ADMIN_TPS_ALERT_PERCENT",
    "ADMIN_MONITOR_ALERT_COOLDOWN_SECONDS",
    "ADMIN_DOWNTIME_GRACE_SECONDS",
)
# 本物の監視のスレッドを眠らせておく間隔（秒。約 31 年）。
IDLE_INTERVAL = "1000000000"
# API の例で、例が書かなかったときに偽物の psutil が返すもの。
DEFAULT_HOST = {
    "cpu_percent": "0.0",
    "memory": {"percent": "0.0", "used": 0, "total": 0},
    "cpu_count": 1,
    "boot_time": "0.0",
}


class FakeClock:
    """webapp_admin.metrics の time の代わり（time() は例の時刻、sleep() は待たない）。"""

    def __init__(self, now: float) -> None:
        """止める時刻を決める。"""
        self._now = now

    def time(self) -> float:
        """止めた時刻。"""
        return self._now

    def sleep(self, seconds: float) -> None:
        """待たない（監視の巡回は基準では回さない）。"""
        return None


class IdSequence:
    """uuid.uuid4 の代わり。呼ぶたびに ID_BASE + 1、+ 2 … の hex を持つものを返す。"""

    def __init__(self) -> None:
        """1 から数え始める。"""
        self.count = 0

    def __call__(self) -> Any:
        """次の ID（hex だけ使われる）。"""
        self.count += 1
        return SimpleNamespace(hex=f"{ID_BASE + self.count:032x}")


class FakePsutil:
    """psutil の代わり。例の host の値を返す（{"$raise": …} ならその例外を投げる）。"""

    def __init__(self, host: dict[str, Any]) -> None:
        """例の host（足りない項目は DEFAULT_HOST）。"""
        self._host = {**DEFAULT_HOST, **host}

    def _value(self, name: str) -> Any:
        """1 つの項目。$raise なら例外。"""
        spec = self._host[name]
        if isinstance(spec, dict) and "$raise" in spec:
            raise harness._exception(spec)
        return spec

    def cpu_percent(self, interval: float | None = None) -> float:
        """cpu_percent(interval=0.1) の代わり（待たない）。"""
        return float(self._value("cpu_percent"))

    def virtual_memory(self) -> Any:
        """virtual_memory() の代わり（percent・used・total だけ）。"""
        memory = self._value("memory")
        return SimpleNamespace(percent=float(memory["percent"]), used=int(memory["used"]), total=int(memory["total"]))

    def cpu_count(self, logical: bool = True) -> Any:
        """cpu_count(logical=True) の代わり（None もそのまま）。"""
        return self._value("cpu_count")

    def boot_time(self) -> float:
        """boot_time() の代わり。"""
        return float(self._value("boot_time"))


def frozen_datetime(now: float) -> Any:
    """webapp_admin.metrics の datetime の代わり（now() だけを例の時刻の地方時にする。ほかは本物）。"""
    from datetime import datetime as real

    class FrozenDatetime(real):
        """datetime.now() を止めた datetime。"""

        @classmethod
        def now(cls, tz: Any = None) -> Any:
            """例の時刻（地方時。harness が日本時間にしてある）。"""
            return real.fromtimestamp(now, tz)

    return FrozenDatetime


def write_input(path: Path, spec: Any) -> None:
    """例のファイルの中身を書く（None は置かない・文字はそのまま・{"lines": [...]} は 1 行ずつ・hex はバイト）。"""
    if spec is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(spec, str):
        path.write_bytes(spec.encode("utf-8"))
    elif "lines" in spec:
        path.write_bytes("".join(line + "\n" for line in spec["lines"]).encode("utf-8"))
    else:
        path.write_bytes(bytes.fromhex(spec["hex"]))


def read_lines(path: Path) -> list[str]:
    """インシデントのファイルの行（無ければ空。空の行は落とす）。"""
    if not path.exists():
        return []
    return [line for line in path.read_text(encoding="utf-8").split("\n") if line]


def _patches(service: dict[str, Any], calls: list[dict[str, Any]], library: dict[str, Any]) -> list[Any]:
    """API の例の service から、webapp_admin.metrics の名前と環境変数を差し替える patch を作る（置き場も作る）。"""
    from webapp_admin import metrics as admin_metrics

    monitor_dir = Path(tempfile.mkdtemp(prefix="admin-fixture-monitor-"))
    write_input(monitor_dir / "incidents.jsonl", service.get("incidents"))
    now = float(service.get("now", "0"))
    env = {"ADMIN_MONITOR_DIR": str(monitor_dir), **(service.get("env") or {})}
    requests = deque(float(t) for t in service.get("requests", []))
    return [
        patch.dict(os.environ, env),
        patch.object(admin_metrics, "psutil", FakePsutil(service.get("host") or {})),
        patch.object(admin_metrics, "time", FakeClock(now)),
        patch.object(admin_metrics, "datetime", frozen_datetime(now)),
        patch.object(admin_metrics, "_APP_STARTED_AT", float(service.get("started", "0"))),
        patch.object(admin_metrics, "_REQUEST_TIMESTAMPS", requests),
    ]


def run_functions(spec: dict[str, Any]) -> dict[str, Any]:
    """整形の関数と、Python の小数の書き方・丸め方・足し方の答え。"""
    from webapp_admin import metrics as m

    return {
        "format_duration": [[x, m._format_duration(float(x))] for x in spec["format_duration"]],
        "format_bytes": [[x, m._format_bytes(float(x))] for x in spec["format_bytes"]],
        "load_tone": [[p, a, m.load_tone(float(p), float(a))] for p, a in spec["load_tone"]],
        "sla_tone": [[p, m.sla_tone(float(p))] for p in spec["sla_tone"]],
        "clamp_percent": [[x, repr(m._clamp_percent(float(x)))] for x in spec["clamp_percent"]],
        "fixed": [[x, n, format(float(x), f".{n}f")] for x, n in spec["fixed"]],
        "general": [[x, format(float(x), "g")] for x in spec["general"]],
        "round": [[x, n, repr(round(float(x), n))] for x, n in spec["round"]],
        "sum": [[xs, repr(sum(float(x) for x in xs))] for xs in spec["sum"]],
    }


def attempt(action: Callable[[], Any]) -> dict[str, Any]:
    """1 つを読み、{"value": 答え} か {"error": 例外の型の名前} にする。"""
    try:
        return {"value": action()}
    except Exception as exc:  # noqa: BLE001 - 読めないことも基準に書く
        return {"error": type(exc).__name__}


def run_procfs(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """偽物の /proc を本物の psutil に読ませた答え。"""
    import psutil

    out = []
    for case in cases:
        with tempfile.TemporaryDirectory(prefix="admin-fixture-proc-") as tmp:
            first = Path(tmp) / "first"
            second = Path(tmp) / "second"
            write_input(first / "stat", case["stat"])
            write_input(first / "meminfo", case["meminfo"])
            write_input(first / "zoneinfo", case.get("zoneinfo"))
            write_input(second / "stat", case.get("stat_after", case["stat"]))
            saved = psutil.PROCFS_PATH
            try:
                psutil.PROCFS_PATH = str(first)
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    memory = attempt(lambda: _memory_record(psutil.virtual_memory()))
                boot = attempt(lambda: repr(psutil.boot_time()))
                cpu = attempt(lambda: _cpu_between(psutil, first, second))
            finally:
                psutil.PROCFS_PATH = saved
        out.append({"name": case["name"], "memory": memory, "boot_time": boot, "cpu_percent": cpu})
    return out


def _memory_record(memory: Any) -> dict[str, Any]:
    """virtual_memory() のうち、画面が使う 3 つ（割合は repr）。"""
    return {"total": memory.total, "used": memory.used, "percent": repr(memory.percent)}


def _cpu_between(psutil: Any, first: Path, second: Path) -> str:
    """first の stat から second の stat までの cpu_percent（interval=None を 2 回。1 回目で first を控えさせる）。"""
    psutil.PROCFS_PATH = str(first)
    psutil.cpu_percent(interval=None)
    psutil.PROCFS_PATH = str(second)
    return repr(psutil.cpu_percent(interval=None))


def run_downtime(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """心拍のファイルを置いて _record_startup_downtime() を呼び、書かれた行を返す。"""
    from webapp_admin import metrics as m

    out = []
    for case in cases:
        with tempfile.TemporaryDirectory(prefix="admin-fixture-downtime-") as tmp:
            write_input(Path(tmp) / "heartbeat.json", case.get("heartbeat"))
            env = {"ADMIN_MONITOR_DIR": tmp, **(case.get("env") or {})}
            ids = IdSequence()
            error = None
            with (
                patch.dict(os.environ, env),
                patch.object(m, "time", FakeClock(float(case["now"]))),
                patch.object(m, "uuid", SimpleNamespace(uuid4=ids)),
            ):
                try:
                    m._record_startup_downtime()
                except Exception as exc:  # noqa: BLE001 - 起動の処理が止まることも基準に書く
                    error = type(exc).__name__
            lines = read_lines(Path(tmp) / "incidents.jsonl")
        out.append({"name": case["name"], "error": error, "lines": lines})
    return out


def run_heartbeat(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """_write_heartbeat() が書いた中身と、置き場に残ったファイルの名前。"""
    from webapp_admin import metrics as m

    out = []
    for case in cases:
        with tempfile.TemporaryDirectory(prefix="admin-fixture-heartbeat-") as tmp:
            target = Path(tmp) / "nested" / "monitor"
            pid = int(case["pid"])
            with (
                patch.dict(os.environ, {"ADMIN_MONITOR_DIR": str(target)}),
                patch.object(m, "time", FakeClock(float(case["now"]))),
                patch.object(m, "_APP_STARTED_AT", float(case["started"])),
                patch.object(m, "os", SimpleNamespace(getpid=lambda: pid, getenv=os.getenv)),
            ):
                m._write_heartbeat()
            text = (target / "heartbeat.json").read_text(encoding="utf-8")
            files = sorted(path.name for path in target.iterdir())
        out.append({"name": case["name"], "text": text, "files": files})
    return out


def run_alerts(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """時刻を進めながら _record_threshold_alerts() を呼び、書かれた行を返す。"""
    from webapp_admin import metrics as m

    out = []
    for case in cases:
        with tempfile.TemporaryDirectory(prefix="admin-fixture-alerts-") as tmp:
            env = {"ADMIN_MONITOR_DIR": tmp, **(case.get("env") or {})}
            ids = IdSequence()
            with (
                patch.dict(os.environ, env),
                patch.dict(m._LAST_ALERT_AT, clear=True),
                patch.object(m, "uuid", SimpleNamespace(uuid4=ids)),
            ):
                for tick in case["ticks"]:
                    metrics = {"metrics": {key: _meter(value) for key, value in tick["meters"].items()}}
                    with patch.object(m, "time", FakeClock(float(tick["now"]))):
                        m._record_threshold_alerts(metrics)
            lines = read_lines(Path(tmp) / "incidents.jsonl")
        out.append({"name": case["name"], "lines": lines})
    return out


def _meter(value: dict[str, Any]) -> dict[str, Any]:
    """例のメーター（label・percent〔repr の文字〕・detail）を、collect_host_metrics の形にする。"""
    return {"label": value["label"], "percent": float(value["percent"]), "detail": value["detail"]}


def wait_for_monitor_startup(timeout: float = 30.0) -> None:
    """本物の監視のスレッドが、起動のときの処理（心拍を書く）を済ませるまで待つ（例の置き場に書かれないように）。"""
    heartbeat = Path(os.environ["SETTINGS_DIR"]) / "admin_monitor" / "heartbeat.json"
    deadline = time.monotonic() + timeout
    while not heartbeat.exists():
        if time.monotonic() > deadline:
            raise SystemExit("監視のスレッドが心拍を書かない（起動のときの処理が終わらない）")
        time.sleep(0.05)


def build(document: dict[str, Any]) -> dict[str, Any]:
    """例の文書を回して、基準の中身を作る（app を読み込む前に、app の要らない節を先に回す）。"""
    harness.prepare_environment(document["secret"], {"ADMIN_MONITOR_INTERVAL_SECONDS": IDLE_INTERVAL})
    for name in MONITOR_ENV:
        os.environ.pop(name, None)
    functions = run_functions(document["functions"])
    procfs = run_procfs(document["procfs"])
    downtime = run_downtime(document["downtime"])
    heartbeat = run_heartbeat(document["heartbeat"])
    alerts = run_alerts(document["alerts"])
    from webapp_admin.app import app

    wait_for_monitor_startup()
    return {
        **harness.header(document, GENERATED_BY),
        "id_base": ID_BASE,
        "cases": harness.run_cases(app, document, _patches),
        "functions": functions,
        "procfs": procfs,
        "downtime": downtime,
        "heartbeat": heartbeat,
        "alerts": alerts,
    }


def main(argv: list[str]) -> int:
    """cases.json（引数があればそのパス）を読み、expected.json（2 つ目の引数があればそのパス）に書く。"""
    source = Path(argv[0]) if argv else CASES
    target = Path(argv[1]) if len(argv) > 1 else OUTPUT
    document = json.loads(source.read_text(encoding="utf-8"))
    harness.write_json(target, build(document))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
