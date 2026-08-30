"""requirements.txt のピンが Docker と同じ条件で解決できるか検査する。

    python tools/check_requirements.py

なぜ要るか:
    requirements.txt は再現性のために全てを == で固定している。その版を
    「手元の環境に入っているもの」から取ってくると、手元が Docker と違う
    Python である場合や、--no-deps で入れたせいで他パッケージの制約を
    満たしていない場合に、壊れたピンをそのまま書いてしまう。
    実際 PyNaCl==1.6.2 を固定して、discord.py[voice] の PyNaCl<1.6 と
    衝突し docker build が落ちた。

    pip の --python-version はマーカーを実行中の処理系で評価してしまう箇所が
    あり、クロス環境の解決確認が当てにならない。ここでは PyPI のメタデータを
    直接読み、マーカーを Dockerfile の Python / linux として自分で評価する。

PyPI へ接続する。オフラインでは実行できない。
"""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

ROOT = Path(__file__).resolve().parent.parent
REQUIREMENTS = ROOT / "requirements.txt"
DOCKERFILE = ROOT / "Dockerfile"


def target_python() -> str:
    """Dockerfile の FROM から Python のバージョンを読む。"""
    match = re.search(r"^FROM\s+python:(\d+\.\d+)", DOCKERFILE.read_text(encoding="utf-8"), re.M)
    if not match:
        print("Dockerfile から Python のバージョンを読めませんでした。3.11 とみなします。")
        return "3.11"
    return match.group(1)


def environment(python_version: str) -> dict[str, str]:
    env = dict(default_environment())
    env.update(
        {
            "python_version": python_version,
            "python_full_version": f"{python_version}.0",
            "sys_platform": "linux",
            "platform_system": "Linux",
            "platform_machine": "x86_64",
            "os_name": "posix",
            "implementation_name": "cpython",
        }
    )
    return env


_cache: dict[tuple[str, str | None], dict | None] = {}


def pypi(name: str, version: str | None) -> dict | None:
    key = (name.lower(), version)
    if key in _cache:
        return _cache[key]
    url = f"https://pypi.org/pypi/{name}/{version}/json" if version else f"https://pypi.org/pypi/{name}/json"
    try:
        with urllib.request.urlopen(url, timeout=40) as response:
            data = json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        data = None
    _cache[key] = data
    return data


def pinned_version(requirement: Requirement) -> str | None:
    for spec in requirement.specifier:
        if spec.operator == "==":
            return spec.version
    return None


def parse_requirements() -> list[Requirement]:
    out: list[Requirement] = []
    for raw in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = raw.split("#")[0].strip()
        if line:
            out.append(Requirement(line))
    return out


def main() -> int:
    python_version = target_python()
    env = environment(python_version)
    requirements = parse_requirements()
    pinned = {r.name.lower().replace("_", "-"): v for r in requirements if (v := pinned_version(r))}

    print(f"対象: Python {python_version} / linux（Dockerfile より）")
    print(f"固定済み {len(pinned)} / 総数 {len(requirements)}\n")

    problems: list[str] = []
    unreachable: list[str] = []

    for requirement in requirements:
        version = pinned_version(requirement)
        info = pypi(requirement.name, version)
        if info is None:
            unreachable.append(f"{requirement}")
            continue
        meta = info["info"]

        requires_python = meta.get("requires_python") or ""
        if requires_python:
            probe = Version(f"{python_version}.0")
            if not SpecifierSet(requires_python).contains(probe, prereleases=True):
                problems.append(
                    f"{requirement.name}=={version} は Python {python_version} に対応していません"
                    f"（Requires-Python: {requires_python}）"
                )

        extras = set(requirement.extras)
        for raw_dep in meta.get("requires_dist") or []:
            try:
                dep = Requirement(raw_dep)
            except Exception:
                continue
            if dep.marker is not None:
                applies = False
                for extra in extras | {""}:
                    probe_env = dict(env, extra=extra)
                    try:
                        if dep.marker.evaluate(probe_env):
                            applies = True
                            break
                    except Exception:
                        continue
                if not applies:
                    continue

            ours = pinned.get(dep.name.lower().replace("_", "-"))
            if ours and not dep.specifier.contains(Version(ours), prereleases=True):
                problems.append(
                    f"{requirement.name}=={version} は {dep.name}{dep.specifier} を要求しますが、"
                    f"requirements.txt は {dep.name}=={ours} を固定しています"
                )

    for line in unreachable:
        print(f"  ?   {line}  メタデータを取得できませんでした（ネットワーク？）")

    if problems:
        print("\n矛盾が見つかりました:\n")
        for problem in sorted(set(problems)):
            print(f"  [NG] {problem}")
        print("\nこのままでは docker build の pip install が失敗します。")
        return 1

    if unreachable:
        print("\n一部を確認できませんでしたが、確認できた範囲に矛盾はありません。")
        return 0

    print("矛盾はありません。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
