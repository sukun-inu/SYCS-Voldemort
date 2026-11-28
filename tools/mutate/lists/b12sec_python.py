"""B12-sec（rust-09 の直し 9 つ）の Python の変異。"""

KIND = "python"
MUTS = [
    (
        "変異なし（通るはず）",
        "services/url_safety.py",
        "return resolved.is_global and not resolved.is_multicast",
        "return resolved.is_global and not resolved.is_multicast",
    ),
    (
        "マルチキャストを通す",
        "services/url_safety.py",
        "return resolved.is_global and not resolved.is_multicast",
        "return resolved.is_global",
    ),
    (
        "解析待ちの上限を見ない",
        "services/virustotal_service.py",
        "        if remaining <= 0:\n            raise VTAnalysisTimeout",
        "        if remaining < -1e9:\n            raise VTAnalysisTimeout",
    ),
    (
        "VT の判定を先頭だけで決める",
        "services/content_moderation.py",
        'mal_max = max((int(r.get("malicious", 0) or 0) for r in vt_results), default=0)',
        'mal_max = max((int(r.get("malicious", 0) or 0) for r in vt_results[:1]), default=0)',
    ),
    (
        "retry-after に上限を付けない",
        "services/groq_client.py",
        "return min(GROQ_MAX_RETRY_AFTER_SECONDS, max(0.0, float(header)))",
        "return max(0.0, float(header))",
    ),
    (
        "SDK の再試行を残す",
        "services/groq_client.py",
        "AsyncGroq(api_key=GROQ_API_KEY, timeout=timeout, max_retries=0)",
        "AsyncGroq(api_key=GROQ_API_KEY, timeout=timeout)",
    ),
    (
        "一時的な失敗を再試行しない",
        "services/groq_client.py",
        "        return exc.status_code in (408, 409) or exc.status_code >= 500\n",
        "        return False\n",
    ),
    (
        "失敗の文を履歴に入れる",
        "services/chatgpt_service.py",
        "            self._trim_history()\n            return FAILURE_REPLY",
        "            final = FAILURE_REPLY",
    ),
    (
        "書き換えの通信の失敗で抜ける",
        "services/security_service.py",
        "            except Exception as e:\n                # Discord の応答（HTTPException）だけでなく",
        "            except discord.HTTPException as e:\n                # Discord の応答（HTTPException）だけでなく",
    ),
    (
        "発言も荒らしに数える",
        "services/security_service.py",
        "if is_vc_raid_ongoing(member.voice.channel.id):",
        "if check_vc_raid(member, member.voice.channel.id):",
    ),
    (
        "畳んだ印を先頭の結果にする",
        "services/security_service.py",
        "worst = max(icons, key=lambda i: _ICON_WEIGHT[i])",
        "worst = icons[0]",
    ),
    (
        "権限不足を失敗と書く",
        "services/security_service.py",
        'why = "権限不足" if result.reason == "forbidden" else "失敗"',
        'why = "失敗"',
    ),
]
