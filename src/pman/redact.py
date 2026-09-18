"""响应脱敏：剥敏感响应头、按正则抹 JSON 字段、超大响应截断。

脱敏是纵深防御的一层——即使目标站点在响应体里回显 token/session，
也会在返回 AI 之前被抹除。
"""
from __future__ import annotations

import json
import re

REDACTED = "***REDACTED***"


def _compile(patterns: list[str] | None) -> list[re.Pattern]:
    return [re.compile(p, re.IGNORECASE) for p in (patterns or []) if p]


def redact_headers(
    headers: dict,
    strip_patterns: list[str],
    secret_values: list[str] | tuple[str, ...] | None = None,
) -> tuple[dict, int]:
    """剥离敏感响应头，并替换响应头值中出现的已知秘密。"""
    pats = _compile(strip_patterns)
    secrets = _normalize_secrets(secret_values)
    out: dict = {}
    count = 0
    for k, v in headers.items():
        if any(p.fullmatch(k) for p in pats):
            count += 1
            continue
        safe, replaced = _replace_secrets(str(v), secrets)
        out[k] = safe
        count += replaced
    return out, count


def redact_body(
    body_bytes: bytes,
    json_key_patterns: list[str],
    max_bytes: int,
    secret_values: list[str] | tuple[str, ...] | None = None,
) -> tuple[object, int, bool, bool]:
    """返回 (净化后内容, 脱敏计数, 是否截断, 是否 JSON)。

    JSON 场景：递归遍历对象，键名匹配任一正则的字段值替换为占位符。
    非 JSON 场景：按 `key: value` / `key=value` 形态做文本替换。
    """
    original_len = len(body_bytes)
    truncated = original_len > max_bytes
    payload = body_bytes[:max_bytes] if truncated else body_bytes
    text = payload.decode("utf-8", errors="replace")
    pats = _compile(json_key_patterns)
    secrets = _normalize_secrets(secret_values)
    try:
        obj = json.loads(text)
        obj, count = _redact_obj(obj, pats, secrets)
        return obj, count, truncated, True
    except Exception:
        redacted_text, count = _redact_text(text, pats, secrets)
        return redacted_text, count, truncated, False


def redact_payload(
    payload,
    json_key_patterns: list[str],
    secret_values: list[str] | tuple[str, ...] | None = None,
):
    """深度脱敏任意 dict/list，返回脱敏后的副本。

    用于审批载荷、错误详情等“可能落盘或回显给 AI”的结构化数据。
    """
    pats = _compile(json_key_patterns)
    out, _ = _redact_obj(payload, pats, _normalize_secrets(secret_values))
    return out


def _normalize_secrets(secret_values) -> tuple[str, ...]:
    """去重并按长度降序排列，保证长 token 先替换。"""
    values = {
        str(value)
        for value in (secret_values or ())
        if value is not None and str(value) != ""
    }
    return tuple(sorted(values, key=lambda value: (-len(value), value)))


def _replace_secrets(text: str, secrets: tuple[str, ...]) -> tuple[str, int]:
    count = 0
    out = text
    for secret in secrets:
        # 长 token 可能被前后缀包裹（如 ``echo-<token>``），允许子串替换；
        # 短值则要求词边界，避免把 Basic 用户名 ``u`` 误伤整段文本。
        if len(secret) < 8:
            pattern = re.compile(
                r"(?<![A-Za-z0-9_])" + re.escape(secret) + r"(?![A-Za-z0-9_])"
            )
            out, occurrences = pattern.subn(REDACTED, out)
        else:
            occurrences = out.count(secret)
            if occurrences:
                out = out.replace(secret, REDACTED)
        count += occurrences
    return out, count


def _redact_obj(obj, pats: list[re.Pattern], secrets: tuple[str, ...]):
    count = 0
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            safe_key, key_count = _replace_secrets(str(k), secrets)
            count += key_count
            if any(p.search(str(k)) for p in pats):
                out[safe_key] = REDACTED
                count += 1
            else:
                out[safe_key], c = _redact_obj(v, pats, secrets)
                count += c
        return out, count
    if isinstance(obj, list):
        out = []
        for v in obj:
            v2, c = _redact_obj(v, pats, secrets)
            out.append(v2)
            count += c
        return out, count
    if isinstance(obj, str):
        return _replace_secrets(obj, secrets)
    return obj, count


def _redact_text(
    text: str, pats: list[re.Pattern], secrets: tuple[str, ...] = ()
) -> tuple[str, int]:
    """净化 ``key: value`` / ``key=value`` 文本，不拼接用户正则。"""
    count = 0

    token = re.compile(
        r"(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*"
        r"(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;]+)"
    )

    def repl(match: re.Match) -> str:
        nonlocal count
        key = match.group("key")
        if not any(p.search(key) for p in pats):
            return match.group(0)
        count += 1
        return f"{key}={REDACTED}"

    out = token.sub(repl, text)
    safe, replaced = _replace_secrets(out, secrets)
    return safe, count + replaced
