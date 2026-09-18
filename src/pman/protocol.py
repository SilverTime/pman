"""pman 本地协议的稳定返回字段。

Python daemon、MCP 适配层和后续 Rust/Tauri broker 共用这组版本与错误码。
协议字段刻意保持扁平，方便 CLI、JSON-RPC 与 named-pipe 传输复用同一结果。
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import Any

PROTOCOL_NAME = "pman"
PROTOCOL_VERSION = 2

ERROR_OK = "ok"
ERROR_VAULT_LOCKED = "vault_locked"
ERROR_UNKNOWN_SITE = "unknown_site"
ERROR_SITE_INACTIVE = "site_inactive"
ERROR_HARNESS_INVALID = "harness_invalid"
ERROR_POLICY_DENIED = "policy_denied"
ERROR_RATE_LIMITED = "rate_limited"
ERROR_PENDING_APPROVAL = "pending_approval"
ERROR_RESPONSE_BLOCKED = "response_blocked"
ERROR_REQUEST_FAILED = "request_failed"
ERROR_INVALID_REQUEST = "invalid_request"
ERROR_UNKNOWN = "unknown_error"

HTTP_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH"})
ALIAS_REF_PREFIX = "pman-alias-utf8:"


class ProtocolValidationError(ValueError):
    """请求不符合 pman/2 输入契约。"""

    error_code = ERROR_INVALID_REQUEST


def encode_alias_ref(alias: str) -> str:
    """Create a stable ASCII transport reference for a site alias."""
    encoded = base64.urlsafe_b64encode(alias.encode("utf-8")).decode("ascii")
    return ALIAS_REF_PREFIX + encoded.rstrip("=")


def decode_alias_ref(site: str | None) -> str | None:
    """Resolve a pman-generated reference without changing policy identity."""
    if not isinstance(site, str) or not site.startswith(ALIAS_REF_PREFIX):
        return site
    encoded = site[len(ALIAS_REF_PREFIX):]
    if not encoded or len(encoded) > 700:
        raise ProtocolValidationError("site 的 alias_ref 无效")
    try:
        padded = encoded + "=" * (-len(encoded) % 4)
        alias = base64.b64decode(
            padded.encode("ascii"), altchars=b"-_", validate=True
        ).decode("utf-8")
    except (UnicodeError, ValueError, binascii.Error) as exc:
        raise ProtocolValidationError("site 的 alias_ref 无效") from exc
    if not alias or len(alias) > 128:
        raise ProtocolValidationError("site 的 alias_ref 无效")
    return alias


def annotate(result: dict[str, Any]) -> dict[str, Any]:
    """为结果补充协议版本与稳定错误码，不改变现有业务字段。"""
    out = dict(result)
    out.setdefault("protocol", PROTOCOL_NAME)
    out.setdefault("protocol_version", PROTOCOL_VERSION)
    out.setdefault("error_code", infer_error_code(out))
    return out


def infer_error_code(result: dict[str, Any]) -> str:
    if result.get("ok"):
        return ERROR_OK
    if result.get("pending_approval"):
        return ERROR_PENDING_APPROVAL
    if result.get("policy_denied"):
        return ERROR_POLICY_DENIED
    if result.get("rate_limited"):
        return ERROR_RATE_LIMITED
    if result.get("response_blocked"):
        return ERROR_RESPONSE_BLOCKED

    message = str(result.get("error") or "")
    if "未解锁" in message:
        return ERROR_VAULT_LOCKED
    if "未知站点" in message:
        return ERROR_UNKNOWN_SITE
    if "已停用" in message:
        return ERROR_SITE_INACTIVE
    if "harness" in message and ("未知" in message or "吊销" in message):
        return ERROR_HARNESS_INVALID
    if message == "请求失败":
        return ERROR_REQUEST_FAILED
    return ERROR_UNKNOWN


def protocol_info() -> dict[str, Any]:
    return {"protocol": PROTOCOL_NAME, "protocol_version": PROTOCOL_VERSION}


def validate_http_request(payload: Any) -> dict[str, Any]:
    """校验并规范 daemon HTTP 请求，避免不同实现各自解释输入。"""
    if not isinstance(payload, dict):
        raise ProtocolValidationError("请求体必须是 JSON 对象")

    site = payload.get("site")
    if not isinstance(site, str) or not site.strip():
        raise ProtocolValidationError("site 必须是 1-128 个字符的站点别名")
    site = decode_alias_ref(site.strip())
    if not site or len(site) > 128:
        raise ProtocolValidationError("site 必须是 1-128 个字符的站点别名")

    method = payload.get("method", "GET")
    if not isinstance(method, str) or method.upper() not in HTTP_METHODS:
        raise ProtocolValidationError("method 必须是 GET/POST/PUT/DELETE/PATCH")
    method = method.upper()

    path = payload.get("path") or ""
    if not isinstance(path, str) or len(path) > 4096:
        raise ProtocolValidationError("path 必须是长度不超过 4096 的字符串")
    if any(ord(ch) < 0x20 for ch in path):
        raise ProtocolValidationError("path 不能包含控制字符")
    if path and not path.startswith("/"):
        path = "/" + path

    capability = payload.get("capability")
    if capability is not None and (
        not isinstance(capability, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", capability) is None
    ):
        raise ProtocolValidationError("capability 格式无效")

    query = payload.get("query")
    json_body = payload.get("json_body")
    form = payload.get("form")
    for name, value in (("query", query), ("json_body", json_body), ("form", form)):
        if value is not None and not isinstance(value, dict):
            raise ProtocolValidationError(f"{name} 必须是 JSON 对象或 null")
    if json_body is not None and form is not None:
        raise ProtocolValidationError("json_body 与 form 不能同时提供")

    return {
        "site": site,
        "method": method,
        "path": path,
        "capability": capability,
        "query": query,
        "json_body": json_body,
        "form": form,
    }
