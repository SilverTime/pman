"""DaemonClient：pm CLI / MCP 与 pmd 守护进程之间的本地回环客户端。"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from .protocol import ERROR_INVALID_REQUEST, PROTOCOL_NAME, PROTOCOL_VERSION


class ClientError(Exception):
    def __init__(
        self,
        message: str,
        error_code: str | None = None,
        payload: dict | None = None,
    ):
        super().__init__(message)
        self.error_code = error_code
        self.payload = payload or {}


def _normalize_text(value: str) -> str:
    """Repair UTF-8 bytes that arrived through a surrogate-escape boundary.

    Some Windows MCP hosts can pass non-ASCII tool arguments as low-surrogate
    code points.  ``json.dumps(..., ensure_ascii=False).encode('utf-8')`` then
    raises before the request reaches pmd.  Recover a complete escaped UTF-8
    sequence; reject incomplete or otherwise invalid sequences explicitly.
    """
    if not any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        return value
    try:
        return value.encode("utf-8", "surrogateescape").decode("utf-8")
    except UnicodeError as exc:
        raise ClientError(
            "请求参数包含无法按 UTF-8 解码的字符",
            ERROR_INVALID_REQUEST,
        ) from exc


def _normalize_json_value(value):
    """Return a JSON-safe value without lone Unicode surrogate code points."""
    if isinstance(value, str):
        return _normalize_text(value)
    if isinstance(value, list):
        return [_normalize_json_value(item) for item in value]
    if isinstance(value, tuple):
        return [_normalize_json_value(item) for item in value]
    if isinstance(value, dict):
        normalized = {}
        for key, item in value.items():
            normalized_key = _normalize_text(key) if isinstance(key, str) else key
            if normalized_key in normalized:
                raise ClientError(
                    "请求参数在 UTF-8 规范化后包含重复字段",
                    ERROR_INVALID_REQUEST,
                )
            normalized[normalized_key] = _normalize_json_value(item)
        return normalized
    return value


class DaemonClient:
    def __init__(self, base_url: str = "http://127.0.0.1:9777", token: str | None = None):
        self.base = (base_url or "http://127.0.0.1:9777").rstrip("/")
        self.token = token or os.environ.get("PM_TOKEN")

    def _request(self, method: str, path: str, payload=None, timeout: int = 180):
        url = self.base + path
        data = None
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if payload is not None:
            data = json.dumps(
                _normalize_json_value(payload), ensure_ascii=False
            ).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                version = result.get("protocol_version")
                protocol = result.get("protocol")
                if version is not None and (
                    protocol != PROTOCOL_NAME or int(version) != PROTOCOL_VERSION
                ):
                    raise ClientError(
                        f"pmd 协议不兼容：收到 {protocol}/{version}，需要 "
                        f"{PROTOCOL_NAME}/{PROTOCOL_VERSION}"
                    )
                return result
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read().decode("utf-8"))
            except Exception:
                body = {}
            if e.code == 401:
                raise ClientError("token 无效或已吊销", body.get("error_code"), body)
            raise ClientError(
                body.get("error") or f"HTTP {e.code}", body.get("error_code"), body
            )
        except urllib.error.URLError as e:
            raise ClientError(
                f"无法连接 pmd（{self.base}）：{e.reason}；请先运行 pm daemon"
            )

    # ---- 端点封装 ----
    def status(self):
        return self._request("GET", "/v1/status")

    def sites(self):
        return self._request("GET", "/v1/sites")

    def http(self, site, method, path, query=None, json_body=None, form=None, capability=None):
        return self._request(
            "POST",
            "/v1/http",
            {
                "site": site,
                "method": method,
                "path": path,
                "capability": capability,
                "query": query,
                "json_body": json_body,
                "form": form,
            },
        )

    def approval(self, req_id):
        return self._request("GET", f"/v1/approval?id={urllib.parse.quote(req_id)}")
