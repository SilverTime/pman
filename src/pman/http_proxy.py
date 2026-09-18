"""HTTP 代理：把站点秘密转换为请求头并转发，只返回净化后的结果。

秘密只用于构造出站请求头，本模块任何函数都不把秘密返回给调用方
（调用方也无法从这里取回秘密）。
"""
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "pman/0.3"
HARD_RESPONSE_CAP = 2 * 1024 * 1024  # 原始响应读取上限，防异常大响应


class ProxyError(Exception):
    pass


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    if port is None:
        port = {"http": 80, "https": 443}.get(scheme)
    return scheme, host, port


class _SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    """只允许同源、同协议重定向，避免认证头跨站泄漏。"""

    max_redirections = 3

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _origin(req.full_url) != _origin(newurl):
            raise ProxyError("已阻止跨源或降级重定向")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_request(
    site_row,
    secret: dict,
    method: str,
    path: str,
    query: dict | None = None,
    json_body: dict | None = None,
    form: dict | None = None,
):
    """构造 (url, headers, body)。"""
    base = (site_row["site_url"] or "").rstrip("/")
    if path and not path.startswith("/"):
        path = "/" + path
    url = base + (path or "")
    if query:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(query)

    headers = {"User-Agent": USER_AGENT, "Accept": "application/json, text/plain, */*"}
    auth_type = site_row["auth_type"]

    if auth_type == "api_token":
        value = secret.get("token")
        if not value:
            raise ProxyError("secret 缺少 token 字段")
        name = secret.get("header") or "Authorization"
        if name.lower() == "authorization" and not value.lower().startswith(
            ("bearer ", "basic ", "token ", "private-token ")
        ):
            value = "Bearer " + value
        headers[name] = value
    elif auth_type == "http_basic":
        user = secret.get("username", "")
        pw = secret.get("password", "")
        raw = base64.b64encode(f"{user}:{pw}".encode()).decode("ascii")
        headers["Authorization"] = "Basic " + raw
    elif auth_type in {"cookie_jar", "login"}:
        cookies = secret.get("cookies", [])
        if isinstance(cookies, dict):
            cookies = [{"name": k, "value": v} for k, v in cookies.items()]
        if not cookies:
            raise ProxyError("secret 缺少 cookies 字段")
        headers["Cookie"] = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
    else:
        raise ProxyError(f"未知 auth_type：{auth_type}")

    body = None
    if json_body is not None:
        body = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif form:
        body = urllib.parse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    return url, headers, body


def execute(
    url: str,
    headers: dict,
    body: bytes | None,
    method: str,
    insecure_tls: bool = False,
    timeout: int = 60,
):
    """执行请求，返回 (status, response_headers, raw_body)。HTTP 4xx/5xx 不抛异常。"""
    ctx = ssl._create_unverified_context() if insecure_tls else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
    try:
        handlers = [_SameOriginRedirectHandler()]
        if ctx is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        opener = urllib.request.build_opener(*handlers)
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, dict(resp.getheaders()), resp.read(HARD_RESPONSE_CAP + 1)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()), e.read(HARD_RESPONSE_CAP + 1)
    except urllib.error.URLError as e:
        raise ProxyError(f"无法连接站点：{e.reason}") from e
