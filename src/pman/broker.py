"""Broker：核心业务编排。

策略检查 → 审批门禁 → 凭据注入 → 转发 → 响应脱敏/截断 → 审计。
secret 只在本模块内部流转，任何返回结果都不包含秘密。
"""
from __future__ import annotations

import base64
import json
import re
import time
import urllib.parse

from . import http_proxy, redact
from .policy import Policy, RateLimiter
from .protocol import ProtocolValidationError, annotate, decode_alias_ref
from .vault import Vault, VaultError

DEFAULT_STRIP_HEADERS = [
    "set-cookie",
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
]
DEFAULT_JSON_KEYS = [
    r"(?i).*token.*",
    r"(?i).*password.*",
    r"(?i).*passwd.*",
    r"(?i).*secret.*",
    r"(?i).*cookie.*",
    r"(?i).*authorization.*",
    r"(?i).*api[_-]?key.*",
]
DEFAULT_MAX_RESPONSE_BYTES = 524288
APPROVAL_STICKY_SECONDS = 600  # 兼容旧审批窗口；每条批准在成功使用后立即消费


class Broker:
    def __init__(self, home=None, password: str | None = None, vault=None):
        """home 与 vault 二选一：传 vault 复用已打开实例（调用方负责关闭）。"""
        self.vault = vault if vault is not None else Vault(home)
        self.rate_limiter = RateLimiter()
        if password is not None:
            self.vault.unlock(password)

    # ---------------- 对外 ----------------
    def sites(self) -> list[dict]:
        """站点元数据（不含秘密），可安全展示给 AI。"""
        return self.vault.list_sites()

    def call(
        self,
        site: str,
        method: str,
        path: str = "",
        query: dict | None = None,
        json_body: dict | None = None,
        form: dict | None = None,
        harness: str | None = None,
        wait_approval_timeout: float = 0.0,
        capability: str | None = None,
    ) -> dict:
        """执行一次调用并附加稳定的 pman 协议字段。"""
        try:
            site = decode_alias_ref(site)
        except ProtocolValidationError as error:
            return annotate({"ok": False, "error": str(error), "error_code": error.error_code})
        if capability is not None and (
            not isinstance(capability, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", capability) is None
        ):
            return annotate({"ok": False, "error": "capability 格式无效", "error_code": "invalid_request"})
        return annotate(
            self._call(
                site,
                method,
                path,
                query,
                json_body,
                form,
                harness,
                wait_approval_timeout,
                capability,
            )
        )

    def _call(
        self,
        site: str,
        method: str,
        path: str = "",
        query: dict | None = None,
        json_body: dict | None = None,
        form: dict | None = None,
        harness: str | None = None,
        wait_approval_timeout: float = 0.0,
        capability: str | None = None,
    ) -> dict:
        """执行一次凭据代理调用。harness=None 表示人工调用（不套策略）。"""
        method = (method or "GET").upper()
        try:
            self.vault.ensure_unlocked()
        except VaultError as e:
            return {"ok": False, "error": str(e)}

        row = self.vault.get_site_row(site)
        if row is None:
            return {"ok": False, "error": f"未知站点：{site}"}
        if row["status"] != "active":
            return {"ok": False, "error": f"站点 {site} 已停用"}

        policy = None
        approval_granted = False
        if harness:
            h = self.vault.get_harness(harness)
            if h is None:
                return {"ok": False, "error": f"未知 harness：{harness}"}
            if h.get("revoked_at") is not None:
                return {"ok": False, "error": f"harness {harness} 已被吊销"}
            policy = Policy(json.loads(h.get("policy_json") or '{"default_action":"deny","allow": []}'))

            ok, why = self.rate_limiter.check(harness, policy.rate_limit_per_min())
            if not ok:
                self.vault.add_audit(
                    harness, site, method, path, None, 0, 0, False, False,
                    None, f"限流:{why}",
                )
                return {"ok": False, "rate_limited": True, "error": why}

            request_fingerprint = self.vault.approval_fingerprint(
                site, method, path, capability, query, json_body, form
            )
            decision = policy.authorize_request(
                site, method, path, capability, query, json_body, form
            )
            boundary_approval = not decision.allowed
            method_approval = decision.allowed and policy.approval_required(method)
            approval_needed = boundary_approval or method_approval
            if approval_needed:
                approval_granted = self.vault.consume_recent_approval(
                    harness,
                    site,
                    method,
                    APPROVAL_STICKY_SECONDS,
                    path=path,
                    request_fingerprint=request_fingerprint,
                )
            if approval_needed and not approval_granted:
                # 审批载荷会在 vault 中落盘并可能回显给 AI，必须先脱敏。
                # 先在 broker 内存中读取该站点秘密，用于处理非敏感字段名下
                # 的回显（例如 ``note: <token>``）；秘密不会写入审批记录。
                approval_secret = None
                try:
                    approval_secret = self.vault.get_site_secret(site)
                except VaultError:
                    pass
                approval_secret_values = (
                    self._secret_values(row, approval_secret)
                    if approval_secret is not None
                    else ()
                )
                safe_payload = redact.redact_payload(
                    {"capability": capability, "query": query, "json_body": json_body, "form": form},
                    DEFAULT_JSON_KEYS,
                    approval_secret_values,
                )
                req_id = self.vault.create_approval(
                    harness,
                    site,
                    method,
                    path,
                    safe_payload,
                    request_fingerprint=request_fingerprint,
                )
                self.vault.add_audit(
                    harness, site, method, path, None, 0, 0, False, False,
                    req_id, "等待范围授权" if boundary_approval else "等待人工审批",
                )
                approval_error = (
                    f"该请求不在白名单内，请在桌面端选择单次批准或永久同意：{req_id}"
                    if boundary_approval
                    else f"该操作需要人工审批，请在桌面端批准：{req_id}"
                )
                if wait_approval_timeout > 0:
                    final = self._wait_approval(req_id, wait_approval_timeout)
                    if final is None or final["status"] != "approved":
                        status = final["status"] if final else "pending"
                        return {
                            "ok": False,
                            "pending_approval": True,
                            "req_id": req_id,
                            "approval_status": status,
                            "access_required": boundary_approval,
                            "error": approval_error,
                        }
                    if not self.vault.consume_approval(req_id):
                        return {
                            "ok": False,
                            "pending_approval": True,
                            "req_id": req_id,
                            "approval_status": "pending",
                            "access_required": boundary_approval,
                            "error": "审批状态已被其他请求消费，请重新发起审批",
                        }
                    approval_granted = True
                else:
                    return {
                        "ok": False,
                        "pending_approval": True,
                        "req_id": req_id,
                        "approval_status": "pending",
                        "access_required": boundary_approval,
                        "error": approval_error,
                    }

        # ---- 凭据注入并转发 ----
        try:
            secret = self.vault.get_site_secret(site)
            url, headers, body = http_proxy.build_request(
                row, secret, method, path, query, json_body, form
            )
            status, resp_headers, raw = http_proxy.execute(
                url, headers, body, method, bool(row["insecure_tls"])
            )
        except Exception as e:
            self.vault.add_audit(
                harness or "human", site, method, path, None, 0, 0, False, False,
                None, "请求失败",
            )
            return {"ok": False, "error": self._safe_error(e)}

        # ---- 响应脱敏 ----
        red = policy.redact() if policy else {}
        strip = red.get("strip_headers", DEFAULT_STRIP_HEADERS)
        jkeys = red.get("json_keys", DEFAULT_JSON_KEYS)
        maxb = int(red.get("max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES))
        secret_values = self._secret_values(row, secret)
        headers_out, hc = redact.redact_headers(resp_headers, strip, secret_values)
        body_out, bc, truncated, is_json = redact.redact_body(
            raw, jkeys, maxb, secret_values
        )

        serialized_body = (
            json.dumps(body_out, ensure_ascii=False)
            if is_json
            else str(body_out)
        )
        if self._contains_secret(headers_out, secret_values) or self._contains_secret(
            serialized_body, secret_values
        ):
            self.vault.add_audit(
                harness or "human", site, method, path, status, len(raw), hc + bc,
                truncated, False, None, "响应包含凭据，已阻止返回",
            )
            return {
                "ok": False,
                "response_blocked": True,
                "status_code": status,
                "error": "响应疑似包含站点凭据，已阻止返回",
            }

        approved = bool(policy and approval_granted)
        self.vault.touch_site(site)
        self.vault.add_audit(
            harness or "human", site, method, path, status, len(raw), hc + bc,
            truncated, approved,
        )

        result = {
            "ok": True,
            "status_code": status,
            "headers": headers_out,
            "redactions": hc + bc,
            "truncated": truncated,
            "truncated_original_bytes": len(raw) if truncated else 0,
        }
        if is_json:
            result["body_json"] = body_out
        else:
            result["body_text"] = body_out
        return result

    @staticmethod
    def _secret_values(site_row, secret: dict) -> tuple[str, ...]:
        """收集本次出站请求中可能被站点回显的秘密及常见编码。

        只收集实际凭据值，不把 ``header``、Cookie 名等元数据当作秘密，
        这样回显请求头时仍能保留可诊断的字段名。
        """
        values: set[str] = set()
        auth_type = site_row["auth_type"]
        if auth_type == "api_token":
            token = str(secret.get("token", ""))
            if token:
                values.add(token)
            header_value = str(secret.get("value", ""))
            if header_value:
                values.add(header_value)
            if token and str(secret.get("header") or "Authorization").lower() == "authorization":
                if not token.lower().startswith(
                    ("bearer ", "basic ", "token ", "private-token ")
                ):
                    values.add("Bearer " + token)
        elif auth_type == "http_basic":
            username = str(secret.get("username", ""))
            password = str(secret.get("password", ""))
            if username:
                values.add(username)
            if password:
                values.add(password)
            basic = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
            values.add("Basic " + basic)
            values.add(basic)
        elif auth_type in {"cookie_jar", "login"}:
            cookies = secret.get("cookies", [])
            if isinstance(cookies, dict):
                cookies = [{"name": k, "value": v} for k, v in cookies.items()]
            cookie_parts = []
            for cookie in cookies:
                value = str(cookie.get("value", ""))
                if value:
                    values.add(value)
                cookie_parts.append(f"{cookie.get('name', '')}={value}")
            if cookie_parts:
                values.add("; ".join(cookie_parts))
        else:
            # login 等扩展类型：递归收集叶子值，但跳过字段名元数据。
            def collect(value, key=None) -> None:
                if isinstance(value, str) and value and key not in {"header", "name"}:
                    values.add(value)
                elif isinstance(value, dict):
                    for child_key, child in value.items():
                        collect(child, str(child_key))
                elif isinstance(value, list):
                    for child in value:
                        collect(child, key)

            collect(secret)

        encoded = set(values)
        for value in tuple(values):
            encoded.add(urllib.parse.quote(value, safe=""))
            encoded.add(urllib.parse.quote_plus(value))
            encoded.add(base64.b64encode(value.encode()).decode("ascii"))
        return tuple(sorted((v for v in encoded if v), key=lambda v: (-len(v), v)))

    @staticmethod
    def _contains_secret(value, secret_values: tuple[str, ...]) -> bool:
        # 对结构化响应只扫描值，不把诊断用的字段名（例如 ``User-Agent``）
        # 当作凭据；JSON 字段本身已在 redact._redact_obj 中处理。
        if isinstance(value, dict):
            return any(Broker._contains_secret(child, secret_values) for child in value.values())
        if isinstance(value, list):
            return any(Broker._contains_secret(child, secret_values) for child in value)
        text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
        for secret in secret_values:
            if not secret:
                continue
            if len(secret) < 8:
                if re.search(
                    r"(?<![A-Za-z0-9_])" + re.escape(secret) + r"(?![A-Za-z0-9_])",
                    text,
                ):
                    return True
            elif secret in text:
                return True
        return False

    @staticmethod
    def _safe_error(error: Exception) -> str:
        """避免把底层异常中的 URL、请求头或库实现细节直接回显。"""
        # 代理异常可能包含 URL、重定向目标、认证头或 TLS 细节；统一使用
        # 稳定的公开错误，当前版本不向调用方返回底层异常内容。
        return "请求失败"

    # ---------------- 内部 ----------------
    def _wait_approval(self, req_id: str, timeout: float):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            row = self.vault.get_approval(req_id)
            if row and row["status"] != "pending":
                return row
            time.sleep(0.5)
        return self.vault.get_approval(req_id)
