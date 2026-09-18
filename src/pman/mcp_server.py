"""MCP stdio server：把 pman 能力暴露为 AI 可调用的工具。

两种后端模式：
1. 守护进程模式（推荐）：PM_DAEMON / --daemon 指向 pmd，PM_TOKEN 认证；
   pmd 按 token 识别 harness 并执行策略。
2. 内嵌直连模式：PM_MASTER_PASSWORD 解锁本地 vault，按 PM_HARNESS 策略执行；
   MCP 进程本身就是持有秘密的边界。

MCP stdio 传输：stdin/stdout 每行一个 JSON-RPC 消息。
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from . import __version__
from .ai_spec import AI_SPEC, AI_TOOLS as TOOLS
from .client import DaemonClient
from .protocol import annotate, decode_alias_ref, encode_alias_ref


class BackendError(Exception):
    pass


class DaemonBackend:
    """经 pmd 守护进程执行。"""

    def __init__(self, base_url: str, token: str | None):
        self.client = DaemonClient(base_url, token)

    def sites(self):
        return self.client.sites().get("sites", [])

    def http(self, site, method, path, query=None, json_body=None, form=None, capability=None):
        return self.client.http(site, method, path, query, json_body, form, capability)

    def approval(self, req_id):
        return self.client.approval(req_id).get("approval")


class DirectBackend:
    """内嵌模式：本进程即持有秘密的边界。"""

    def __init__(self, home, harness: str, password: str):
        from .broker import Broker

        self.broker = Broker(home, password=password)
        self.harness = harness

    def sites(self):
        return self.broker.sites()

    def http(self, site, method, path, query=None, json_body=None, form=None, capability=None):
        return self.broker.call(
            site,
            method,
            path,
            capability=capability,
            query=query,
            json_body=json_body,
            form=form,
            harness=self.harness,
        )

    def approval(self, req_id):
        return self.broker.vault.get_approval(req_id)

    def close(self):
        self.broker.vault.close()


def make_backend(
    daemon_url: str | None = None,
    token: str | None = None,
    harness: str | None = None,
    home: str | None = None,
):
    home = home or os.environ.get("PM_HOME", str(Path.home() / ".pman"))
    daemon_url = daemon_url or os.environ.get("PM_DAEMON")
    if daemon_url:
        return DaemonBackend(daemon_url, token or os.environ.get("PM_TOKEN"))
    harness = harness or os.environ.get("PM_HARNESS")
    password = os.environ.get("PM_MASTER_PASSWORD")
    if not password:
        raise BackendError(
            "内嵌模式需要环境变量 PM_MASTER_PASSWORD；"
            "或改用守护进程模式（PM_DAEMON + PM_TOKEN）"
        )
    if not harness:
        raise BackendError("内嵌模式需要环境变量 PM_HARNESS（策略归属）")
    return DirectBackend(home, harness, password)


class McpServer:
    def __init__(self, backend):
        self.backend = backend

    # ---------------- JSON-RPC ----------------
    def handle(self, msg: dict):
        rid = msg.get("id")
        method = msg.get("method")
        try:
            if method == "initialize":
                params = msg.get("params") or {}
                return self._ok(
                    rid,
                    {
                        "protocolVersion": params.get("protocolVersion", "2024-11-05"),
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "pman", "version": __version__},
                    },
                )
            if method == "notifications/initialized":
                return None
            if method == "ping":
                return self._ok(rid, {})
            if method == "tools/list":
                return self._ok(rid, {"tools": TOOLS})
            if method == "tools/call":
                return self._tool_call(rid, msg.get("params") or {})
            return self._err(rid, -32601, f"unknown method: {method}")
        except Exception as e:
            return self._err(rid, -32603, f"internal error: {e}")

    def _tool_call(self, rid, params: dict):
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            if name == "pm_contract":
                result = {"ok": True, "contract": AI_SPEC}
            elif name == "pm_sites":
                sites = []
                for site in self.backend.sites():
                    metadata = dict(site)
                    alias = metadata.get("alias")
                    if isinstance(alias, str) and not alias.isascii():
                        metadata["alias_ref"] = encode_alias_ref(alias)
                    sites.append(metadata)
                result = {"ok": True, "sites": sites}
            elif name == "pm_http":
                result = self.backend.http(
                    site=decode_alias_ref(args.get("site")),
                    method=args.get("method", "GET"),
                    path=args.get("path", ""),
                    capability=args.get("capability"),
                    query=args.get("query"),
                    json_body=args.get("json_body"),
                    form=args.get("form"),
                )
            elif name == "pm_approval_wait":
                result = self._wait_approval(args.get("req_id"), args.get("timeout_sec", 60))
            else:
                return self._err(rid, -32602, f"unknown tool: {name}")
        except Exception as e:
            payload = getattr(e, "payload", None)
            result = dict(payload) if isinstance(payload, dict) else {}
            result.setdefault("ok", False)
            result.setdefault("error", str(e))
            if getattr(e, "error_code", None):
                result.setdefault("error_code", e.error_code)
        result = annotate(result)
        is_error = not result.get("ok", False)
        return self._ok(
            rid,
            {
                "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}],
                "isError": is_error,
            },
        )

    def _wait_approval(self, req_id, timeout):
        if not req_id:
            return {"ok": False, "error": "缺少 req_id"}
        timeout = max(0.0, min(float(timeout), 300.0))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            row = self.backend.approval(req_id)
            if row and row.get("status") != "pending":
                return {"ok": True, "approval": row}
            time.sleep(0.5)
        row = self.backend.approval(req_id)
        return {"ok": True, "approval": row, "note": "等待超时，可再次调用本工具继续等待"}

    # ---------------- stdio ----------------
    def _write_stdio(self, text: str) -> None:
        """MCP stdio 契约要求 UTF-8；Windows 上绕过本地代码页。"""
        buf = getattr(sys.stdout, "buffer", None)
        if buf is not None:
            buf.write(text.encode("utf-8"))
            buf.flush()
            return
        sys.stdout.write(text)
        sys.stdout.flush()

    def run_stdio(self):
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except Exception:
                continue
            resp = self.handle(msg)
            if resp is not None:
                self._write_stdio(json.dumps(resp, ensure_ascii=False) + "\n")

    @staticmethod
    def _ok(rid, result):
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    @staticmethod
    def _err(rid, code, message):
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}
