"""pmd：本地调用守护进程。

启动：
    PM_MASTER_PASSWORD=... pm daemon  # daemon 启动时解锁

AI harness 侧通过 Bearer token 访问（token 由 pm token issue 签发）。
人工审批、审计、锁定和解锁不通过 harness token 暴露。
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__
from .broker import Broker
from .protocol import ProtocolValidationError, annotate, protocol_info, validate_http_request

log = logging.getLogger("pman.daemon")
MAX_BODY = 10 * 1024 * 1024


def exit_when_parent_stops(parent_pid: int | None) -> None:
    """Terminate this daemon when its desktop parent exits.

    The desktop launches pmd as a managed child.  A parent watchdog prevents
    an unlocked credential broker from surviving a desktop crash.  No secret
    or parent command-line data is inspected.
    """
    if not parent_pid or parent_pid <= 0:
        return

    def watch_windows() -> None:
        import ctypes
        from ctypes import wintypes

        synchronize = 0x00100000
        infinite = 0xFFFFFFFF
        kernel32 = ctypes.windll.kernel32
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(synchronize, False, parent_pid)
        if not handle:
            os._exit(0)
        try:
            kernel32.WaitForSingleObject(handle, infinite)
        finally:
            kernel32.CloseHandle(handle)
        os._exit(0)

    def watch_posix() -> None:
        while os.getppid() == parent_pid:
            time.sleep(1.0)
        os._exit(0)

    target = watch_windows if os.name == "nt" else watch_posix
    threading.Thread(target=target, name="pmd-parent-watch", daemon=True).start()


class PmanDaemon:
    def __init__(self, home, password: str | None = None, port: int = 9777):
        self.broker = Broker(home, password)
        self.port = port
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        if self._httpd is None:
            return ("127.0.0.1", self.port)
        return self._httpd.server_address[:2]

    def _make_handler(self):
        broker = self.broker

        class Handler(BaseHTTPRequestHandler):
            server_version = f"pman/{__version__}"
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                log.debug("%s - %s", self.address_string(), fmt % args)

            # ---------- helpers ----------
            def _send(self, code, obj):
                body = json.dumps(annotate(obj), ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _body(self) -> dict:
                length = int(self.headers.get("Content-Length") or 0)
                if length <= 0:
                    return {}
                if length > MAX_BODY:
                    raise ValueError("请求体过大")
                raw = self.rfile.read(length)
                try:
                    return json.loads(raw.decode("utf-8"))
                except Exception as exc:
                    raise ValueError("请求体必须是 JSON") from exc

            def _auth(self):
                """返回 harness 记录或发送 401 并返回 None。"""
                header = self.headers.get("Authorization", "")
                if not header.startswith("Bearer "):
                    self._send(401, {"error": "缺少 Bearer token"})
                    return None
                h = broker.vault.check_token(header[7:].strip())
                if h is None:
                    self._send(401, {"error": "token 无效或已吊销"})
                    return None
                return h

            # ---------- GET ----------
            def do_GET(self):
                parsed = urlparse(self.path)
                try:
                    if parsed.path == "/healthz":
                        self._send(200, {"ok": True})
                        return
                    if parsed.path == "/v1/status":
                        self._send(
                            200,
                            {
                                "unlocked": broker.vault.unlocked,
                                "initialized": broker.vault.initialized,
                                **protocol_info(),
                            },
                        )
                        return
                    h = self._auth()
                    if h is None:
                        return
                    qs = parse_qs(parsed.query)
                    if parsed.path == "/v1/sites":
                        self._send(200, {"sites": broker.sites()})
                        return
                    if parsed.path == "/v1/approvals":
                        self._send(403, {"error": "审批队列仅允许本地人工管理"})
                        return
                    if parsed.path == "/v1/approval":
                        req_id = qs.get("id", [""])[0]
                        row = broker.vault.get_approval(req_id)
                        if row is None or row["harness"] != h["name"]:
                            self._send(404, {"error": "审批不存在"})
                        else:
                            self._send(200, {"approval": row})
                        return
                    if parsed.path == "/v1/audit":
                        self._send(403, {"error": "审计仅允许本地人工管理"})
                        return
                    self._send(404, {"error": "未知路径"})
                except Exception as e:
                    log.exception("GET %s", self.path)
                    self._send(500, {"error": str(e)})

            # ---------- POST ----------
            def do_POST(self):
                parsed = urlparse(self.path)
                try:
                    if parsed.path in {"/v1/unlock", "/v1/lock"}:
                        self._send(403, {"error": "锁定/解锁仅允许本地人工管理"})
                        return
                    h = self._auth()
                    if h is None:
                        return
                    payload = self._body()
                    if parsed.path == "/v1/http":
                        request = validate_http_request(payload)
                        result = broker.call(
                            **request,
                            harness=h["name"],
                        )
                        # Pending human approval is a successful protocol exchange,
                        # not a transport failure.  HTTP 200 preserves req_id for
                        # older MCP clients that discard JSON fields on HTTPError.
                        self._send(
                            200 if result.get("ok") or result.get("pending_approval") else 403,
                            result,
                        )
                        return
                    if parsed.path == "/v1/approve":
                        self._send(403, {"error": "审批仅允许本地人工管理"})
                        return
                    self._send(404, {"error": "未知路径"})
                except ProtocolValidationError as e:
                    self._send(400, {"error": str(e), "error_code": e.error_code})
                except ValueError as e:
                    self._send(400, {"error": str(e)})
                except Exception as e:
                    log.exception("POST %s", self.path)
                    self._send(500, {"error": str(e)})

        return Handler

    def start(self, block: bool = False):
        if self._httpd is not None:
            return
        self._httpd = ThreadingHTTPServer(("127.0.0.1", self.port), self._make_handler())
        if block:
            try:
                self._httpd.serve_forever()
            except KeyboardInterrupt:
                pass
        else:
            self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
            self._thread.start()

    def shutdown(self):
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        self.broker.vault.close()
