"""测试公共工具：sys.path 注入、临时目录、本地目标 HTTP 服务器。"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
os.environ.setdefault("PM_KDF_ITERATIONS", "1000")

GOOD_TOKEN = "good-token"
COOKIE_VALUE = "sekrit-cookie"
BASIC_HEADER = "Basic dXNlcjpwYXNz"  # user:pass


class TargetHandler(BaseHTTPRequestHandler):
    """模拟内网站点：需要合法凭据；响应里故意回显秘密以验证脱敏。"""

    server_version = "test-target/1.0"

    def log_message(self, fmt, *args):  # 静默
        pass

    def _json(self, code, obj):
        payload = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Auth-Token", "echo-header-secret")  # 敏感响应头
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _text(self, code, text):
        payload = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("X-Auth-Token", "echo-header-secret")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _authed(self) -> bool:
        auth = self.headers.get("Authorization", "")
        cookie = self.headers.get("Cookie", "")
        return (
            auth == f"Bearer {GOOD_TOKEN}"
            or auth == BASIC_HEADER
            or f"sid={COOKIE_VALUE}" in cookie
        )

    def _route(self):
        path = self.path.split("?")[0]
        if path == "/api/echo":
            self._json(200, {"request_headers": {k: v for k, v in self.headers.items()}})
            return
        if not self._authed():
            self._json(401, {"error": "unauthorized"})
            return
        if path == "/api/ok":
            self._json(
                200,
                {
                    "data": [1, 2, 3],
                    "access_token": f"echo-{GOOD_TOKEN}",
                    "nested": {"password": "echo-pass"},
                },
            )
            return
        if path == "/api/plain":
            self._text(200, f"status=ok password={GOOD_TOKEN} note=plain")
            return
        if path == "/api/arbitrary":
            self._json(200, {"data": GOOD_TOKEN, "nested": [GOOD_TOKEN]})
            return
        if path == "/api/post" and self.command == "POST":
            self._json(200, {"created": True, "csrf_token": "echo-csrf"})
            return
        self._json(404, {"error": "not found"})

    def do_GET(self):
        self._route()

    def do_POST(self):
        self._route()

    def do_PUT(self):
        self._route()

    def do_DELETE(self):
        self._route()


class TestHTTPServer(ThreadingHTTPServer):
    """测试服务器关闭时同步释放监听 socket，避免 ResourceWarning 泄漏。"""

    def shutdown(self):
        super().shutdown()
        self.server_close()


def start_target() -> ThreadingHTTPServer:
    server = TestHTTPServer(("127.0.0.1", 0), TargetHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def target_url(server: ThreadingHTTPServer) -> str:
    return f"http://127.0.0.1:{server.server_address[1]}"


def make_temp_home() -> str:
    return tempfile.mkdtemp(prefix="pman-test-")
