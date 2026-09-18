import helpers  # noqa: F401
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pman import http_proxy
from pman.redact import REDACTED, redact_body


class _ClosableServer(ThreadingHTTPServer):
    def shutdown(self):
        super().shutdown()
        self.server_close()


class RedirectHandler(BaseHTTPRequestHandler):
    location = ""
    final_body = b"ok"

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/start":
            self.send_response(302)
            self.send_header("Location", self.location)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.final_body)))
        self.end_headers()
        self.wfile.write(self.final_body)


class SinkHandler(BaseHTTPRequestHandler):
    seen_headers = None

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        type(self).seen_headers = dict(self.headers.items())
        body = b"sink"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class SecurityTest(unittest.TestCase):
    def _server(self, handler):
        server = _ClosableServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def tearDown(self):
        for server in getattr(self, "_servers", []):
            server.shutdown()

    def _track(self, server):
        self._servers = getattr(self, "_servers", [])
        self._servers.append(server)
        return server

    def test_cross_origin_redirect_is_blocked_before_auth_leak(self):
        sink = self._track(self._server(SinkHandler))
        SinkHandler.seen_headers = None
        RedirectHandler.location = f"http://127.0.0.1:{sink.server_address[1]}/sink"
        redirect = self._track(self._server(RedirectHandler))

        with self.assertRaises(http_proxy.ProxyError):
            http_proxy.execute(
                f"http://127.0.0.1:{redirect.server_address[1]}/start",
                {"Authorization": "Bearer DUMMY-CREDENTIAL"},
                None,
                "GET",
            )
        self.assertIsNone(SinkHandler.seen_headers)

    def test_same_origin_redirect_still_works(self):
        RedirectHandler.location = "http://127.0.0.1/unused"
        server = self._track(self._server(RedirectHandler))
        RedirectHandler.location = f"http://127.0.0.1:{server.server_address[1]}/final"
        status, _, body = http_proxy.execute(
            f"http://127.0.0.1:{server.server_address[1]}/start",
            {},
            None,
            "GET",
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b"ok")

    def test_redact_body_covers_arbitrary_json_and_plain_text(self):
        obj, count, truncated, is_json = redact_body(
            b'{"data":"DUMMY-CREDENTIAL","items":["DUMMY-CREDENTIAL"]}',
            [],
            1024,
            ["DUMMY-CREDENTIAL"],
        )
        self.assertTrue(is_json)
        self.assertFalse(truncated)
        self.assertEqual(obj["data"], REDACTED)
        self.assertEqual(obj["items"][0], REDACTED)
        self.assertGreaterEqual(count, 2)

        text, count, _, is_json = redact_body(
            b"password=DUMMY-CREDENTIAL; note=ok", [], 1024, ["DUMMY-CREDENTIAL"]
        )
        self.assertFalse(is_json)
        self.assertIn(REDACTED, text)
        self.assertNotIn("DUMMY-CREDENTIAL", text)
        self.assertGreaterEqual(count, 1)

        short_obj, _, _, _ = redact_body(
            b'{"data":"t","status":"ok"}', [], 1024, ["t"]
        )
        self.assertEqual(short_obj["data"], REDACTED)
        self.assertEqual(short_obj["status"], "ok")


if __name__ == "__main__":
    unittest.main()
