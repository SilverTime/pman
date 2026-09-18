import helpers  # noqa: F401
import json
import tempfile
import unittest

from helpers import start_target, target_url
from pman.client import ClientError, DaemonClient
from pman.daemon import PmanDaemon
from pman.protocol import encode_alias_ref
from pman.vault import Vault


class DaemonTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.target = start_target()
        home = self.tmp.name
        v = Vault(home)
        v.create("pw")
        v.add_site("api", target_url(self.target), "api_token", {"token": helpers.GOOD_TOKEN})
        v.add_site("cookie", target_url(self.target), "cookie_jar",
                   {"cookies": [{"name": "sid", "value": helpers.COOKIE_VALUE}]})
        self.token = v.issue_token("codex")
        v.set_policy(
            "codex",
            {"allow": [{"site": "api", "methods": ["GET"], "paths": ["/api/ok"]}]},
        )
        v.close()
        # 守护进程只在启动时接受主密码；运行中不提供远程解锁/锁定。
        self.daemon = PmanDaemon(home, password="pw", port=0)
        self.daemon.start()
        host, port = self.daemon.address
        self.base = f"http://{host}:{port}"

    def tearDown(self):
        self.daemon.shutdown()
        self.target.shutdown()
        self.tmp.cleanup()

    def test_http_roundtrip_and_local_admin_boundary(self):
        anon = DaemonClient(self.base)
        status = anon.status()
        self.assertTrue(status["unlocked"])
        self.assertEqual(status["protocol"], "pman")
        self.assertEqual(status["protocol_version"], 2)

        c = DaemonClient(self.base, self.token)
        sites = c.sites()["sites"]
        self.assertEqual([s["alias"] for s in sites], ["api", "cookie"])

        res = c.http("api", "GET", "/api/ok")
        self.assertTrue(res["ok"])
        self.assertEqual(res["status_code"], 200)
        self.assertNotIn(helpers.GOOD_TOKEN, json.dumps(res, ensure_ascii=False))
        self.assertIn("***REDACTED***", json.dumps(res, ensure_ascii=False))

        # 审计只能由本地人工 Vault 读取，harness token 访问被拒绝。
        with self.assertRaises(ClientError):
            c._request("GET", "/v1/audit")
        with self.assertRaises(ClientError):
            c._request("GET", "/v1/approvals")
        v = Vault(self.tmp.name)
        v.unlock("pw")
        audit = v.query_audit(harness="codex")
        v.close()
        self.assertTrue(any(r["status_code"] == 200 for r in audit))
        self.assertTrue(all("token" not in json.dumps(r, ensure_ascii=False) for r in audit))
        with self.assertRaises(ClientError):
            c._request("POST", "/v1/lock", {})
        with self.assertRaises(ClientError):
            c._request("POST", "/v1/approve", {"id": "apr_missing"})

    def test_bad_token_rejected(self):
        c = DaemonClient(self.base, "pm_bad")
        with self.assertRaises(ClientError):
            c.sites()

    def test_http_request_contract_rejects_ambiguous_or_unsupported_input(self):
        c = DaemonClient(self.base, self.token)
        with self.assertRaises(ClientError) as ctx:
            c._request(
                "POST",
                "/v1/http",
                {"site": "api", "method": "TRACE", "path": "/api/ok"},
            )
        self.assertEqual(ctx.exception.error_code, "invalid_request")
        with self.assertRaises(ClientError) as ctx:
            c._request(
                "POST",
                "/v1/http",
                {
                    "site": "api",
                    "method": "POST",
                    "path": "/api/post",
                    "json_body": {"x": 1},
                    "form": {"x": "1"},
                },
            )
        self.assertEqual(ctx.exception.error_code, "invalid_request")

    def test_short_lease_token_works_and_revokes_live(self):
        v = Vault(self.tmp.name)
        v.unlock("pw")
        lease = v.issue_lease("codex", 600, note="session job")
        v.close()

        c = DaemonClient(self.base, lease["token"])
        res = c.http("api", "GET", "/api/ok")
        self.assertTrue(res["ok"])
        self.assertEqual(res["status_code"], 200)

        v = Vault(self.tmp.name)
        v.revoke_lease(lease["id"])
        v.close()
        with self.assertRaises(ClientError):
            c.sites()

    def test_policy_enforced_via_daemon(self):
        c = DaemonClient(self.base, self.token)
        pending = c.http("api", "GET", "/api/echo")
        self.assertTrue(pending["pending_approval"])
        self.assertTrue(pending["access_required"])
        self.assertEqual(pending["error_code"], "pending_approval")
        second = c.http("api", "GET", "/api/echo")
        self.assertEqual(second["req_id"], pending["req_id"])
        cookie = c.http("cookie", "GET", "/api/ok")  # 未授权站点
        self.assertTrue(cookie["pending_approval"])

    def test_daemon_resolves_ascii_reference_from_legacy_mcp(self):
        alias = "Jenkins 基线"
        v = Vault(self.tmp.name)
        v.unlock("pw")
        v.add_site(alias, target_url(self.target), "api_token", {"token": helpers.GOOD_TOKEN})
        v.set_policy(
            "codex",
            {"allow": [{"site": alias, "methods": ["GET"], "paths": ["/api/ok"]}]},
        )
        v.close()

        c = DaemonClient(self.base, self.token)
        res = c.http(encode_alias_ref(alias), "GET", "/api/ok")
        self.assertTrue(res["ok"])
        self.assertEqual(res["status_code"], 200)

    def test_approval_via_daemon(self):
        v = Vault(self.tmp.name)
        v.set_policy(
            "codex",
            {
                "allow": [{"site": "api", "methods": ["GET", "POST"], "paths": ["/api/ok", "/api/post"]}],
                "approval": {"required_for": ["POST"]},
            },
        )
        v.close()
        c = DaemonClient(self.base, self.token)
        pending = c.http("api", "POST", "/api/post", json_body={"x": 1})
        self.assertTrue(pending["pending_approval"])
        # 审批由本地人工 Vault 完成，不经过 harness HTTP API。
        v = Vault(self.tmp.name)
        v.unlock("pw")
        rows = v.list_approvals("pending")
        self.assertEqual(len(rows), 1)
        req_id = pending["req_id"]
        v.decide_approval(req_id, True)
        v.close()
        res = c.http("api", "POST", "/api/post", json_body={"x": 1})
        self.assertTrue(res["ok"])


if __name__ == "__main__":
    unittest.main()
