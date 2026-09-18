import helpers  # noqa: F401
import json
import tempfile
import unittest

from helpers import start_target, target_url
from pman.broker import Broker
from pman.redact import REDACTED
from pman.vault import Vault


class BrokerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.target = start_target()
        home = self.tmp.name
        v = Vault(home)
        v.create("pw")
        v.add_site("api", target_url(self.target), "api_token", {"token": helpers.GOOD_TOKEN})
        v.add_site(
            "cookie",
            target_url(self.target),
            "cookie_jar",
            {"cookies": [{"name": "sid", "value": helpers.COOKIE_VALUE}]},
        )
        v.add_site(
            "login",
            target_url(self.target),
            "login",
            {"cookies": [{"name": "sid", "value": helpers.COOKIE_VALUE}]},
        )
        v.add_site("basic", target_url(self.target), "http_basic", {"username": "user", "password": "pass"})
        v.add_site("bad", target_url(self.target), "api_token", {"token": "wrong-token"})
        v.issue_token("codex")
        v.set_policy(
            "codex",
            {
                "allow": [
                    {"site": "api", "methods": ["GET"], "paths": ["/api/ok"]},
                    {"site": "api", "methods": ["POST"], "paths": ["/api/post"]},
                ],
                "approval": {"required_for": ["POST"]},
            },
        )
        v.issue_token("strict")
        v.set_policy(
            "strict",
            {
                "allow": [{"site": "api", "methods": ["POST"], "paths": ["/api/post"]}],
                "approval": {"required_for": ["POST"]},
            },
        )
        v.close()
        self.broker = Broker(home, password="pw")

    def tearDown(self):
        self.broker.vault.close()
        self.target.shutdown()
        self.tmp.cleanup()

    def _dump(self, res):
        return json.dumps(res, ensure_ascii=False)

    def test_human_call_ok_and_redacted(self):
        res = self.broker.call("api", "GET", "/api/ok")
        self.assertTrue(res["ok"])
        self.assertEqual(res["protocol"], "pman")
        self.assertEqual(res["protocol_version"], 2)
        self.assertEqual(res["error_code"], "ok")
        self.assertEqual(res["status_code"], 200)
        body = res["body_json"]
        self.assertEqual(body["data"], [1, 2, 3])
        self.assertEqual(body["access_token"], REDACTED)
        self.assertEqual(body["nested"]["password"], REDACTED)
        self.assertNotIn("X-Auth-Token", res["headers"])  # 敏感响应头被剥离
        dump = self._dump(res)
        self.assertNotIn(helpers.GOOD_TOKEN, dump)
        self.assertGreaterEqual(res["redactions"], 3)

    def test_harness_policy_allowed_and_denied(self):
        ok = self.broker.call("api", "GET", "/api/ok", harness="codex")
        self.assertTrue(ok["ok"])
        denied = self.broker.call("api", "GET", "/api/echo", harness="codex")
        self.assertFalse(denied["ok"])
        self.assertTrue(denied.get("pending_approval"))
        self.assertTrue(denied.get("access_required"))
        self.broker.vault.decide_approval(denied["req_id"], True)
        approved = self.broker.call("api", "GET", "/api/echo", harness="codex")
        self.assertTrue(approved["ok"])
        # 越界批准只精确生效一次，不会永久扩大 allow 策略。
        repeated = self.broker.call("api", "GET", "/api/echo", harness="codex")
        self.assertTrue(repeated.get("pending_approval"))
        self.assertTrue(
            any(
                r["note"] and r["note"].startswith("等待范围授权")
                for r in self.broker.vault.query_audit()
            )
        )

    def test_approval_flow(self):
        res = self.broker.call("api", "POST", "/api/post", json_body={"x": 1}, harness="codex")
        self.assertFalse(res["ok"])
        self.assertTrue(res.get("pending_approval"))
        req_id = res["req_id"]
        self.broker.vault.decide_approval(req_id, True)
        res2 = self.broker.call("api", "POST", "/api/post", json_body={"x": 1}, harness="codex")
        self.assertTrue(res2["ok"])
        self.assertEqual(res2["status_code"], 200)
        self.assertTrue(res2["body_json"]["created"])
        # 默认审批是一次性授权，重复请求必须重新进入审批队列。
        res3 = self.broker.call("api", "POST", "/api/post", json_body={"x": 1}, harness="codex")
        self.assertTrue(res3.get("pending_approval"))

    def test_approval_payload_redacted_before_persist(self):
        res = self.broker.call(
            "api",
            "POST",
            "/api/post",
            json_body={"title": "ok", "password": "sup3r-secret", "token": "tok-123"},
            form={"password": "form-secret"},
            query={"api_key": "query-secret"},
            harness="codex",
        )
        self.assertTrue(res.get("pending_approval"))
        row = self.broker.vault.get_approval(res["req_id"])
        raw = self._dump(row)
        self.assertNotIn("sup3r-secret", raw)
        self.assertNotIn("tok-123", raw)
        self.assertNotIn("form-secret", raw)
        self.assertNotIn("query-secret", raw)
        self.assertEqual(row["payload"]["json_body"]["title"], "ok")
        self.assertEqual(row["payload"]["json_body"]["password"], REDACTED)
        self.assertEqual(row["payload"]["json_body"]["token"], REDACTED)
        self.assertEqual(row["payload"]["form"]["password"], REDACTED)
        self.assertEqual(row["payload"]["query"]["api_key"], REDACTED)

    def test_approval_payload_redacts_known_secret_in_arbitrary_field(self):
        res = self.broker.call(
            "api",
            "POST",
            "/api/post",
            json_body={"note": helpers.GOOD_TOKEN},
            query={"q": helpers.GOOD_TOKEN},
            harness="codex",
        )
        self.assertTrue(res.get("pending_approval"))
        row = self.broker.vault.get_approval(res["req_id"])
        raw = self._dump(row)
        self.assertNotIn(helpers.GOOD_TOKEN, raw)
        self.assertEqual(row["payload"]["json_body"]["note"], REDACTED)
        self.assertEqual(row["payload"]["query"]["q"], REDACTED)

    def test_deny_flow(self):
        res = self.broker.call("api", "POST", "/api/post", harness="strict")
        self.assertTrue(res.get("pending_approval"))
        self.broker.vault.decide_approval(res["req_id"], False)
        res2 = self.broker.call("api", "POST", "/api/post", harness="strict")
        self.assertFalse(res2["ok"])
        self.assertTrue(res2.get("pending_approval"))  # 拒绝后仍需审批

    def test_arbitrary_json_secret_is_blocked_or_redacted(self):
        res = self.broker.call("api", "GET", "/api/arbitrary")
        self.assertTrue(res["ok"])
        self.assertNotIn(helpers.GOOD_TOKEN, self._dump(res))
        self.assertEqual(res["body_json"]["data"], REDACTED)
        self.assertEqual(res["body_json"]["nested"][0], REDACTED)

    def test_plain_text_secret_is_redacted_without_regex_error(self):
        res = self.broker.call("api", "GET", "/api/plain")
        self.assertTrue(res["ok"])
        self.assertNotIn(helpers.GOOD_TOKEN, self._dump(res))
        self.assertIn(REDACTED, res["body_text"])

    def test_cookie_jar_injection_and_echo_redaction(self):
        res = self.broker.call("cookie", "GET", "/api/echo")
        self.assertTrue(res["ok"])
        dump = self._dump(res)
        self.assertNotIn(helpers.COOKIE_VALUE, dump)  # 响应回显 Cookie 被脱敏
        headers = res["body_json"]["request_headers"]
        self.assertEqual(headers["Cookie"], REDACTED)

    def test_login_cookie_injection_and_echo_redaction(self):
        res = self.broker.call("login", "GET", "/api/echo")
        self.assertTrue(res["ok"])
        dump = self._dump(res)
        self.assertNotIn(helpers.COOKIE_VALUE, dump)
        self.assertEqual(res["body_json"]["request_headers"]["Cookie"], REDACTED)

    def test_http_basic(self):
        res = self.broker.call("basic", "GET", "/api/ok")
        self.assertTrue(res["ok"])
        self.assertEqual(res["status_code"], 200)

    def test_wrong_credential_yields_401(self):
        res = self.broker.call("bad", "GET", "/api/ok")
        self.assertTrue(res["ok"])  # 请求执行成功，但站点返回 401
        self.assertEqual(res["status_code"], 401)

    def test_unknown_site(self):
        res = self.broker.call("nope", "GET", "/")
        self.assertFalse(res["ok"])
        self.assertIn("未知站点", res["error"])
        self.assertEqual(res["error_code"], "unknown_site")

    def test_locked_vault_rejected(self):
        self.broker.vault.lock()
        res = self.broker.call("api", "GET", "/api/ok")
        self.assertFalse(res["ok"])
        self.assertIn("未解锁", res["error"])


if __name__ == "__main__":
    unittest.main()
