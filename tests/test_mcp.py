import helpers  # noqa: F401
import json
import tempfile
import unittest

from helpers import start_target, target_url
from pman.mcp_server import DirectBackend, McpServer, TOOLS
from pman.protocol import encode_alias_ref
from pman.vault import Vault


class McpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.target = start_target()
        home = self.tmp.name
        v = Vault(home)
        v.create("pw")
        v.add_site("api", target_url(self.target), "api_token", {"token": helpers.GOOD_TOKEN})
        v.issue_token("codex")
        v.set_policy(
            "codex",
            {"allow": [{"site": "api", "methods": ["GET"], "paths": ["/api/ok"]}]},
        )
        v.close()
        self.server = McpServer(DirectBackend(home, "codex", "pw"))

    def tearDown(self):
        self.server.backend.close()
        self.target.shutdown()
        self.tmp.cleanup()

    def _rpc(self, method, params=None, rid=1):
        return self.server.handle(
            {"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}
        )

    def test_initialize_and_tools_list(self):
        res = self._rpc("initialize", {"protocolVersion": "2024-11-05"})
        self.assertIn("tools", res["result"]["capabilities"])
        self.assertEqual(res["result"]["serverInfo"]["name"], "pman")
        res = self._rpc("tools/list")
        names = [t["name"] for t in res["result"]["tools"]]
        self.assertEqual(names, [t["name"] for t in TOOLS])

    def test_ping_and_notification(self):
        self.assertEqual(self._rpc("ping")["result"], {})
        self.assertIsNone(self._rpc("notifications/initialized"))

    def test_http_tool_ok_redacted(self):
        res = self._rpc(
            "tools/call",
            {"name": "pm_http", "arguments": {"site": "api", "method": "GET", "path": "/api/ok"}},
        )
        content = res["result"]["content"][0]
        self.assertFalse(res["result"]["isError"])
        obj = json.loads(content["text"])
        self.assertTrue(obj["ok"])
        self.assertEqual(obj["protocol"], "pman")
        self.assertEqual(obj["protocol_version"], 2)
        self.assertEqual(obj["status_code"], 200)
        text = json.dumps(res, ensure_ascii=False)
        self.assertNotIn(helpers.GOOD_TOKEN, text)
        self.assertIn("***REDACTED***", text)

    def test_http_tool_requests_one_time_access_outside_policy(self):
        res = self._rpc(
            "tools/call",
            {"name": "pm_http", "arguments": {"site": "api", "method": "GET", "path": "/api/echo"}},
        )
        self.assertTrue(res["result"]["isError"])
        obj = json.loads(res["result"]["content"][0]["text"])
        self.assertTrue(obj["pending_approval"])
        self.assertTrue(obj["access_required"])
        self.assertTrue(obj["req_id"].startswith("apr_"))

    def test_contract_tool(self):
        res = self._rpc("tools/call", {"name": "pm_contract", "arguments": {}})
        self.assertFalse(res["result"]["isError"])
        obj = json.loads(res["result"]["content"][0]["text"])
        self.assertTrue(obj["ok"])
        self.assertEqual(obj["contract"]["protocol"], {"name": "pman", "version": 2})
        self.assertEqual(obj["contract"]["contract"], "pman-ai/2")
        self.assertIn("pm_http", [t["name"] for t in obj["contract"]["mcp_tools"]])

    def test_sites_tool(self):
        res = self._rpc("tools/call", {"name": "pm_sites", "arguments": {}})
        obj = json.loads(res["result"]["content"][0]["text"])
        self.assertTrue(obj["ok"])
        self.assertEqual(obj["sites"][0]["alias"], "api")
        self.assertNotIn("secret", json.dumps(obj, ensure_ascii=False))

    def test_http_tool_accepts_ascii_alias_ref(self):
        alias = "Jenkins 基线"
        vault = self.server.backend.broker.vault
        vault.add_site(
            alias,
            target_url(self.target),
            "api_token",
            {"token": helpers.GOOD_TOKEN},
        )
        vault.set_policy(
            "codex",
            {
                "allow": [
                    {"site": "api", "methods": ["GET"], "paths": ["/api/ok"]},
                    {"site": alias, "methods": ["GET"], "paths": ["/api/ok"]},
                ]
            },
        )

        sites = self._rpc("tools/call", {"name": "pm_sites", "arguments": {}})
        metadata = json.loads(sites["result"]["content"][0]["text"])["sites"]
        site = next(item for item in metadata if item["alias"] == alias)
        self.assertEqual(site["alias_ref"], encode_alias_ref(alias))

        res = self._rpc(
            "tools/call",
            {
                "name": "pm_http",
                "arguments": {
                    "site": site["alias_ref"],
                    "method": "GET",
                    "path": "/api/ok",
                },
            },
        )
        self.assertFalse(res["result"]["isError"])

    def test_secret_field_tool_removed(self):
        names = [t["name"] for t in TOOLS]
        self.assertNotIn("pm_secret_field", names)
        res = self._rpc(
            "tools/call",
            {"name": "pm_secret_field", "arguments": {"site": "api", "key": "token"}},
        )
        self.assertIn("error", res)
        self.assertNotIn(helpers.GOOD_TOKEN, json.dumps(res, ensure_ascii=False))

    def test_unknown_tool_and_method(self):
        self.assertIn("error", self._rpc("tools/call", {"name": "nope", "arguments": {}}))
        self.assertIn("error", self._rpc("no/such/method"))


if __name__ == "__main__":
    unittest.main()
