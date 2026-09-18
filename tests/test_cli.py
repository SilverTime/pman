import helpers  # noqa: F401
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from helpers import start_target, target_url
from pman import cli


class CliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.target = start_target()
        self.env = {
            "PM_HOME": self.tmp.name,
            "PM_MASTER_PASSWORD": "cli-pw",
            "PM_KDF_ITERATIONS": "1000",
        }
        self._old = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)
        self.url = target_url(self.target)

    def tearDown(self):
        for k, v in self._old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.target.shutdown()
        self.tmp.cleanup()

    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.dispatch(argv)
        return code, out.getvalue(), err.getvalue()

    def test_init_twice_fails(self):
        self.assertEqual(self._run(["init"])[0], 0)
        code, _, err = self._run(["init"])
        self.assertEqual(code, 1)
        self.assertIn("已初始化", err)

    def test_full_flow(self):
        self.assertEqual(self._run(["init"])[0], 0)
        code, _, err = self._run(
            ["site", "add", "api", "--url", self.url, "--type", "api_token",
             "--secret", "token=" + helpers.GOOD_TOKEN]
        )
        self.assertEqual(code, 0, err)
        code, out, _ = self._run(["token", "issue", "codex"])
        self.assertEqual(code, 0)
        token = out.strip().splitlines()[0]
        self.assertTrue(token.startswith("pm_"))
        code, out, _ = self._run(
            ["grant", "codex", "--site", "api", "--methods", "GET", "--paths", "/api/ok"]
        )
        self.assertEqual(code, 0)
        code, out, _ = self._run(
            ["call", "--site", "api", "--method", "GET", "--path", "/api/ok", "--harness", "codex"]
        )
        self.assertEqual(code, 0)
        obj = json.loads(out)
        self.assertTrue(obj["ok"])
        self.assertNotIn(helpers.GOOD_TOKEN, out)
        self.assertIn("***REDACTED***", out)
        code, out, _ = self._run(["audit", "--harness", "codex"])
        self.assertEqual(code, 0)
        self.assertIn("codex", out)

    def test_call_outside_policy_requests_one_time_access(self):
        self._run(["init"])
        self._run(["site", "add", "api", "--url", self.url, "--type", "api_token",
                   "--secret", "token=" + helpers.GOOD_TOKEN])
        self._run(["token", "issue", "codex"])
        self._run(["grant", "codex", "--site", "api", "--methods", "GET", "--paths", "/api/ok"])
        code, out, _ = self._run(
            ["call", "--site", "api", "--path", "/api/echo", "--harness", "codex"]
        )
        self.assertEqual(code, 1)
        result = json.loads(out)
        self.assertTrue(result["pending_approval"])
        self.assertTrue(result["access_required"])
        self.assertEqual(result["error_code"], "pending_approval")

    def test_site_ls_and_token_ls(self):
        self._run(["init"])
        self._run(["site", "add", "api", "--url", self.url, "--type", "api_token",
                   "--secret", "token=x"])
        code, out, _ = self._run(["site", "ls"])
        self.assertEqual(code, 0)
        self.assertIn("api", out)
        self._run(["token", "issue", "codex"])
        code, out, _ = self._run(["token", "ls"])
        self.assertEqual(code, 0)
        self.assertIn("codex", out)

    def test_json_outputs_for_human_commands(self):
        self._run(["init"])
        self._run(["site", "add", "api", "--url", self.url, "--type", "api_token",
                   "--secret", "token=" + helpers.GOOD_TOKEN])
        code, out, _ = self._run(["site", "ls", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["sites"][0]["alias"], "api")
        self._run(["token", "issue", "codex"])
        code, out, _ = self._run(["token", "ls", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["harnesses"][0]["name"], "codex")
        code, out, _ = self._run(["audit", "--json"])
        self.assertEqual(code, 0)
        self.assertIsInstance(json.loads(out)["audit"], list)

    def test_short_ttl_token_and_lease_lifecycle(self):
        self._run(["init"])
        code, out, _ = self._run(
            ["token", "issue", "codex", "--ttl", "2h", "--json"]
        )
        self.assertEqual(code, 0)
        tok_obj = json.loads(out)
        self.assertEqual(tok_obj["harness"], "codex")
        self.assertTrue(tok_obj["token"].startswith("pm_"))

        code, out, _ = self._run(
            ["lease", "issue", "codex", "--ttl", "15m", "--note", "job-42", "--json"]
        )
        self.assertEqual(code, 0)
        lease = json.loads(out)["lease"]
        self.assertTrue(lease["token"].startswith("pmlease_"))

        code, out, _ = self._run(["lease", "ls", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["leases"][0]["id"], lease["id"])

        code, out, _ = self._run(["lease", "revoke", lease["id"], "--json"])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out)["revoked"])

        code, out, _ = self._run(["lease", "ls", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["leases"], [])

    def test_ai_contract_discovery_and_status(self):
        self._run(["init"])
        self._run(["site", "add", "api", "--url", self.url, "--type", "api_token",
                   "--secret", "token=" + helpers.GOOD_TOKEN])
        code, out, _ = self._run(["ai-help", "--json"])
        self.assertEqual(code, 0)
        spec = json.loads(out)
        self.assertEqual(spec["contract"], "pman-ai/2")
        self.assertEqual(spec["protocol"], {"name": "pman", "version": 2})
        self.assertIn("pm_http", [t["name"] for t in spec["mcp_tools"]])

        code, out, _ = self._run(["sites"])
        self.assertEqual(code, 0)
        sites = json.loads(out)["sites"]
        self.assertEqual([s["alias"] for s in sites], ["api"])

        code, out, _ = self._run(["cred", "ls"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["sites"][0]["alias"], "api")

        code, out, _ = self._run(["cred", "status", "api"])
        self.assertEqual(code, 0)
        obj = json.loads(out)
        self.assertTrue(obj["ok"])
        self.assertEqual(obj["credential"]["alias"], "api")
        self.assertNotIn("secret_cipher", json.dumps(obj, ensure_ascii=False))

    def test_site_add_custom_header(self):
        self._run(["init"])
        code, _, err = self._run(
            ["site", "add", "hdr", "--url", self.url, "--type", "api_token",
             "--secret", "token=" + helpers.GOOD_TOKEN, "--header", "Private-Token"]
        )
        self.assertEqual(code, 0, err)
        code, out, _ = self._run(["call", "--site", "hdr", "--path", "/api/echo"])
        self.assertEqual(code, 0)
        obj = json.loads(out)
        headers = obj["body_json"]["request_headers"]
        self.assertIn("Private-Token", headers)
        self.assertNotIn(helpers.GOOD_TOKEN, out)

    def test_run_alias_uses_credential_without_secret(self):
        self._run(["init"])
        self._run(["site", "add", "api", "--url", self.url, "--type", "api_token",
                   "--secret", "token=" + helpers.GOOD_TOKEN])
        code, out, _ = self._run(["run", "--site", "api", "--path", "/api/ok"])
        self.assertEqual(code, 0)
        obj = json.loads(out)
        self.assertTrue(obj["ok"])
        self.assertNotIn(helpers.GOOD_TOKEN, out)
        self.assertIn("***REDACTED***", out)

    def test_daemon_accepts_desktop_password_over_stdin(self):
        fake_daemon = unittest.mock.Mock()
        fake_daemon.address = ("127.0.0.1", 9777)
        old_password = os.environ.pop("PM_MASTER_PASSWORD", None)
        try:
            with (
                patch("pman.cli.PmanDaemon", return_value=fake_daemon) as daemon_type,
                patch("pman.cli.exit_when_parent_stops") as parent_watch,
                patch("sys.stdin", io.StringIO("desktop-pw\n")),
            ):
                code, _, error = self._run(
                    ["daemon", "--password-stdin", "--parent-pid", "4321"]
                )
        finally:
            if old_password is not None:
                os.environ["PM_MASTER_PASSWORD"] = old_password

        self.assertEqual(code, 0, error)
        daemon_type.assert_called_once_with(Path(self.tmp.name), "desktop-pw", 9777)
        parent_watch.assert_called_once_with(4321)
        fake_daemon.start.assert_called_once_with(block=True)
        self.assertNotIn("desktop-pw", error)


if __name__ == "__main__":
    unittest.main()
