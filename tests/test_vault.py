import helpers  # noqa: F401
import tempfile
import unittest

from pman.vault import Vault, VaultError


class VaultTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.vault = Vault(self.tmp.name)
        self.vault.create("master-pw")

    def tearDown(self):
        self.vault.close()
        self.tmp.cleanup()

    def test_unlock_lock_wrong_password(self):
        self.assertTrue(self.vault.unlocked)

    def test_schema_v2_and_v1_auto_migration(self):
        version = self.vault._conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()[0]
        self.assertEqual(version, "2")
        self.vault._conn.execute(
            "UPDATE meta SET value='1' WHERE key='schema_version'"
        )
        self.vault._conn.commit()
        self.vault.close()
        migrated = Vault(self.tmp.name)
        self.assertEqual(
            migrated._conn.execute(
                "SELECT value FROM meta WHERE key='schema_version'"
            ).fetchone()[0],
            "2",
        )
        columns = {
            row[1]
            for row in migrated._conn.execute("PRAGMA table_info(approvals)").fetchall()
        }
        self.assertIn("request_fingerprint", columns)
        self.assertIn("consumed_at", columns)
        migrated.unlock("master-pw")
        migrated.close()
        # tearDown 只关闭已替换的连接，避免重复 close。
        self.vault = Vault(self.tmp.name)
        self.vault.lock()
        self.assertFalse(self.vault.unlocked)
        with self.assertRaises(VaultError):
            self.vault.unlock("wrong-pw")
        self.vault.unlock("master-pw")
        self.assertTrue(self.vault.unlocked)

    def test_add_and_get_secret(self):
        self.vault.add_site("gitlab", "https://git.local/", "api_token", {"token": "glpat-x"})
        self.assertEqual(self.vault.get_site_secret("gitlab")["token"], "glpat-x")
        sites = self.vault.list_sites()
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0]["site_url"], "https://git.local")
        self.assertNotIn("dek_wrapped", sites[0])
        self.assertNotIn("secret_cipher", sites[0])

    def test_secret_encrypted_at_rest(self):
        self.vault.add_site(
            "s", "https://x", "http_basic", {"username": "u", "password": "p@ss-word-xyz"}
        )
        raw = self.vault.db_path.read_bytes()
        self.assertNotIn(b"p@ss-word-xyz", raw)

    def test_duplicate_alias_rejected(self):
        self.vault.add_site("a", "https://x", "api_token", {"token": "t"})
        with self.assertRaises(VaultError):
            self.vault.add_site("a", "https://y", "api_token", {"token": "t"})

    def test_remove_site_cleans_matching_policy_rules(self):
        self.vault.add_site("gitlab", "https://git.local", "api_token", {"token": "t"})
        self.vault.issue_token("codex")
        self.vault.set_policy(
            "codex",
            {
                "allow": [
                    {"site": "gitlab", "methods": ["GET"], "paths": ["/api/**"]},
                    {"site": "other", "methods": ["GET"], "paths": ["/health"]},
                ]
            },
        )
        self.vault.remove_site("gitlab")
        policy = self.vault.get_policy("codex")
        self.assertEqual(policy["allow"], [{"site": "other", "methods": ["GET"], "paths": ["/health"]}])

    def test_secret_requires_unlock(self):
        self.vault.add_site("a", "https://x", "api_token", {"token": "t"})
        self.vault.lock()
        with self.assertRaises(VaultError):
            self.vault.get_site_secret("a")

    def test_token_lifecycle(self):
        tok = self.vault.issue_token("codex")
        h = self.vault.check_token(tok)
        self.assertIsNotNone(h)
        self.assertEqual(h["name"], "codex")
        self.assertIsNone(self.vault.check_token("pm_bad"))
        self.vault.revoke_token("codex")
        self.assertIsNone(self.vault.check_token(tok))

    def test_token_expiry(self):
        tok = self.vault.issue_token("tmp", expires_days=0)
        self.assertIsNone(self.vault.check_token(tok))

    def test_token_ttl_seconds(self):
        tok = self.vault.issue_token("short", ttl_seconds=60)
        h = self.vault.check_token(tok)
        self.assertIsNotNone(h)
        self.assertEqual(h["name"], "short")
        self.assertEqual(h["token_kind"], "harness")

    def test_lease_lifecycle(self):
        main_token = self.vault.issue_token("codex")
        lease = self.vault.issue_lease("codex", 600, note="nightly job")
        self.assertTrue(lease["id"].startswith("lease_"))
        self.assertTrue(lease["token"].startswith("pmlease_"))
        h = self.vault.check_token(lease["token"])
        self.assertIsNotNone(h)
        self.assertEqual(h["name"], "codex")
        self.assertEqual(h["token_kind"], "lease")
        self.assertEqual(h["lease_id"], lease["id"])
        self.assertEqual(h["lease_note"], "nightly job")
        self.assertTrue(self.vault.list_leases()[0]["last_used_at"] is not None)
        self.vault.revoke_lease(lease["id"])
        self.assertIsNone(self.vault.check_token(lease["token"]))
        # 租约吊销不影响 harness 主 token
        self.assertIsNotNone(self.vault.check_token(main_token))

    def test_lease_rejects_non_positive_ttl(self):
        self.vault.issue_token("codex")
        with self.assertRaises(VaultError):
            self.vault.issue_lease("codex", 0)

    def test_lease_requires_valid_harness(self):
        with self.assertRaises(VaultError):
            self.vault.issue_lease("nope", 60)

    def test_audit(self):
        self.vault.add_audit("codex", "gitlab", "GET", "/x", 200, 100, 2, False, False)
        rows = self.vault.query_audit(harness="codex")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["redactions"], 2)

    def test_approvals(self):
        rid = self.vault.create_approval("codex", "gitlab", "POST", "/mr", {"a": 1})
        self.assertIsNotNone(self.vault.get_approval(rid))
        self.assertFalse(self.vault.has_recent_approval("codex", "gitlab", "POST"))
        self.vault.decide_approval(rid, True)
        self.assertEqual(self.vault.get_approval(rid)["status"], "approved")
        self.assertTrue(self.vault.has_recent_approval("codex", "gitlab", "POST"))
        # 已决请求不再改变
        self.vault.decide_approval(rid, False)
        self.assertEqual(self.vault.get_approval(rid)["status"], "approved")

    def test_approval_binding_and_one_shot_consumption(self):
        rid = self.vault.create_approval(
            "codex", "gitlab", "POST", "/mr", {"a": 1}, request_fingerprint="fp-1"
        )
        self.vault.decide_approval(rid, True)
        self.assertTrue(
            self.vault.has_recent_approval(
                "codex", "gitlab", "POST", path="/mr", request_fingerprint="fp-1"
            )
        )
        self.assertFalse(
            self.vault.has_recent_approval(
                "codex", "gitlab", "POST", path="/other", request_fingerprint="fp-1"
            )
        )
        self.assertTrue(
            self.vault.consume_recent_approval(
                "codex", "gitlab", "POST", path="/mr", request_fingerprint="fp-1"
            )
        )
        self.assertFalse(
            self.vault.consume_recent_approval(
                "codex", "gitlab", "POST", path="/mr", request_fingerprint="fp-1"
            )
        )


if __name__ == "__main__":
    unittest.main()
