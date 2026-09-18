import helpers  # noqa: F401
import unittest

from pman.policy import Policy, RateLimiter

POL = {
    "allow": [
        {"site": "gitlab", "methods": ["GET"], "paths": ["/api/v4/**"]},
        {"site": "wiki", "methods": ["GET", "POST"], "paths": ["/page/*"]},
        {"site": "open", "methods": ["GET"], "paths": []},
    ],
    "approval": {"required_for": ["POST", "DELETE"]},
    "rate_limit": {"req_per_min": 5},
}


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.p = Policy(POL)

    def test_glob_star_star(self):
        self.assertTrue(self.p.authorize("gitlab", "GET", "/api/v4/projects").allowed)
        self.assertTrue(self.p.authorize("gitlab", "get", "/api/v4/version").allowed)
        self.assertFalse(self.p.authorize("gitlab", "POST", "/api/v4/projects").allowed)
        self.assertFalse(self.p.authorize("gitlab", "GET", "/api/v3/x").allowed)

    def test_star_not_crossing_slash(self):
        self.assertTrue(self.p.authorize("wiki", "GET", "/page/a").allowed)
        self.assertFalse(self.p.authorize("wiki", "GET", "/page/a/b").allowed)

    def test_default_deny(self):
        self.assertFalse(Policy({"allow": []}).authorize("x", "GET", "/").allowed)
        self.assertFalse(Policy(None).authorize("x", "GET", "/").allowed)

    def test_default_allow_is_explicit(self):
        self.assertTrue(
            Policy({"default_action": "allow"}).authorize("x", "GET", "/anything").allowed
        )
        self.assertTrue(
            Policy({"default": "allow"}).authorize("x", "GET", "/compat").allowed
        )
        self.assertFalse(
            Policy({"default_action": "unexpected"}).authorize("x", "GET", "/").allowed
        )

    def test_empty_paths_allows_any_path(self):
        self.assertTrue(self.p.authorize("open", "GET", "/anything/here").allowed)

    def test_approval_required(self):
        self.assertTrue(self.p.approval_required("POST"))
        self.assertTrue(self.p.approval_required("delete"))
        self.assertFalse(self.p.approval_required("GET"))

    def test_rate_limiter(self):
        rl = RateLimiter()
        self.assertTrue(rl.check("a", 2)[0])
        self.assertTrue(rl.check("a", 2)[0])
        ok, why = rl.check("a", 2)
        self.assertFalse(ok)
        self.assertIn("配额", why)
        self.assertTrue(rl.check("b", 2)[0])


if __name__ == "__main__":
    unittest.main()
