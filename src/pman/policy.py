"""策略引擎：每个 harness 独立 profile，默认拒绝为安全基线。

policy JSON 结构::

    {
      "default_action": "deny",
      "rate_limit": {"req_per_min": 60},
      "allow": [
        {"site": "gitlab", "methods": ["GET"], "paths": ["/api/v4/**"]}
      ],
      "approval": {"required_for": ["POST", "PUT", "DELETE"]},
      "redact": {
        "strip_headers": ["set-cookie", "authorization"],
        "json_keys": ["(?i).*token.*"],
        "max_response_bytes": 524288
      },
    }

路径支持 glob：``**`` 匹配任意字符，``*`` 匹配非 ``/`` 字符。
"""
from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass


def _glob_to_regex(pattern: str) -> re.Pattern:
    escaped = re.escape(pattern)
    escaped = escaped.replace(r"\*\*", ".*")
    escaped = escaped.replace(r"\*", "[^/]*")
    return re.compile("^" + escaped + "$")


@dataclass
class Decision:
    allowed: bool
    reason: str = ""
    approval_required: bool = False


class Policy:
    def __init__(self, policy: dict | None):
        self.policy = policy or {}
        # Missing or invalid values deliberately keep the secure default.
        # ``default`` is accepted as a compatibility alias for hand-written
        # policies; the desktop always writes the canonical key.
        configured_action = self.policy.get(
            "default_action", self.policy.get("default", "deny")
        )
        self.default_action = "allow" if configured_action == "allow" else "deny"

    @classmethod
    def empty(cls) -> "Policy":
        return cls({"allow": []})

    def authorize(self, site_alias: str, method: str, path: str) -> Decision:
        """按 allow 规则匹配；未匹配时遵循显式 default_action，缺省拒绝。"""
        return self.authorize_request(site_alias, method, path)

    def authorize_request(self, site_alias: str, method: str, path: str, capability=None,
                          query=None, json_body=None, form=None) -> Decision:
        for entry in self.policy.get("allow", []):
            if entry.get("site") != site_alias:
                continue
            methods = [m.upper() for m in entry.get("methods", [])]
            if method.upper() not in methods:
                continue
            paths = entry.get("paths", [])
            if entry.get("capability") is not None and entry.get("capability") != capability:
                continue
            if not _constraints_match(entry.get("constraints") or {}, query, json_body, form):
                continue
            if not paths:
                return Decision(True)
            for pat in paths:
                if _glob_to_regex(pat).match(path):
                    return Decision(True)
        if self.default_action == "allow":
            return Decision(True)
        return Decision(False, f"策略拒绝：{method} {path} @ {site_alias}")

    def approval_required(self, method: str) -> bool:
        rf = self.policy.get("approval", {}).get("required_for", [])
        return method.upper() in [m.upper() for m in rf]

    def redact(self) -> dict:
        return self.policy.get("redact", {})

    def rate_limit_per_min(self) -> int:
        try:
            return int(self.policy.get("rate_limit", {}).get("req_per_min", 0))
        except (TypeError, ValueError):
            return 0


def _constraints_match(constraints: dict, query, json_body, form) -> bool:
    sources = {"query": query, "json_body": json_body, "form": form}
    for source, fields in constraints.items():
        if source not in sources or not isinstance(fields, dict):
            return False
        actual = sources[source]
        if not isinstance(actual, dict):
            return False
        for key, patterns in fields.items():
            if key not in actual or not isinstance(patterns, list) or not patterns:
                return False
            value = actual[key]
            if isinstance(value, (dict, list)):
                return False
            rendered = "null" if value is None else str(value).lower() if isinstance(value, bool) else str(value)
            if not any(isinstance(pattern, str) and _glob_to_regex(pattern).match(rendered) for pattern in patterns):
                return False
    return True


class RateLimiter:
    """进程内滑动窗口限流（每秒窗口固定 60s，按 harness 计数）。"""

    def __init__(self) -> None:
        self._events: dict[str, deque] = {}

    def check(self, name: str, per_min: int) -> tuple[bool, str]:
        if per_min <= 0:
            return True, ""
        now = time.monotonic()
        q = self._events.setdefault(name, deque())
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= per_min:
            return False, f"超过配额 {per_min} 次/分钟"
        q.append(now)
        return True, ""
