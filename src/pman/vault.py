"""加密 Vault：SQLite 元数据 + 逐站点 AES-GCM 秘密加密。

- KEK：主密码经 PBKDF2-HMAC-SHA256 派生，只存于进程内存。
- 每站点独立 DEK，用 KEK 包裹后落盘；秘密字段用 DEK 加密。
- 非敏感元数据（别名、URL、用途）明文存储，便于锁定状态下列表。
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import secrets as pysecrets
import sqlite3
import threading
import uuid
from pathlib import Path

from . import crypto

SCHEMA_VERSION = "2"
AUTH_TYPES = ("api_token", "http_basic", "cookie_jar", "login")


class VaultError(Exception):
    pass


def _now_dt() -> datetime.datetime:
    return datetime.datetime.now()


def _now() -> str:
    return _now_dt().isoformat(timespec="seconds")


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _json_or(text, default):
    try:
        return json.loads(text)
    except Exception:
        return default


class Vault:
    def __init__(self, home: str | os.PathLike):
        self.home = Path(home)
        self.home.mkdir(parents=True, exist_ok=True)
        self.db_path = self.home / "vault.db"
        self._kek: bytes | None = None
        self._write_lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._init_schema()

    # ---------------- schema ----------------
    def _init_schema(self) -> None:
        with self._write_lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sites (
                    id TEXT PRIMARY KEY,
                    alias TEXT NOT NULL UNIQUE,
                    name TEXT,
                    site_url TEXT NOT NULL,
                    auth_type TEXT NOT NULL,
                    purpose TEXT,
                    tags TEXT,
                    login_script TEXT,
                    refresh_on TEXT,
                    requires_human INTEGER NOT NULL DEFAULT 0,
                    insecure_tls INTEGER NOT NULL DEFAULT 0,
                    dek_wrapped BLOB,
                    secret_cipher BLOB,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_used_at TEXT,
                    expires_at TEXT,
                    status TEXT NOT NULL DEFAULT 'active'
                );
                CREATE TABLE IF NOT EXISTS harnesses (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    token_hash TEXT,
                    policy_json TEXT NOT NULL DEFAULT '{"default_action":"deny","allow": []}',
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    revoked_at TEXT
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    harness TEXT NOT NULL,
                    site TEXT,
                    method TEXT,
                    path TEXT,
                    status_code INTEGER,
                    resp_bytes INTEGER NOT NULL DEFAULT 0,
                    redactions INTEGER NOT NULL DEFAULT 0,
                    truncated INTEGER NOT NULL DEFAULT 0,
                    approved INTEGER NOT NULL DEFAULT 0,
                    req_id TEXT,
                    note TEXT
                );
                CREATE TABLE IF NOT EXISTS approvals (
                    id TEXT PRIMARY KEY,
                    ts TEXT NOT NULL,
                    harness TEXT NOT NULL,
                    site TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    payload TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    decided_at TEXT,
                    decided_by TEXT,
                    request_fingerprint TEXT,
                    consumed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS leases (
                    id TEXT PRIMARY KEY,
                    harness TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    note TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT,
                    last_used_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_leases_token_hash ON leases(token_hash);
                """
            )
            # v0.3 adds request binding without invalidating existing vaults.
            columns = {
                row[1]
                for row in self._conn.execute("PRAGMA table_info(approvals)").fetchall()
            }
            for name, definition in (
                ("request_fingerprint", "TEXT"),
                ("consumed_at", "TEXT"),
            ):
                if name not in columns:
                    self._conn.execute(
                        f"ALTER TABLE approvals ADD COLUMN {name} {definition}"
                    )
            version = self._conn.execute(
                "SELECT value FROM meta WHERE key='schema_version'"
            ).fetchone()
            if version is not None and version["value"] != SCHEMA_VERSION:
                # v1 只缺少审批绑定列；列补齐后即可原地升级，不触碰任何密文。
                try:
                    old_version = int(version["value"])
                except (TypeError, ValueError) as exc:
                    raise VaultError("vault schema_version 无效，请先备份后处理") from exc
                if old_version > int(SCHEMA_VERSION):
                    raise VaultError(
                        f"vault schema {old_version} 高于当前版本 {SCHEMA_VERSION}，请升级 pman"
                    )
                self._conn.execute(
                    "UPDATE meta SET value=? WHERE key='schema_version'",
                    (SCHEMA_VERSION,),
                )
            self._conn.commit()

    # ---------------- 初始化 / 解锁 ----------------
    @property
    def unlocked(self) -> bool:
        return self._kek is not None

    @property
    def initialized(self) -> bool:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key='master_salt'"
        ).fetchone()
        return row is not None

    def ensure_unlocked(self) -> None:
        if self._kek is None:
            raise VaultError(
                "vault 未解锁：请先 pm vault unlock（或设置环境变量 PM_MASTER_PASSWORD）"
            )

    def create(self, password: str) -> None:
        with self._write_lock:
            if self.initialized:
                raise VaultError(f"vault 已初始化：{self.db_path}")
            salt = os.urandom(crypto.SALT_BYTES)
            kek = crypto.derive_kek(password, salt)
            verifier = crypto.encrypt(kek, b"pman-ok")
            self._conn.executemany(
                "INSERT INTO meta(key,value) VALUES(?,?)",
                [
                    ("schema_version", SCHEMA_VERSION),
                    ("master_salt", salt.hex()),
                    ("kek_verifier", verifier.hex()),
                ],
            )
            self._conn.commit()
            self._kek = kek

    def unlock(self, password: str) -> None:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key='master_salt'"
        ).fetchone()
        if row is None:
            raise VaultError("vault 未初始化：请先 pm init")
        ver = self._conn.execute(
            "SELECT value FROM meta WHERE key='kek_verifier'"
        ).fetchone()
        kek = crypto.derive_kek(password, bytes.fromhex(row["value"]))
        try:
            if crypto.decrypt(kek, bytes.fromhex(ver["value"])) != b"pman-ok":
                raise VaultError("密码错误")
        except VaultError:
            raise
        except Exception as exc:
            raise VaultError("密码错误") from exc
        self._kek = kek

    def lock(self) -> None:
        self._kek = None

    # ---------------- 站点 ----------------
    def add_site(
        self,
        alias: str,
        site_url: str,
        auth_type: str,
        secret: dict,
        *,
        name: str | None = None,
        purpose: str | None = None,
        tags: list[str] | None = None,
        login_script: str | None = None,
        refresh_on: list[int] | None = None,
        requires_human: bool = False,
        insecure_tls: bool = False,
        expires_at: str | None = None,
    ) -> None:
        if auth_type not in AUTH_TYPES:
            raise VaultError(f"auth_type 必须为 {'/'.join(AUTH_TYPES)}")
        if not secret:
            raise VaultError("secret 不能为空")
        with self._write_lock:
            self.ensure_unlocked()
            if self.get_site_row(alias) is not None:
                raise VaultError(f"站点 {alias} 已存在")
            dek = os.urandom(crypto.KEY_BYTES)
            dek_wrapped = crypto.encrypt(self._kek, dek)
            secret_cipher = crypto.encrypt(
                dek, json.dumps(secret, ensure_ascii=False).encode("utf-8")
            )
            now = _now()
            self._conn.execute(
                """INSERT INTO sites(
                       id, alias, name, site_url, auth_type, purpose, tags,
                       login_script, refresh_on, requires_human, insecure_tls,
                       dek_wrapped, secret_cipher, created_at, updated_at, expires_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    uuid.uuid4().hex,
                    alias,
                    name,
                    site_url.rstrip("/"),
                    auth_type,
                    purpose,
                    json.dumps(tags or [], ensure_ascii=False),
                    login_script,
                    json.dumps(refresh_on or [], ensure_ascii=False),
                    int(bool(requires_human)),
                    int(bool(insecure_tls)),
                    dek_wrapped,
                    secret_cipher,
                    now,
                    now,
                    expires_at,
                ),
            )
            self._conn.commit()

    def get_site_row(self, alias: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM sites WHERE alias=?", (alias,)
        ).fetchone()

    def get_site_secret(self, alias: str) -> dict:
        """解密并返回站点秘密；调用方保证不将结果交给 AI。"""
        self.ensure_unlocked()
        row = self.get_site_row(alias)
        if row is None:
            raise VaultError(f"未知站点：{alias}")
        if row["status"] != "active":
            raise VaultError(f"站点 {alias} 已停用")
        try:
            dek = crypto.decrypt(self._kek, row["dek_wrapped"])
            plain = crypto.decrypt(dek, row["secret_cipher"])
            return json.loads(plain.decode("utf-8"))
        except Exception as exc:
            raise VaultError(f"解密站点 {alias} 失败") from exc

    def list_sites(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM sites ORDER BY alias"
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d.pop("dek_wrapped", None)
            d.pop("secret_cipher", None)
            d["tags"] = _json_or(d.get("tags"), [])
            d["refresh_on"] = _json_or(d.get("refresh_on"), [])
            out.append(d)
        return out

    def remove_site(self, alias: str) -> None:
        with self._write_lock:
            self.ensure_unlocked()
            with self._conn:
                exists = self._conn.execute(
                    "SELECT 1 FROM sites WHERE alias=? LIMIT 1", (alias,)
                ).fetchone()
                if exists is None:
                    raise VaultError(f"未知站点：{alias}")
                policies = self._conn.execute(
                    "SELECT name, policy_json FROM harnesses"
                ).fetchall()
                for name, policy_json in policies:
                    try:
                        policy = json.loads(policy_json or "{}")
                    except (TypeError, ValueError):
                        continue
                    allow = policy.get("allow") if isinstance(policy, dict) else None
                    if not isinstance(allow, list):
                        continue
                    filtered = [
                        rule
                        for rule in allow
                        if not isinstance(rule, dict) or rule.get("site") != alias
                    ]
                    if len(filtered) != len(allow):
                        policy["allow"] = filtered
                        self._conn.execute(
                            "UPDATE harnesses SET policy_json=? WHERE name=?",
                            (json.dumps(policy, ensure_ascii=False), name),
                        )
                self._conn.execute("DELETE FROM sites WHERE alias=?", (alias,))

    def touch_site(self, alias: str) -> None:
        with self._write_lock:
            self._conn.execute(
                "UPDATE sites SET last_used_at=? WHERE alias=?", (_now(), alias)
            )
            self._conn.commit()

    def update_secret(self, alias: str, secret: dict) -> None:
        with self._write_lock:
            self.ensure_unlocked()
            row = self.get_site_row(alias)
            if row is None:
                raise VaultError(f"未知站点：{alias}")
            dek = crypto.decrypt(self._kek, row["dek_wrapped"])
            secret_cipher = crypto.encrypt(
                dek, json.dumps(secret, ensure_ascii=False).encode("utf-8")
            )
            self._conn.execute(
                "UPDATE sites SET secret_cipher=?, updated_at=? WHERE alias=?",
                (secret_cipher, _now(), alias),
            )
            self._conn.commit()

    # ---------------- harness / token ----------------
    @staticmethod
    def _expiry(expires_days: int | None, ttl_seconds: int | None) -> str:
        if ttl_seconds is not None:
            return (
                _now_dt() + datetime.timedelta(seconds=int(ttl_seconds))
            ).isoformat(timespec="seconds")
        return (
            _now_dt() + datetime.timedelta(days=int(expires_days or 0))
        ).isoformat(timespec="seconds")

    def issue_token(
        self,
        name: str,
        expires_days: int = 30,
        ttl_seconds: int | None = None,
    ) -> str:
        """签发（或轮换）某 harness 的访问 token，返回明文 token（仅此一次）。

        支持两种有效期：``expires_days``（天，历史接口）或 ``ttl_seconds``
        （秒，推荐给脚本/短期会话）。二者同时提供时以 ttl_seconds 为准。
        """
        token = "pm_" + pysecrets.token_urlsafe(32)
        with self._write_lock:
            self.ensure_unlocked()
            exists = self._conn.execute(
                "SELECT id FROM harnesses WHERE name=?", (name,)
            ).fetchone()
            expires = self._expiry(expires_days, ttl_seconds)
            if exists:
                self._conn.execute(
                    "UPDATE harnesses SET token_hash=?, revoked_at=NULL, expires_at=?, created_at=? WHERE name=?",
                    (_hash_token(token), expires, _now(), name),
                )
            else:
                self._conn.execute(
                    "INSERT INTO harnesses(id,name,token_hash,policy_json,created_at,expires_at) VALUES(?,?,?,?,?,?)",
                    (uuid.uuid4().hex, name, _hash_token(token), '{"default_action":"deny","allow": []}', _now(), expires),
                )
            self._conn.commit()
        return token

    def revoke_token(self, name: str) -> None:
        with self._write_lock:
            cur = self._conn.execute(
                "UPDATE harnesses SET revoked_at=?, token_hash=NULL WHERE name=?",
                (_now(), name),
            )
            self._conn.commit()
            if cur.rowcount == 0:
                raise VaultError(f"未知 harness：{name}")

    def check_token(self, token: str | None) -> dict | None:
        """校验 harness token 或短期租约 token，返回带身份标记的 harness 记录。

        正常 harness token 会附带 ``token_kind="harness"``；租约 token 附带
        ``token_kind="lease"``、``lease_id`` 与 ``lease_note``。策略仍按
        harness 名生效，租约只是更短的有效期 + 独立吊销能力。
        """
        if not token:
            return None
        digest = _hash_token(token)

        row = self._conn.execute(
            "SELECT * FROM harnesses WHERE token_hash=?", (digest,)
        ).fetchone()
        if row is not None and row["revoked_at"] is None:
            if not row["expires_at"] or row["expires_at"] > _now():
                out = dict(row)
                out["token_kind"] = "harness"
                return out

        lease = self._conn.execute(
            "SELECT * FROM leases WHERE token_hash=?", (digest,)
        ).fetchone()
        if lease is None or lease["revoked_at"] is not None:
            return None
        if lease["expires_at"] and lease["expires_at"] <= _now():
            return None
        h = self.get_harness(lease["harness"])
        if h is None or h.get("revoked_at") is not None:
            return None
        self._touch_lease(lease["id"])
        out = dict(h)
        out.update(
            {
                "token_kind": "lease",
                "lease_id": lease["id"],
                "lease_note": lease["note"],
            }
        )
        return out

    # ---------------- 短期租约 ----------------
    def issue_lease(
        self, harness: str, ttl_seconds: int, note: str | None = None
    ) -> dict:
        """为某 harness 签发一条短期租约 token（不影响其主 token）。

        租约复用 harness 的既有策略，适合“一次任务 / 一个 AI 会话”场景；
        到期自动失效，也可按 lease_id 单独吊销。
        """
        if int(ttl_seconds) <= 0:
            raise VaultError("租约 TTL 必须大于 0")
        h = self.get_harness(harness)
        if h is None:
            raise VaultError(f"未知 harness：{harness}")
        if h.get("revoked_at") is not None:
            raise VaultError(f"harness {harness} 已被吊销，不能签发租约")
        token = "pmlease_" + pysecrets.token_urlsafe(32)
        lease_id = "lease_" + uuid.uuid4().hex[:12]
        now = _now()
        expires = self._expiry(None, ttl_seconds)
        with self._write_lock:
            self.ensure_unlocked()
            self._conn.execute(
                """INSERT INTO leases(
                       id, harness, token_hash, note, created_at, expires_at)
                   VALUES(?,?,?,?,?,?)""",
                (lease_id, harness, _hash_token(token), note, now, expires),
            )
            self._conn.commit()
        return {
            "id": lease_id,
            "token": token,
            "harness": harness,
            "note": note,
            "created_at": now,
            "expires_at": expires,
        }

    def list_leases(self, include_revoked: bool = False) -> list[dict]:
        q = (
            "SELECT id, harness, note, created_at, expires_at, revoked_at, last_used_at "
            "FROM leases"
        )
        if not include_revoked:
            q += " WHERE revoked_at IS NULL"
        q += " ORDER BY created_at DESC"
        return [dict(r) for r in self._conn.execute(q).fetchall()]

    def revoke_lease(self, lease_id: str) -> None:
        with self._write_lock:
            cur = self._conn.execute(
                "UPDATE leases SET revoked_at=? WHERE id=?",
                (_now(), lease_id),
            )
            self._conn.commit()
            if cur.rowcount == 0:
                raise VaultError(f"未知租约：{lease_id}")

    def _touch_lease(self, lease_id: str) -> None:
        with self._write_lock:
            self._conn.execute(
                "UPDATE leases SET last_used_at=? WHERE id=?", (_now(), lease_id)
            )
            self._conn.commit()

    def get_harness(self, name: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM harnesses WHERE name=?", (name,)
        ).fetchone()
        return dict(row) if row else None

    def list_harnesses(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT name, policy_json, created_at, expires_at, revoked_at FROM harnesses ORDER BY name"
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["policy"] = _json_or(d.get("policy_json"), {})
            d.pop("policy_json", None)
            out.append(d)
        return out

    def set_policy(self, name: str, policy: dict) -> None:
        with self._write_lock:
            cur = self._conn.execute(
                "UPDATE harnesses SET policy_json=? WHERE name=?",
                (json.dumps(policy, ensure_ascii=False), name),
            )
            self._conn.commit()
            if cur.rowcount == 0:
                raise VaultError(f"未知 harness：{name}")

    def get_policy(self, name: str) -> dict:
        h = self.get_harness(name)
        if h is None:
            raise VaultError(f"未知 harness：{name}")
        return _json_or(h.get("policy_json"), {})

    # ---------------- 审计 ----------------
    def add_audit(
        self,
        harness: str,
        site: str | None,
        method: str | None,
        path: str | None,
        status_code: int | None,
        resp_bytes: int,
        redactions: int,
        truncated: bool,
        approved: bool,
        req_id: str | None = None,
        note: str | None = None,
    ) -> None:
        """审计字段不包含任何秘密。"""
        with self._write_lock:
            self._conn.execute(
                """INSERT INTO audit_log(
                       ts, harness, site, method, path, status_code, resp_bytes,
                       redactions, truncated, approved, req_id, note)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    _now(),
                    harness,
                    site,
                    method,
                    path,
                    status_code,
                    int(resp_bytes or 0),
                    int(redactions or 0),
                    int(bool(truncated)),
                    int(bool(approved)),
                    req_id,
                    note,
                ),
            )
            self._conn.commit()

    def query_audit(
        self, harness: str | None = None, since_hours: float | None = None, limit: int = 200
    ) -> list[dict]:
        q = "SELECT * FROM audit_log"
        conds, args = [], []
        if harness:
            conds.append("harness=?")
            args.append(harness)
        if since_hours:
            t = (_now_dt() - datetime.timedelta(hours=since_hours)).isoformat(timespec="seconds")
            conds.append("ts>=?")
            args.append(t)
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in self._conn.execute(q, args).fetchall()]

    # ---------------- 审批 ----------------
    def create_approval(
        self,
        harness: str,
        site: str,
        method: str,
        path: str,
        payload: dict,
        request_fingerprint: str | None = None,
    ) -> str:
        with self._write_lock:
            if request_fingerprint:
                existing = self._conn.execute(
                    """SELECT id FROM approvals
                       WHERE harness=? AND site=? AND method=? AND path=?
                         AND request_fingerprint=? AND status='pending'
                       ORDER BY ts DESC LIMIT 1""",
                    (harness, site, method, path, request_fingerprint),
                ).fetchone()
                if existing is not None:
                    return str(existing["id"])
            req_id = "apr_" + uuid.uuid4().hex[:12]
            self._conn.execute(
                "INSERT INTO approvals(id,ts,harness,site,method,path,payload,status,request_fingerprint) VALUES(?,?,?,?,?,?,?, 'pending', ?)",
                (
                    req_id,
                    _now(),
                    harness,
                    site,
                    method,
                    path,
                    json.dumps(payload, ensure_ascii=False),
                    request_fingerprint,
                ),
            )
            self._conn.commit()
        return req_id

    def _approval_out(self, row: sqlite3.Row) -> dict:
        d = dict(row)
        d["payload"] = _json_or(d.get("payload"), {})
        return d

    def get_approval(self, req_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM approvals WHERE id=?", (req_id,)
        ).fetchone()
        return self._approval_out(row) if row else None

    def list_approvals(self, status: str = "pending") -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM approvals WHERE status=? ORDER BY ts DESC", (status,)
        ).fetchall()
        return [self._approval_out(r) for r in rows]

    def decide_approval(self, req_id: str, approve: bool, decided_by: str = "human") -> dict | None:
        with self._write_lock:
            row = self.get_approval(req_id)
            if row is None:
                return None
            if row["status"] != "pending":
                return row
            self._conn.execute(
                "UPDATE approvals SET status=?, decided_at=?, decided_by=? WHERE id=?",
                ("approved" if approve else "denied", _now(), decided_by, req_id),
            )
            self._conn.commit()
            return self.get_approval(req_id)

    def has_recent_approval(
        self,
        harness: str,
        site: str,
        method: str,
        within_seconds: int = 600,
        path: str | None = None,
        request_fingerprint: str | None = None,
    ) -> bool:
        """仅允许同一请求指纹在窗口内复用审批。"""
        t = (_now_dt() - datetime.timedelta(seconds=within_seconds)).isoformat(timespec="seconds")
        conditions = [
            "harness=?",
            "site=?",
            "method=?",
            "status='approved'",
            "decided_at>=?",
            "consumed_at IS NULL",
        ]
        args: list[object] = [harness, site, method, t]
        if path is not None:
            conditions.append("path=?")
            args.append(path)
        if request_fingerprint is not None:
            conditions.append("request_fingerprint=?")
            args.append(request_fingerprint)
        row = self._conn.execute(
            "SELECT id FROM approvals WHERE " + " AND ".join(conditions) + " LIMIT 1",
            args,
        ).fetchone()
        return row is not None

    def consume_recent_approval(
        self,
        harness: str,
        site: str,
        method: str,
        within_seconds: int = 600,
        path: str | None = None,
        request_fingerprint: str | None = None,
    ) -> bool:
        """原子消费一条匹配审批；默认授权只允许成功使用一次。"""
        t = (_now_dt() - datetime.timedelta(seconds=within_seconds)).isoformat(timespec="seconds")
        conditions = [
            "harness=?",
            "site=?",
            "method=?",
            "status='approved'",
            "decided_at>=?",
            "consumed_at IS NULL",
        ]
        args: list[object] = [harness, site, method, t]
        if path is not None:
            conditions.append("path=?")
            args.append(path)
        if request_fingerprint is not None:
            conditions.append("request_fingerprint=?")
            args.append(request_fingerprint)
        with self._write_lock:
            row = self._conn.execute(
                "SELECT id FROM approvals WHERE " + " AND ".join(conditions)
                + " ORDER BY decided_at DESC LIMIT 1",
                args,
            ).fetchone()
            if row is None:
                return False
            cur = self._conn.execute(
                "UPDATE approvals SET consumed_at=? WHERE id=? AND consumed_at IS NULL",
                (_now(), row["id"]),
            )
            self._conn.commit()
            return cur.rowcount == 1

    def consume_approval(self, req_id: str) -> bool:
        """原子消费指定的已批准请求，用于等待审批后立即执行。"""
        with self._write_lock:
            cur = self._conn.execute(
                "UPDATE approvals SET consumed_at=? WHERE id=? AND status='approved' AND consumed_at IS NULL",
                (_now(), req_id),
            )
            self._conn.commit()
            return cur.rowcount == 1

    def approval_fingerprint(
        self,
        site: str,
        method: str,
        path: str,
        capability=None,
        query=None,
        json_body=None,
        form=None,
    ) -> str:
        """用 Vault KEK 对完整请求做稳定 HMAC，不把请求秘密落盘。"""
        self.ensure_unlocked()
        canonical = json.dumps(
            {
                "site": site,
                "method": (method or "GET").upper(),
                "path": path or "",
                "capability": capability,
                "query": query,
                "json_body": json_body,
                "form": form,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(self._kek, canonical, hashlib.sha256).hexdigest()

    def close(self) -> None:
        with self._write_lock:
            self._conn.close()
