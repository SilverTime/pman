"""pm 命令行入口：面向人的管理 CLI + 面向 AI 的调用 CLI。

常用流程：
    pm init
    pm site add gitlab --url https://git.internal --type api_token --secret token=xxx --header Private-Token
    pm token issue codex --expires-days 30
    pm grant codex --site gitlab --methods GET --paths "/api/v4/**"
    pm call --site gitlab --method GET --path /api/v4/version
    pm daemon
    pm mcp --harness codex
"""
from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import re
import sys
from pathlib import Path

from . import __version__
from .ai_spec import contract_dict, contract_markdown
from .broker import Broker
from .client import ClientError, DaemonClient
from .daemon import PmanDaemon, exit_when_parent_stops
from .mcp_server import BackendError, McpServer, make_backend
from .protocol import annotate
from .vault import AUTH_TYPES, Vault, VaultError

EXAMPLES = """示例：
  pm init
  pm site add gitlab --url https://git.internal --type api_token --secret token=glpat-xxx --header Private-Token
  pm site add jira --url https://jira.internal --type cookie_jar --cookie-header "JSESSIONID=abc; atlassian.xsrf.token=xyz"
  pm site ls
  pm token issue codex --expires-days 30
  pm grant codex --site gitlab --methods GET --paths "/api/v4/**" "/api/v4/version"
  pm grant claude --approve-for POST,DELETE --rate-limit 60
  pm call --site gitlab --method GET --path /api/v4/version
  pm run --site gitlab --method GET --path /api/v4/version
  pm lease issue codex --ttl 15m --note "job-42"
  pm daemon --port 9777
  pm mcp --harness codex --daemon http://127.0.0.1:9777 --token <token>
"""


# ---------------- helpers ----------------
def _home() -> Path:
    return Path(os.environ.get("PM_HOME", Path.home() / ".pman"))


def _read_password(confirm: bool = False) -> str:
    env = os.environ.get("PM_MASTER_PASSWORD")
    if env:
        return env
    if not sys.stdin.isatty():
        raise VaultError("未设置环境变量 PM_MASTER_PASSWORD，且当前无交互终端")
    try:
        pw = getpass.getpass("主密码: ")
        if confirm:
            pw2 = getpass.getpass("再次输入主密码: ")
            if pw != pw2:
                raise VaultError("两次输入不一致")
    except EOFError:
        raise VaultError("读取密码失败（无可用输入）") from None
    if not pw:
        raise VaultError("密码不能为空")
    return pw


_OPEN_VAULTS: list[Vault] = []


def _open_vault() -> Vault:
    """打开 vault 并登记；dispatch 结束时统一关闭，避免 Windows 文件锁。"""
    vault = Vault(_home())
    _OPEN_VAULTS.append(vault)
    return vault


def _open_direct(password: str | None = None) -> Vault:
    """直接模式：打开并解锁 vault（解锁态仅本进程有效）。"""
    vault = _open_vault()
    if password is not None:
        vault.unlock(password)
    else:
        vault.unlock(_read_password())
    return vault


def _write_text(text: str) -> None:
    """输出文本：真实进程强制 UTF-8，测试重定向时退回 sys.stdout。"""
    try:
        buf = getattr(sys.stdout, "buffer", None)
        if buf is not None:
            buf.write(text.encode("utf-8"))
            buf.flush()
            return
    except Exception:
        pass
    sys.stdout.write(text)
    sys.stdout.flush()


def _dump(obj) -> None:
    """输出 JSON：真实进程强制 UTF-8（AI/脚本契约），测试重定向时退回文本流。"""
    _write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")


def _die(msg) -> int:
    print(f"错误：{msg}", file=sys.stderr)
    return 1


def _split_list(values) -> list[str]:
    out = []
    for v in values or []:
        out.extend(s.strip() for s in v.split(",") if s.strip())
    return out


_TTL_RE = re.compile(r"^(\d+)\s*(s|sec|m|min|h|hr|d)$", re.IGNORECASE)


def _parse_ttl(text: str) -> int:
    """把 ``15m`` / ``2h`` / ``90s`` / ``7d`` 解析为秒。"""
    m = _TTL_RE.fullmatch((text or "").strip().lower())
    if not m:
        raise VaultError("--ttl 需要形如 90s / 15m / 2h / 7d")
    n = int(m.group(1))
    unit = m.group(2)[0]
    seconds = n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    if seconds <= 0:
        raise VaultError("--ttl 必须大于 0")
    return seconds


def _parse_cookie_header(text: str) -> list[dict]:
    cookies = []
    for part in text.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            cookies.append({"name": k.strip(), "value": v.strip()})
    return cookies


def _collect_secret(args) -> dict:
    secret: dict = {}
    for kv in getattr(args, "secret", None) or []:
        if "=" not in kv:
            raise VaultError(f"--secret 需要 k=v 形式：{kv}")
        k, v = kv.split("=", 1)
        secret[k.strip()] = v
    if getattr(args, "header", None):
        secret["header"] = args.header
    if getattr(args, "secret_json", None):
        obj = json.loads(Path(args.secret_json).read_text(encoding="utf-8"))
        if not isinstance(obj, dict):
            raise VaultError("--secret-json 文件内容必须是 JSON 对象")
        secret.update(obj)
    if getattr(args, "cookie_header", None):
        secret["cookies"] = _parse_cookie_header(args.cookie_header)
    return secret


def _ensure_secret_fields(secret: dict, atype: str, args) -> dict:
    """校验并按需交互补齐秘密字段。"""

    def ask(key: str, hidden: bool = False) -> str:
        if not sys.stdin.isatty():
            raise VaultError(f"缺少秘密字段 {key!r}，且当前无交互终端")
        try:
            if hidden:
                return getpass.getpass(f"  {key}: ")
            return input(f"  {key}: ").strip()
        except EOFError:
            raise VaultError(f"缺少秘密字段 {key!r}") from None

    if atype == "api_token":
        if "token" not in secret:
            secret["token"] = ask("token", hidden=True)
        if "header" not in secret:
            if sys.stdin.isatty():
                try:
                    secret["header"] = (
                        input("  自定义请求头名（回车=Authorization）: ").strip()
                        or "Authorization"
                    )
                except EOFError:
                    secret["header"] = "Authorization"
            else:
                secret["header"] = "Authorization"
    elif atype == "http_basic":
        if "username" not in secret:
            secret["username"] = ask("username")
        if "password" not in secret:
            secret["password"] = ask("password", hidden=True)
    elif atype == "cookie_jar":
        if not secret.get("cookies"):
            secret["cookies"] = _parse_cookie_header(ask("Cookie 头（a=b; c=d）"))
    elif atype == "login":
        if "username" not in secret:
            secret["username"] = ask("username")
        if "password" not in secret:
            secret["password"] = ask("password", hidden=True)
        if not getattr(args, "login_script", None):
            raise VaultError("login 型站点必须提供 --login-script（登录脚本，M3 能力）")
    return secret


# ---------------- 命令实现 ----------------
def cmd_init(args) -> int:
    vault = _open_vault()
    if vault.initialized:
        return _die(f"vault 已初始化：{vault.db_path}")
    vault.create(_read_password(confirm=True))
    print(f"vault 已初始化：{vault.db_path}")
    print("提示：请妥善保管主密码；丢失将无法解密任何站点秘密。")
    return 0


def cmd_vault_unlock(args) -> int:
    if args.daemon:
        return _die("pmd 必须在启动时通过 PM_MASTER_PASSWORD 解锁；解锁不接受 harness token")
    else:
        vault = _open_vault()
        vault.unlock(_read_password())
        print("密码正确。")
        print("注意：直接模式下解锁状态不跨进程；pmd 请在启动前设置 PM_MASTER_PASSWORD。")
    return 0


def cmd_vault_lock(args) -> int:
    if args.daemon:
        return _die("pmd 锁定仅允许本地人工管理；请停止 pmd 或使用桌面端")
    return _die("直接模式没有驻留进程可锁定")


def cmd_vault_status(args) -> int:
    if args.daemon:
        _dump(DaemonClient(args.daemon, args.token).status())
    else:
        vault = _open_vault()
        _dump({"home": str(vault.home), "initialized": vault.initialized, "unlocked": vault.unlocked})
    return 0


def cmd_site_add(args) -> int:
    if args.type not in AUTH_TYPES:
        return _die(f"--type 必须为 {'/'.join(AUTH_TYPES)}")
    vault = _open_direct()
    secret = _ensure_secret_fields(_collect_secret(args), args.type, args)
    vault.add_site(
        args.alias,
        args.url,
        args.type,
        secret,
        name=args.name,
        purpose=args.purpose,
        tags=_split_list(args.tags),
        login_script=args.login_script,
        requires_human=args.requires_human,
        insecure_tls=args.insecure,
    )
    print(f"站点 {args.alias} 已添加（{args.type}）")
    return 0


def cmd_site_ls(args) -> int:
    vault = _open_vault()
    sites = vault.list_sites()
    if getattr(args, "json", False):
        _dump({"ok": True, "sites": sites})
        return 0
    if not sites:
        print("（暂无站点）")
        return 0
    print(f"{'ALIAS':<16}{'TYPE':<12}{'URL':<40}{'PURPOSE':<24}{'LAST_USED':<20}")
    for s in sites:
        print(
            f"{s['alias']:<16}{s['auth_type']:<12}{s['site_url']:<40}"
            f"{(s['purpose'] or ''):<24}{(s['last_used_at'] or ''):<20}"
        )
    return 0


def cmd_sites(args) -> int:
    """AI/脚本友好：以 JSON 列出站点元数据（不含秘密）。"""
    if args.daemon:
        sites = DaemonClient(args.daemon, args.token).sites().get("sites", [])
    else:
        sites = _open_vault().list_sites()
    _dump(annotate({"ok": True, "sites": sites}))
    return 0


def _find_site(sites, alias: str) -> dict | None:
    for s in sites:
        if s["alias"] == alias:
            return s
    return None


def cmd_cred_status(args) -> int:
    """AI/脚本友好：查看某条凭据的元数据状态，不解密、不碰秘密。"""
    if args.daemon:
        client = DaemonClient(args.daemon, args.token)
        sites = client.sites().get("sites", [])
        vault_state = client.status()
    else:
        vault = _open_vault()
        sites = vault.list_sites()
        vault_state = {"unlocked": vault.unlocked, "initialized": vault.initialized}
    site = _find_site(sites, args.alias)
    if site is None:
        return _die(f"未知站点：{args.alias}（可用 pm sites / pm cred ls 查看别名）")
    _dump(annotate({"ok": True, "credential": site, "vault": vault_state}))
    return 0


def cmd_ai_help(args) -> int:
    """输出 pman 的 AI 契约；--json 输出机器可读版本。"""
    if args.json:
        _dump(contract_dict())
    else:
        _write_text(contract_markdown())
    return 0


def cmd_site_rm(args) -> int:
    vault = _open_vault()
    try:
        vault.remove_site(args.alias)
    except VaultError as e:
        return _die(str(e))
    print(f"站点 {args.alias} 已删除")
    return 0


def cmd_site_test(args) -> int:
    vault = _open_direct()
    res = Broker(vault=vault).call(args.alias, "GET", "/")
    _dump(res)
    return 0 if res.get("ok") else 1


def cmd_site_rotate(args) -> int:
    vault = _open_direct()
    if vault.get_site_row(args.alias) is None:
        return _die(f"未知站点：{args.alias}")
    atype = vault.get_site_row(args.alias)["auth_type"]
    secret = _ensure_secret_fields(_collect_secret(args), atype, args)
    vault.update_secret(args.alias, secret)
    print(f"站点 {args.alias} 秘密已更新")
    return 0


def cmd_token_issue(args) -> int:
    vault = _open_direct()
    ttl_seconds = _parse_ttl(args.ttl) if args.ttl else None
    token = vault.issue_token(args.harness, args.expires_days, ttl_seconds=ttl_seconds)
    h = vault.get_harness(args.harness)
    expires_at = h.get("expires_at") if h else None
    ttl_label = args.ttl or f"{args.expires_days}d"
    vault.add_audit(
        args.harness, None, None, None, None, 0, 0, False, False, None,
        f"签发/轮换 harness token（有效期 {ttl_label}）",
    )
    if getattr(args, "json", False):
        _dump(
            {
                "ok": True,
                "harness": args.harness,
                "token": token,
                "expires_at": expires_at,
            }
        )
    else:
        print(token)
        print(
            f"（该 token 仅显示这一次，请配置到 harness 的 MCP/工具环境变量 PM_TOKEN；"
            f"有效期 {ttl_label}）",
            file=sys.stderr,
        )
    return 0


def cmd_token_revoke(args) -> int:
    vault = _open_direct()
    vault.revoke_token(args.harness)
    vault.add_audit(
        args.harness, None, None, None, None, 0, 0, False, False, None,
        "吊销 harness token",
    )
    if getattr(args, "json", False):
        _dump({"ok": True, "harness": args.harness, "revoked": True})
    else:
        print(f"harness {args.harness} 已吊销")
    return 0


def cmd_token_ls(args) -> int:
    vault = _open_vault()
    rows = vault.list_harnesses()
    if getattr(args, "json", False):
        _dump({"ok": True, "harnesses": rows})
        return 0
    if not rows:
        print("（暂无 harness）")
        return 0
    print(f"{'NAME':<16}{'REVOKED':<22}{'EXPIRES':<22}")
    for h in rows:
        print(f"{h['name']:<16}{(h['revoked_at'] or ''):<22}{(h['expires_at'] or ''):<22}")
    return 0


def cmd_lease_issue(args) -> int:
    vault = _open_direct()
    ttl_seconds = _parse_ttl(args.ttl)
    lease = vault.issue_lease(args.harness, ttl_seconds, args.note)
    vault.add_audit(
        args.harness, None, None, None, None, 0, 0, False, False, None,
        f"签发短期租约 {lease['id']}（TTL {args.ttl}）",
    )
    if getattr(args, "json", False):
        _dump({"ok": True, "lease": lease})
    else:
        print(lease["token"])
        print(
            f"（租约 {lease['id']} 仅显示这一次，绑定 harness {args.harness}，"
            f"TTL {args.ttl}；可用 pm lease ls / pm lease revoke 管理）",
            file=sys.stderr,
        )
    return 0


def cmd_lease_ls(args) -> int:
    vault = _open_vault()
    rows = vault.list_leases(include_revoked=bool(getattr(args, "all", False)))
    if getattr(args, "json", False):
        _dump({"ok": True, "leases": rows})
        return 0
    if not rows:
        print("（暂无租约）")
        return 0
    print(f"{'LEASE_ID':<20}{'HARNESS':<14}{'TTL_EXPIRES':<22}{'LAST_USED':<20}{'NOTE'}")
    for r in rows:
        print(
            f"{r['id']:<20}{r['harness']:<14}{r['expires_at']:<22}"
            f"{(r['last_used_at'] or ''):<20}{(r['note'] or '')}"
        )
    return 0


def cmd_lease_revoke(args) -> int:
    vault = _open_direct()
    lease = next(
        (r for r in vault.list_leases(include_revoked=True) if r["id"] == args.lease_id),
        None,
    )
    if lease is None:
        return _die(f"未知租约：{args.lease_id}")
    vault.revoke_lease(args.lease_id)
    vault.add_audit(
        lease["harness"], None, None, None, None, 0, 0, False, False, None,
        f"吊销短期租约 {args.lease_id}",
    )
    if getattr(args, "json", False):
        _dump({"ok": True, "lease_id": args.lease_id, "revoked": True})
    else:
        print(f"租约 {args.lease_id} 已吊销")
    return 0


def cmd_grant(args) -> int:
    vault = _open_direct()
    policy = vault.get_policy(args.harness)
    if args.policy_json:
        policy = json.loads(Path(args.policy_json).read_text(encoding="utf-8"))
    if args.rate_limit is not None:
        policy.setdefault("rate_limit", {})["req_per_min"] = int(args.rate_limit)
    if args.approve_for is not None:
        policy.setdefault("approval", {})["required_for"] = _split_list(args.approve_for)
    if args.site:
        paths = []
        for grp in args.paths or []:
            paths.extend(grp)
        entry = {
            "site": args.site,
            "methods": _split_list(args.methods) or ["GET"],
            "paths": _split_list(paths),
        }
        policy.setdefault("allow", [])
        policy["allow"] = [e for e in policy["allow"] if e.get("site") != args.site]
        policy["allow"].append(entry)
    vault.set_policy(args.harness, policy)
    print(f"harness {args.harness} 策略已更新：")
    _dump(policy)
    return 0


def cmd_revoke(args) -> int:
    vault = _open_direct()
    policy = vault.get_policy(args.harness)
    policy["allow"] = [e for e in policy.get("allow", []) if e.get("site") != args.site]
    vault.set_policy(args.harness, policy)
    print(f"已从 harness {args.harness} 策略中移除站点 {args.site}")
    return 0


def cmd_policy_show(args) -> int:
    vault = _open_vault()
    _dump(vault.get_policy(args.harness))
    return 0


def _parse_call_args(args):
    query = {}
    for kv in args.query or []:
        if "=" not in kv:
            raise VaultError(f"--query 需要 k=v 形式：{kv}")
        k, v = kv.split("=", 1)
        query[k.strip()] = v
    if args.query_json:
        obj = json.loads(args.query_json)
        if not isinstance(obj, dict):
            raise VaultError("--query-json 必须是 JSON 对象")
        query.update(obj)
    form = {}
    for kv in args.form or []:
        if "=" not in kv:
            raise VaultError(f"--form 需要 k=v 形式：{kv}")
        k, v = kv.split("=", 1)
        form[k.strip()] = v
    json_body = None
    if args.json is not None:
        json_body = json.loads(args.json)
    if args.json_file:
        json_body = json.loads(Path(args.json_file).read_text(encoding="utf-8"))
    return query or None, form or None, json_body


def cmd_call(args) -> int:
    query, form, json_body = _parse_call_args(args)
    if args.daemon:
        client = DaemonClient(args.daemon, args.token)
        res = client.http(args.site, args.method, args.path, query, json_body, form, args.capability)
    else:
        vault = _open_direct()
        res = Broker(vault=vault).call(
            args.site,
            args.method,
            args.path,
            capability=args.capability,
            query=query,
            json_body=json_body,
            form=form,
            harness=args.harness,
            wait_approval_timeout=args.wait_approval,
        )
    _dump(res)
    return 0 if res.get("ok") else 1


def cmd_approve(args) -> int:
    approve = not getattr(args, "deny", False)
    if args.daemon:
        return _die("审批仅允许本地人工管理，不接受 harness token")
    else:
        vault = _open_direct()
        row = vault.decide_approval(args.req_id, approve)
    if row is None:
        return _die(f"审批不存在：{args.req_id}")
    print(f"审批 {row['id']} → {row['status']}")
    return 0


def cmd_approvals(args) -> int:
    if args.daemon:
        return _die("审批队列仅允许本地人工管理，不接受 harness token")
    else:
        rows = _open_vault().list_approvals("pending")
    if getattr(args, "json", False):
        _dump({"ok": True, "approvals": rows})
        return 0
    if not rows:
        print("（无待审批请求）")
        return 0
    print(f"{'REQ_ID':<18}{'HARNESS':<14}{'METHOD':<8}{'SITE':<14}{'PATH'}")
    for r in rows:
        print(f"{r['id']:<18}{r['harness']:<14}{r['method']:<8}{r['site']:<14}{r['path']}")
    return 0


def cmd_audit(args) -> int:
    if args.daemon:
        return _die("审计仅允许本地人工管理，不接受 harness token")
    else:
        rows = _open_vault().query_audit(args.harness, args.since, args.limit)
    if getattr(args, "json", False):
        _dump({"ok": True, "audit": rows})
        return 0
    if not rows:
        print("（暂无审计记录）")
        return 0
    print(f"{'TS':<20}{'HARNESS':<12}{'METHOD':<8}{'SITE':<12}{'PATH':<32}{'STATUS':<8}{'BYTES':<8}{'REDACT':<8}")
    for r in rows:
        print(
            f"{r['ts']:<20}{r['harness']:<12}{(r['method'] or ''):<8}{(r['site'] or ''):<12}"
            f"{(r['path'] or '')[:30]:<32}{(str(r['status_code'] or '')):<8}{r['resp_bytes']:<8}{r['redactions']:<8}"
        )
    return 0


def cmd_daemon(args) -> int:
    if args.log_file:
        logging.basicConfig(
            filename=args.log_file, level=logging.INFO,
            format="%(asctime)s %(name)s %(levelname)s %(message)s",
        )
    else:
        logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                            format="%(asctime)s %(name)s %(levelname)s %(message)s")
    if getattr(args, "password_stdin", False):
        password = sys.stdin.readline(4097)
        if len(password) > 4096:
            return _die("主密码输入过长")
        password = password.rstrip("\r\n")
    else:
        password = os.environ.get("PM_MASTER_PASSWORD")
    if not password:
        return _die(
            "启动 pmd 必须由桌面端通过安全输入提供主密码，"
            "或由人工设置 PM_MASTER_PASSWORD；运行中的 pmd 不接受远程解锁"
        )
    daemon = PmanDaemon(_home(), password, args.port)
    password = None
    exit_when_parent_stops(getattr(args, "parent_pid", None))
    host, port = daemon.address
    print(f"pmd 已启动：http://{host}:{port}（已自动解锁）", file=sys.stderr)
    daemon.start(block=True)
    return 0


def cmd_mcp(args) -> int:
    try:
        backend = make_backend(args.daemon, args.token, args.harness, str(_home()))
    except BackendError as e:
        return _die(str(e))
    McpServer(backend).run_stdio()
    return 0


# ---------------- parser ----------------
def _add_call_parser(sub, name, daemon_opts):
    """call / run 共用同一组参数：run 是面向 AI 的同义命令。"""
    p = sub.add_parser(
        name,
        help="以站点身份执行 HTTP 请求（凭据由本地代理注入，输出净化后 JSON）",
    )
    p.add_argument("--site", required=True)
    p.add_argument("--method", default="GET")
    p.add_argument("--path", default="/")
    p.add_argument("--capability")
    p.add_argument("--query", action="append", metavar="K=V")
    p.add_argument("--query-json", metavar="JSON")
    p.add_argument("--json", metavar="JSON", help="JSON 请求体")
    p.add_argument("--json-file", metavar="FILE")
    p.add_argument("--form", action="append", metavar="K=V")
    p.add_argument("--harness", help="以某 harness 身份执行（应用其策略）")
    p.add_argument("--wait-approval", type=float, default=0.0, metavar="SEC")
    daemon_opts(p)
    p.set_defaults(func=cmd_call)
    return p


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pm",
        description="pman：面向 AI harness 的本地凭据代理（秘密永不进入 AI 上下文）",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"pman {__version__}")
    sub = parser.add_subparsers(dest="command")

    def daemon_opts(p):
        p.add_argument("--daemon", default=os.environ.get("PM_DAEMON"),
                       help="pmd 地址（默认 http://127.0.0.1:9777）")
        p.add_argument("--token", default=os.environ.get("PM_TOKEN"), help="harness token")

    # init
    p = sub.add_parser("init", help="初始化加密 vault")
    p.set_defaults(func=cmd_init)

    # vault
    p = sub.add_parser("vault", help="查看状态；直接模式校验解锁密码")
    pv = p.add_subparsers(dest="sub")
    p = pv.add_parser("unlock", help="直接模式校验密码；pmd 必须启动时设置 PM_MASTER_PASSWORD")
    daemon_opts(p)
    p.set_defaults(func=cmd_vault_unlock)
    p = pv.add_parser("lock", help="锁定仅由本地人工管理或桌面端完成")
    daemon_opts(p)
    p.set_defaults(func=cmd_vault_lock)
    p = pv.add_parser("status", help="查看状态")
    daemon_opts(p)
    p.set_defaults(func=cmd_vault_status)

    # site
    p = sub.add_parser("site", help="站点管理")
    ps = p.add_subparsers(dest="sub")
    p = ps.add_parser("add", help="添加站点")
    p.add_argument("alias")
    p.add_argument("--url", required=True, help="站点根 URL")
    p.add_argument("--type", required=True, choices=AUTH_TYPES, help="认证类型")
    p.add_argument("--secret", action="append", metavar="K=V", help="秘密字段，可重复")
    p.add_argument("--secret-json", metavar="FILE", help="秘密 JSON 文件（k=v 优先）")
    p.add_argument("--header", metavar="NAME", help="api_token 请求头名（默认 Authorization）")
    p.add_argument("--cookie-header", metavar="STR", help="Cookie 头（cookie_jar 类型快捷导入）")
    p.add_argument("--name", help="显示名")
    p.add_argument("--purpose", help="用途说明")
    p.add_argument("--tags", action="append", metavar="A,B")
    p.add_argument("--login-script", metavar="FILE", help="登录脚本（login 类型，M3 能力）")
    p.add_argument("--requires-human", action="store_true", help="会话刷新需要人工（如 MFA）")
    p.add_argument("--insecure", action="store_true", help="信任自签证书（内网站点）")
    p.set_defaults(func=cmd_site_add)
    p = ps.add_parser("ls", help="列出站点（不含秘密）")
    p.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    p.set_defaults(func=cmd_site_ls)
    p = ps.add_parser("rm", help="删除站点")
    p.add_argument("alias")
    p.set_defaults(func=cmd_site_rm)
    p = ps.add_parser("test", help="测试站点连通性（GET /）")
    p.add_argument("alias")
    p.set_defaults(func=cmd_site_test)
    p = ps.add_parser("rotate", help="更新站点秘密")
    p.add_argument("alias")
    p.add_argument("--secret", action="append", metavar="K=V")
    p.add_argument("--secret-json", metavar="FILE")
    p.add_argument("--header", metavar="NAME", help="api_token 请求头名")
    p.add_argument("--cookie-header", metavar="STR")
    p.add_argument("--login-script", metavar="FILE")
    p.set_defaults(func=cmd_site_rotate)

    # token
    p = sub.add_parser("token", help="harness token 管理")
    pt = p.add_subparsers(dest="sub")
    p = pt.add_parser("issue", help="签发/轮换 token（明文仅显示一次）")
    p.add_argument("harness")
    p.add_argument("--expires-days", type=int, default=30, help="有效期天数（默认 30）")
    p.add_argument("--ttl", metavar="15m|2h|90s|7d", help="短期 TTL（优先于 --expires-days）")
    p.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    p.set_defaults(func=cmd_token_issue)
    p = pt.add_parser("revoke", help="吊销 token")
    p.add_argument("harness")
    p.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    p.set_defaults(func=cmd_token_revoke)
    p = pt.add_parser("ls", help="列出 harness")
    p.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    p.set_defaults(func=cmd_token_ls)

    # lease：任务级短期租约 token
    p = sub.add_parser("lease", help="短期租约 token（任务/会话级，独立吊销）")
    pl = p.add_subparsers(dest="sub")
    p = pl.add_parser("issue", help="签发短期租约（明文仅显示一次）")
    p.add_argument("harness")
    p.add_argument("--ttl", required=True, metavar="15m|2h|90s|7d", help="租约有效期")
    p.add_argument("--note", help="用途备注（如某次任务/会话）")
    p.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    p.set_defaults(func=cmd_lease_issue)
    p = pl.add_parser("ls", help="列出租约")
    p.add_argument("--all", action="store_true", help="包含已吊销租约")
    p.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    p.set_defaults(func=cmd_lease_ls)
    p = pl.add_parser("revoke", help="吊销指定租约")
    p.add_argument("lease_id")
    p.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    p.set_defaults(func=cmd_lease_revoke)

    # grant / revoke / policy
    p = sub.add_parser("grant", help="给 harness 授权站点/方法/路径（白名单）")
    p.add_argument("harness")
    p.add_argument("--site", help="站点别名")
    p.add_argument("--methods", action="append", metavar="GET,POST", help="方法列表")
    p.add_argument("--paths", action="append", nargs="+", metavar="GLOB", help="路径 glob，可多个")
    p.add_argument("--rate-limit", type=int, metavar="N", help="每分钟请求配额")
    p.add_argument("--approve-for", action="append", metavar="POST,DELETE", help="需要人工审批的方法")
    p.add_argument("--policy-json", metavar="FILE", help="用文件整体替换策略")
    p.set_defaults(func=cmd_grant)
    p = sub.add_parser("revoke", help="撤销 harness 对某站点的授权")
    p.add_argument("harness")
    p.add_argument("--site", required=True)
    p.set_defaults(func=cmd_revoke)
    p = sub.add_parser("policy", help="查看/管理 harness 策略")
    pp = p.add_subparsers(dest="sub")
    q = pp.add_parser("show", help="显示策略")
    q.add_argument("harness")
    q.set_defaults(func=cmd_policy_show)

    # AI 自发现契约
    p = sub.add_parser("ai-help", help="输出 AI 使用契约（安全边界 + 命令规范）")
    p.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    p.set_defaults(func=cmd_ai_help)

    # AI/脚本友好的站点元数据（JSON）
    p = sub.add_parser("sites", help="列出站点元数据（JSON，不含秘密）")
    daemon_opts(p)
    p.set_defaults(func=cmd_sites)

    # cred：AI 视角的“凭据”命令组（与 site 同源，只暴露元数据）
    p = sub.add_parser("cred", help="AI 友好的凭据发现/状态/使用命令")
    pc = p.add_subparsers(dest="sub")
    q = pc.add_parser("ls", aliases=["list"], help="列出凭据（JSON，不含秘密）")
    daemon_opts(q)
    q.set_defaults(func=cmd_sites)
    q = pc.add_parser("status", help="查看凭据元数据状态（JSON）")
    q.add_argument("alias")
    daemon_opts(q)
    q.set_defaults(func=cmd_cred_status)
    _add_call_parser(pc, "run", daemon_opts)

    # call / run（同一语义，call 为人类习惯名，run 为 AI 规范名）
    _add_call_parser(sub, "call", daemon_opts)
    _add_call_parser(sub, "run", daemon_opts)

    # approvals
    p = sub.add_parser("approve", help="批准待审批请求")
    p.add_argument("req_id")
    daemon_opts(p)
    p.set_defaults(func=cmd_approve)
    p = sub.add_parser("deny", help="拒绝待审批请求")
    p.add_argument("req_id")
    daemon_opts(p)
    p.set_defaults(func=lambda a: cmd_approve(argparse.Namespace(**{**vars(a), "deny": True})))
    p = sub.add_parser("approvals", help="查看待审批队列")
    p.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    daemon_opts(p)
    p.set_defaults(func=cmd_approvals)

    # audit
    p = sub.add_parser("audit", help="查看审计日志（不含秘密）")
    p.add_argument("--harness")
    p.add_argument("--since", type=float, metavar="HOURS")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    daemon_opts(p)
    p.set_defaults(func=cmd_audit)

    # daemon / mcp
    p = sub.add_parser("daemon", help="启动 pmd（前台运行，只监听 127.0.0.1）")
    p.add_argument("--port", type=int, default=9777)
    p.add_argument("--log-file", metavar="FILE")
    p.add_argument("--password-stdin", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--parent-pid", type=int, help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_daemon)
    p = sub.add_parser("mcp", help="启动 MCP stdio server（供 harness 调用）")
    p.add_argument("--harness", help="策略归属 harness（内嵌模式必填）")
    daemon_opts(p)
    p.set_defaults(func=cmd_mcp)

    return parser


def dispatch(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not getattr(args, "func", None):
        build_parser().print_help()
        return 0
    try:
        return args.func(args)
    except VaultError as e:
        return _die(str(e))
    except ClientError as e:
        return _die(str(e))
    except FileNotFoundError as e:
        return _die(str(e))
    except BrokenPipeError:
        return 0
    finally:
        for v in _OPEN_VAULTS:
            try:
                v.close()
            except Exception:
                pass
        _OPEN_VAULTS.clear()


def main() -> None:
    sys.exit(dispatch())


if __name__ == "__main__":
    main()
