import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { Activity } from "./Activity";
import { Access, GrantDialog } from "./Access";
import { LoginDialog } from "./Credentials";
import { ConnectionLibrary } from "./ConnectionLibrary";
import { ImportDialog, ResumeDialog, SettingsPanel } from "./Settings";
import {
  ApprovalSummary,
  AssistanceRequest,
  AuditEntry,
  call,
  Client,
  defaultSettings,
  errorText,
  HarnessSummary,
  managementLocked,
  nativeAvailable,
  Route,
  Settings,
  SiteSummary,
  timestamp,
  VaultStatus,
} from "./api";
import { Brand, Empty, Icon, IconName, Modal, Notice, useAction } from "./ui";
import { previewData } from "./preview";

const navigation: { id: Route; title: string; icon: IconName }[] = [
  { id: "credentials", title: "连接", icon: "link" },
  { id: "access", title: "AI 工具", icon: "grid" },
  { id: "activity", title: "活动", icon: "activity" },
  { id: "settings", title: "设置", icon: "settings" },
];
const preview =
  !nativeAvailable() &&
  new URLSearchParams(window.location.search).get("preview") === "1";
const previewState = new URLSearchParams(window.location.search).get("state");

export default function App() {
  const [status, setStatus] = useState<VaultStatus | null>(
    preview
      ? {
          ...previewData.status,
          management_locked:
            previewState === "locked" || previewState === "paused",
          service_paused: previewState === "paused",
          service_running: previewState !== "paused",
        }
      : null,
  );
  const [settings, setSettings] = useState<Settings>({
    ...defaultSettings,
    theme:
      preview &&
      new URLSearchParams(window.location.search).get("theme") === "dark"
        ? "dark"
        : "light",
  });
  const [settingsLoaded, setSettingsLoaded] = useState(preview);
  const [error, setError] = useState<string | null>(null);
  const [resuming, setResuming] = useState(false);
  const inFlight = useRef(false);
  const statusEpoch = useRef(0);
  const refresh = useCallback(async () => {
    if (preview || !nativeAvailable() || inFlight.current) return;
    inFlight.current = true;
    const epoch = statusEpoch.current;
    try {
      const next = await call<VaultStatus>("vault_status");
      if (epoch === statusEpoch.current) {
        setStatus(next);
        setError(null);
      }
    } catch (err) {
      setError(errorText(err));
    } finally {
      inFlight.current = false;
    }
  }, []);
  useEffect(() => {
    if (!nativeAvailable()) return;
    void refresh();
    void call<Settings>("settings_get")
      .then((next) => setSettings({ ...defaultSettings, ...next }))
      .catch((err) => setError(errorText(err)))
      .finally(() => setSettingsLoaded(true));
    const interval = window.setInterval(() => void refresh(), 2000);
    const unsubscribers: (() => void)[] = [];
    let disposed = false;
    for (const event of [
      "pman-state-changed",
      "management-locked",
      "service-changed",
      "approvals-changed",
    ]) {
      void listen(event, () => {
        if (event === "management-locked") {
          statusEpoch.current += 1;
          window.dispatchEvent(new Event("pman-hide-secrets"));
          setStatus((current) =>
            current ? { ...current, management_locked: true } : current,
          );
        }
        if (event === "approvals-changed")
          window.dispatchEvent(new Event("pman-refresh-data"));
        void refresh();
      })
        .then((fn) => {
          if (disposed) fn();
          else unsubscribers.push(fn);
        })
        .catch(() => undefined);
    }
    return () => {
      disposed = true;
      window.clearInterval(interval);
      unsubscribers.forEach((fn) => fn());
    };
  }, [refresh]);
  useEffect(() => {
    document.documentElement.dataset.theme = settings.theme;
    document.documentElement.dataset.motion = settings.reduced_motion
      ? "reduced"
      : "normal";
  }, [settings.theme, settings.reduced_motion]);
  if (!nativeAvailable() && !preview)
    return (
      <div className="boot-screen">
        <Brand />
        <div className="boot-card">
          <Icon name="terminal" size={36} />
          <h1>打开 pman 桌面工作台</h1>
          <p>凭据和授权由本机原生服务管理。浏览器页面不能直接连接保险库。</p>
          <a className="button" href="?preview=1">
            查看使用合成数据的界面预览
          </a>
        </div>
      </div>
    );
  if (!status || !settingsLoaded)
    return (
      <div className="boot-screen">
        <Brand />
        <div className="boot-card">
          <h1>正在连接本机服务</h1>
          <p>读取保险库和授权服务状态…</p>
          <Notice error={error} />
          {error && (
            <button className="button" onClick={() => void refresh()}>
              重新连接
            </button>
          )}
        </div>
      </div>
    );
  return (
    <>
      <div className={preview ? "app-root preview-mode" : "app-root"}>
        {preview && (
          <div className="preview-banner">
            界面预览 · 仅合成数据 · 不连接真实保险库，操作需在桌面应用中完成
          </div>
        )}
        {managementLocked(status) || !status.initialized ? (
          <UnlockScreen
            status={status}
            error={error}
            helloEnabled={settings.hello_enabled}
            onRefresh={refresh}
            onResume={() => setResuming(true)}
          />
        ) : (
          <Workbench
            status={status}
            settings={settings}
            onSettings={setSettings}
            onRefreshStatus={refresh}
            onResume={() => setResuming(true)}
            statusError={error}
          />
        )}
      </div>
      {resuming && (
        <ResumeDialog
          helloAvailable={status.hello_available && settings.hello_enabled}
          onClose={() => setResuming(false)}
          onResumed={refresh}
        />
      )}
    </>
  );
}

function UnlockScreen({
  status,
  error,
  helloEnabled,
  onRefresh,
  onResume,
}: {
  status: VaultStatus;
  error: string | null;
  helloEnabled: boolean;
  onRefresh: () => Promise<void>;
  onResume: () => void;
}) {
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [importing, setImporting] = useState(false);
  const action = useAction();
  async function unlock(event: FormEvent) {
    event.preventDefault();
    await action.run(async () => {
      if (
        !status.initialized &&
        (password.length < 12 || password !== confirmation)
      )
        throw new Error(
          password.length < 12
            ? "主密码至少 12 个字符。"
            : "两次输入的主密码不一致。",
        );
      await call(status.initialized ? "management_unlock" : "vault_create", {
        password,
      });
      setPassword("");
      setConfirmation("");
      await onRefresh();
    });
  }
  return (
    <div className="unlock-screen">
      <header>
        <Brand />
        <ServiceBadge status={status} />
      </header>
      <main className="unlock-layout">
        <section className="unlock-context">
          <span className="eyebrow">LOCAL AUTHORIZATION TERMINAL</span>
          <h1>
            你的账号。
            <br />
            你的授权边界。
          </h1>
          <p>密码留在本机，AI 在你允许的范围内工作。</p>
          <div className="service-statement">
            <span
              className={`service-line ${status.service_running ? "running" : ""}`}
            />
            <div>
              <h2>
                {status.service_paused
                  ? "AI 服务已由你暂停"
                  : status.service_running
                    ? "AI 服务继续运行"
                    : status.initialized
                      ? "AI 服务等待恢复"
                      : "从本机保险库开始"}
              </h2>
              <p>
                {status.service_paused
                  ? "暂停状态已保存。Windows 登录或重启后也不会自动恢复。"
                  : status.service_running
                    ? "Windows 锁屏和管理界面锁定，不影响已获得授权的调用。"
                    : status.initialized
                      ? "验证身份后可查看状态，并主动恢复授权服务。"
                      : "保存密码、连接网站，再为 AI 指定可以使用的账号与操作。"}
              </p>
            </div>
          </div>
          {status.pending_approvals > 0 && (
            <div className="locked-approvals">
              <Icon name="bell" />
              <span>
                <strong>{status.pending_approvals}</strong>{" "}
                个请求等待审批，验证后查看。
              </span>
            </div>
          )}
        </section>
        <section className="unlock-card">
          <span className="unlock-emblem">
            <Icon name="lock" size={27} />
          </span>
          <h2>{status.initialized ? "管理界面已锁定" : "创建本地保险库"}</h2>
          <p>
            {status.initialized
              ? "验证本人身份，管理凭据与 AI 权限。"
              : "设置主密码，用于管理验证与备份恢复。"}
          </p>
          <form className="stack-form" onSubmit={unlock}>
            <label>
              主密码
              <input
                autoFocus
                required
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete={
                  status.initialized ? "current-password" : "new-password"
                }
                placeholder={
                  status.initialized ? "输入主密码" : "至少 12 个字符"
                }
              />
            </label>
            {!status.initialized && (
              <label>
                再次输入主密码
                <input
                  required
                  type="password"
                  value={confirmation}
                  onChange={(event) => setConfirmation(event.target.value)}
                  autoComplete="new-password"
                />
              </label>
            )}
            <Notice error={action.error || error} />
            <button
              className="button primary full"
              type="submit"
              disabled={action.busy}
            >
              {action.busy
                ? "验证中…"
                : status.initialized
                  ? "解锁管理界面"
                  : "创建保险库"}
              <Icon name="arrow" size={16} />
            </button>
            {status.initialized && status.hello_available && helloEnabled && (
              <button
                className="button full"
                type="button"
                disabled={action.busy}
                onClick={() =>
                  void action.run(async () => {
                    await call("management_unlock_hello");
                    await onRefresh();
                  })
                }
              >
                使用 Windows Hello
              </button>
            )}
          </form>
          {status.initialized && status.service_paused && (
            <button className="text-button resume-link" onClick={onResume}>
              验证并恢复 AI 服务
            </button>
          )}
          {!status.initialized && (
            <button
              className="text-button resume-link"
              onClick={() => setImporting(true)}
            >
              导入已有保险库
            </button>
          )}
          <div className="unlock-footnote">
            <Icon name="shield" size={14} />
            {status.service_running
              ? "解锁管理界面不会更改 AI 授权"
              : "主动暂停的服务需要单独恢复"}
          </div>
        </section>
      </main>
      <footer>
        <span>本机加密存储 · MCP / CLI 授权调用</span>
        <button
          className="text-button"
          onClick={() => void action.run(() => call("window_hide"))}
        >
          隐藏到托盘
        </button>
      </footer>
      {importing && (
        <ImportDialog
          onClose={() => setImporting(false)}
          onSaved={async () => {
            setImporting(false);
            await onRefresh();
          }}
        />
      )}
    </div>
  );
}

function ServiceBadge({ status }: { status: VaultStatus }) {
  const running = status.service_running;
  return (
    <span
      className={`service-badge ${running ? "running" : status.service_paused ? "paused" : "pending"}`}
      title={status.ai_proxy?.detail}
    >
      <i />
      {running
        ? "AI 服务运行中"
        : status.service_paused
          ? "AI 服务已暂停"
          : "AI 服务未就绪"}
    </span>
  );
}

function Workbench({
  status,
  settings,
  onSettings,
  onRefreshStatus,
  onResume,
  statusError,
}: {
  status: VaultStatus;
  settings: Settings;
  onSettings: (value: Settings) => void;
  onRefreshStatus: () => Promise<void>;
  onResume: () => void;
  statusError: string | null;
}) {
  const [route, setRoute] = useState<Route>("credentials");
  const [sites, setSites] = useState<SiteSummary[]>(
    preview ? previewData.sites : [],
  );
  const [harnesses, setHarnesses] = useState<HarnessSummary[]>(
    preview ? previewData.harnesses : [],
  );
  const [clients, setClients] = useState<Client[]>(
    preview ? previewData.clients : [],
  );
  const [entries, setEntries] = useState<AuditEntry[]>(
    preview ? previewData.entries : [],
  );
  const [approvals, setApprovals] = useState<ApprovalSummary[]>(
    preview ? previewData.approvals : [],
  );
  const [assistance, setAssistance] = useState<AssistanceRequest[]>(
    preview ? previewData.assistance : [],
  );
  const [assistedLogin, setAssistedLogin] = useState<{
    request: AssistanceRequest;
    site: SiteSummary;
  } | null>(null);
  const [assistedAccess, setAssistedAccess] =
    useState<AssistanceRequest | null>(null);
  const [loading, setLoading] = useState(!preview);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [approvalOpen, setApprovalOpen] = useState(false);
  const [focusSite, setFocusSite] = useState<string | null>(null);
  const [focusHarness, setFocusHarness] = useState<string | null>(null);
  const action = useAction();
  const inFlight = useRef(false);
  const mounted = useRef(true);
  const refresh = useCallback(async () => {
    if (preview || inFlight.current) return;
    inFlight.current = true;
    const results = await Promise.allSettled([
      call<SiteSummary[]>("list_sites"),
      call<HarnessSummary[]>("list_harnesses"),
      call<Client[]>("clients_list"),
      call<AuditEntry[]>("list_audit", { limit: 200 }),
      call<ApprovalSummary[]>("list_approvals", { status: "pending" }),
      call<AssistanceRequest[]>("assistance_list", { status: "pending" }),
    ]);
    if (mounted.current) {
      if (results[0].status === "fulfilled") setSites(results[0].value);
      if (results[1].status === "fulfilled") setHarnesses(results[1].value);
      if (results[2].status === "fulfilled") setClients(results[2].value);
      if (results[3].status === "fulfilled") setEntries(results[3].value);
      if (results[4].status === "fulfilled") setApprovals(results[4].value);
      if (results[5].status === "fulfilled") setAssistance(results[5].value);
      const labels = ["凭据", "授权策略", "客户端", "活动", "审批", "协助请求"];
      const errors = results.flatMap((result, index) =>
        result.status === "rejected"
          ? [`${labels[index]}：${errorText(result.reason)}`]
          : [],
      );
      setLoadError(
        errors.length
          ? `部分数据更新失败，当前仍显示上次结果。${errors.join("；")}`
          : null,
      );
      setLoading(false);
    }
    inFlight.current = false;
  }, []);
  useEffect(() => {
    mounted.current = true;
    void refresh();
    const timer = window.setInterval(() => void refresh(), 4000);
    const update = () => void refresh();
    window.addEventListener("pman-refresh-data", update);
    return () => {
      mounted.current = false;
      window.clearInterval(timer);
      window.removeEventListener("pman-refresh-data", update);
    };
  }, [refresh]);
  const lock = useCallback(async () => {
    await call("management_lock");
    await onRefreshStatus();
  }, [onRefreshStatus]);
  const navigate = (next: Route) => {
    window.dispatchEvent(new Event("pman-hide-secrets"));
    setRoute(next);
  };
  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === ",") {
        event.preventDefault();
        window.dispatchEvent(new Event("pman-hide-secrets"));
        setRoute("settings");
      }
      if (
        (event.ctrlKey || event.metaKey) &&
        event.shiftKey &&
        event.key.toLowerCase() === "l"
      ) {
        event.preventDefault();
        void action.run(lock);
      }
    };
    window.addEventListener("keydown", keydown);
    return () => window.removeEventListener("keydown", keydown);
  }, [lock]);
  function authorize(site: string, harness?: string) {
    setFocusSite(null);
    setFocusHarness(harness || null);
    navigate("access");
    if (!harness) window.setTimeout(() => setFocusSite(site), 0);
  }
  const pendingCount = approvals.length + assistance.length;
  function assist(request: AssistanceRequest) {
    const site = sites.find((item) => item.alias === request.site);
    if (!site) {
      action.setError("请求对应的连接已不存在，请取消该请求。");
      setApprovalOpen(false);
      return;
    }
    setApprovalOpen(false);
    if (request.kind === "login") setAssistedLogin({ request, site });
    else setAssistedAccess(request);
  }
  async function handled(request: AssistanceRequest) {
    await action.run(async () => {
      await call("assistance_decide", { id: request.id, status: "handled" });
      await refresh();
    });
  }
  return (
    <div className="workbench bookshelf-workbench">
      <aside className="sidebar">
        <Brand />
        <nav aria-label="主导航">
          {navigation
            .filter((item) => item.id !== "settings")
            .map((item) => (
              <button
                key={item.id}
                className={`nav-item${route === item.id ? " selected" : ""}`}
                aria-current={route === item.id ? "page" : undefined}
                onClick={() => navigate(item.id)}
              >
                <Icon name={item.icon} />
                <span>{item.title}</span>
              </button>
            ))}
        </nav>
        <div className="sidebar-bottom">
          <button
            className="nav-item"
            onClick={() => void action.run(lock)}
            disabled={action.busy}
            title="锁定管理界面，保留 AI 服务状态"
          >
            <Icon name="lock" />
            <span>锁定</span>
          </button>
          <button
            className={`nav-item${route === "settings" ? " selected" : ""}`}
            aria-current={route === "settings" ? "page" : undefined}
            onClick={() => navigate("settings")}
          >
            <Icon name="settings" />
            <span>设置</span>
          </button>
          <button
            className="text-button hide-window"
            onClick={() => void action.run(() => call("window_hide"))}
          >
            隐藏到托盘
          </button>
        </div>
      </aside>
      <div className="main-column">
        <header className="topbar">
          <div className="breadcrumb">
            个人工作区 <Icon name="chevron" size={12} />
            <strong>
              {navigation.find((item) => item.id === route)?.title}
            </strong>
          </div>
          <div className="topbar-actions">
            <ServiceBadge status={status} />
            {status.service_paused && (
              <button className="text-button" onClick={onResume}>
                恢复
              </button>
            )}
            <span className="topbar-divider" />
            <button
              className={`approval-button${pendingCount ? " has-pending" : ""}`}
              onClick={() => setApprovalOpen(true)}
              aria-label={`${pendingCount} 个待审批请求`}
            >
              <Icon name="bell" size={18} />
              <span>待审批</span>
              <b>{pendingCount}</b>
            </button>
          </div>
        </header>
        <main
          className={`main-scroll${route === "credentials" ? " library-scroll" : ""}`}
        >
          <div className="global-notices">
            <Notice error={statusError || loadError || action.error} />
            {(statusError || loadError) && (
              <button
                className="button small"
                disabled={loading}
                onClick={() => void refresh()}
              >
                <Icon name="refresh" size={15} />
                重试刷新
              </button>
            )}
          </div>
          <div hidden={route !== "credentials"} className="library-route">
            <ConnectionLibrary
              sites={sites}
              harnesses={harnesses}
              clients={clients}
              entries={entries}
              loading={loading}
              onRefresh={refresh}
              onAuthorize={authorize}
              onClients={() => navigate("access")}
              onActivity={() => navigate("activity")}
            />
          </div>
          <div hidden={route !== "access"}>
            <Access
              clients={clients}
              harnesses={harnesses}
              sites={sites}
              audit={entries}
              onRefresh={refresh}
              focusSite={focusSite}
              focusHarness={focusHarness}
            />
          </div>
          <div hidden={route !== "activity"}>
            <Activity
              entries={entries}
              onRefresh={refresh}
              onAuthorize={(harness, site) => authorize(site, harness)}
            />
          </div>
          <div hidden={route !== "settings"}>
            <SettingsPanel
              settings={settings}
              status={status}
              onSettings={onSettings}
              onRefresh={async () => {
                await refresh();
                await onRefreshStatus();
              }}
              onResume={onResume}
            />
          </div>
        </main>
        <footer className="statusbar">
          <span>
            <Icon name="terminal" size={13} />
            {preview ? "合成数据预览" : "原生授权服务"}
          </span>
          <span>
            管理界面已解锁 <span className="shortcut">Ctrl Shift L 锁定</span>
          </span>
        </footer>
      </div>
      {approvalOpen && (
        <ApprovalDialog
          approvals={approvals}
          assistance={assistance}
          onAssist={assist}
          onClose={() => setApprovalOpen(false)}
          onRefresh={refresh}
        />
      )}
      {assistedLogin && (
        <LoginDialog
          site={assistedLogin.site}
          onClose={() => setAssistedLogin(null)}
          onSaved={() => handled(assistedLogin.request)}
        />
      )}
      {assistedAccess && (
        <GrantDialog
          harness={assistedAccess.harness}
          sites={sites}
          initialSite={assistedAccess.site}
          initialScope={assistedAccess.requested_scope}
          fixedSite
          onClose={() => setAssistedAccess(null)}
          onSaved={async () => {
            const request = assistedAccess;
            setAssistedAccess(null);
            await handled(request);
          }}
        />
      )}
    </div>
  );
}

function ApprovalDialog({
  approvals,
  assistance,
  onAssist,
  onClose,
  onRefresh,
}: {
  approvals: ApprovalSummary[];
  assistance: AssistanceRequest[];
  onAssist: (request: AssistanceRequest) => void;
  onClose: () => void;
  onRefresh: () => Promise<void>;
}) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const action = useAction();
  const [deciding, setDeciding] = useState<string | null>(null);
  async function decide(
    approval: ApprovalSummary,
    mode: "deny" | "once" | "persistent",
  ) {
    setDeciding(`${approval.id}:${mode}`);
    await action.run(
      async () => {
        await call("decide_approval", {
          id: approval.id,
          approve: mode !== "deny",
          persistent: mode === "persistent",
          decidedBy: "desktop",
        });
        await onRefresh();
      },
      mode === "persistent"
        ? "已永久同意此客户端访问当前连接、方法和路径，可随时在 AI 访问中撤销。"
        : mode === "once"
          ? "已批准本次请求，只能使用一次。"
          : "已拒绝本次请求。",
    );
    setDeciding(null);
  }
  return (
    <Modal
      title={`待审批请求${approvals.length + assistance.length ? ` · ${approvals.length + assistance.length}` : ""}`}
      subtitle="处理登录协助、权限申请和请求审批。可单次批准，也可保存为持续授权。"
      onClose={() => {
        if (!action.busy) onClose();
      }}
      wide
    >
      <Notice error={action.error} message={action.message} />
      {assistance.length > 0 && (
        <div className="approval-list assistance-list">
          {assistance.map((request) => (
            <article className="approval-card" key={request.id}>
              <header>
                <div>
                  <strong>{request.harness}</strong>
                  <span>
                    {request.kind === "login"
                      ? "请求协助登录"
                      : "申请持续或临时权限"}
                  </span>
                </div>
                <small>{timestamp(request.created_at)}</small>
              </header>
              <div className="grant-scope">
                <strong>{request.site}</strong>
                {request.requested_scope && (
                  <>
                    <span className="method">
                      {request.requested_scope.method}
                    </span>
                    <code>{request.requested_scope.path}</code>
                  </>
                )}
              </div>
              {request.reason && (
                <p className="small-text muted">{request.reason}</p>
              )}
              <footer>
                <span className="small-text muted">需要本人操作</span>
                <div className="button-row">
                  <button
                    className="button small"
                    disabled={action.busy}
                    onClick={() =>
                      void action.run(async () => {
                        await call("assistance_decide", {
                          id: request.id,
                          status: "cancelled",
                        });
                        await onRefresh();
                      })
                    }
                  >
                    取消请求
                  </button>
                  <button
                    className="button primary small"
                    disabled={action.busy}
                    onClick={() => onAssist(request)}
                  >
                    {request.kind === "login"
                      ? "打开登录向导"
                      : "检查并配置授权"}
                  </button>
                </div>
              </footer>
            </article>
          ))}
        </div>
      )}
      {approvals.length ? (
        <div className="approval-list">
          {approvals.map((approval) => (
            <article className="approval-card" key={approval.id}>
              <header>
                <div>
                  <strong>{approval.harness}</strong>
                  <span>请求使用 {approval.site}</span>
                </div>
                <small>{timestamp(approval.ts)}</small>
              </header>
              <div className="grant-scope">
                <span className="method">{approval.method}</span>
                <code>{approval.path}</code>
              </div>
              <button
                className="text-button"
                aria-expanded={expanded === approval.id}
                onClick={() =>
                  setExpanded(expanded === approval.id ? null : approval.id)
                }
              >
                {expanded === approval.id
                  ? "收起请求详情"
                  : "查看请求参数与内容"}
              </button>
              {expanded === approval.id && (
                <pre className="code-block approval-payload" tabIndex={0}>
                  {JSON.stringify(approval.payload, null, 2)}
                </pre>
              )}
              <footer>
                <span className="mono muted small-text">{approval.id}</span>
                <div className="button-row">
                  <button
                    className="button small"
                    disabled={action.busy}
                    onClick={() => void decide(approval, "deny")}
                  >
                    拒绝
                  </button>
                  <button
                    className="button small"
                    disabled={action.busy}
                    onClick={() => void decide(approval, "once")}
                  >
                    {deciding === `${approval.id}:once`
                      ? "处理中…"
                      : "仅批准本次"}
                  </button>
                  <button
                    className="button primary small"
                    disabled={action.busy}
                    onClick={() => void decide(approval, "persistent")}
                    title="持续允许此客户端访问当前连接、方法和路径，直至手动撤销"
                  >
                    {deciding === `${approval.id}:persistent`
                      ? "处理中…"
                      : "永久同意"}
                  </button>
                </div>
              </footer>
            </article>
          ))}
        </div>
      ) : (
        !assistance.length && (
          <Empty icon="check" title="所有请求已处理">
            有新的请求需要决定时，这里会显示提醒。
          </Empty>
        )
      )}
    </Modal>
  );
}
