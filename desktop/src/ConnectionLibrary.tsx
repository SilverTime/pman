import { useEffect, useRef, useState } from "react";
import { ConfigDialog, PairDialog } from "./Access";
import {
  CredentialDetail,
  EntryDialog,
  LoginDialog,
  MetadataDialog,
  OAuthPresetDialog,
} from "./Credentials";
import {
  AuditEntry,
  Client,
  ConnectionCheck,
  ConnectionStatus,
  HarnessSummary,
  OAuthStart,
  SiteInput,
  SiteSummary,
  call,
  errorCodeInfo,
  errorText,
  siteDetails,
  statusLabel,
  timestamp,
  typeLabel,
} from "./api";
import {
  accountLabel,
  clientActive,
  connectionAbility,
  connectionGrants,
  connectionHost,
  connectionProvider,
  dimensionSummary,
  dimensionTone,
  expired,
  needsAttention,
  statusDimensions,
  wholeConnection,
} from "./connections";
import { Badge, Empty, Icon, IconButton, Modal, Notice, useAction } from "./ui";

export function ServiceMark({ name, kind }: { name: string; kind?: string }) {
  const key = name.toLowerCase();
  const label = key.includes("github")
    ? "GH"
    : key.includes("gitlab")
      ? "GL"
      : key.includes("notion")
        ? "N"
        : key.includes("codex")
          ? "C"
          : key.includes("claude")
            ? "Cl"
            : key.includes("openai")
                ? "AI"
                : "";
  return (
    <span
      className={`service-mark${label ? ` mark-${label.toLowerCase().replace(/[^a-z0-9]/g, "claude")}` : ""}`}
      aria-hidden="true"
    >
      {label || <Icon name={kind === "password" || kind === "api_token" ? "key" : kind === "http_basic" ? "shield" : "globe"} size={22} />}
    </span>
  );
}

type Props = {
  sites: SiteSummary[];
  clients: Client[];
  harnesses: HarnessSummary[];
  entries: AuditEntry[];
  loading: boolean;
  onRefresh: () => Promise<void>;
  onAuthorize: (site: string, harness?: string) => void;
  onClients: () => void;
  onActivity: () => void;
};

export function ConnectionLibrary({
  sites,
  clients,
  harnesses,
  entries,
  loading,
  onRefresh,
  onAuthorize,
  onClients,
  onActivity,
}: Props) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [group, setGroup] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [granting, setGranting] = useState<SiteSummary | null>(null);
  const [editing, setEditing] = useState<SiteSummary | null>(null);
  const [loggingIn, setLoggingIn] = useState<SiteSummary | null>(null);
  const [managing, setManaging] = useState<SiteSummary | null>(null);
  const [authConfig, setAuthConfig] = useState<SiteSummary | null>(null);
  const [rotating, setRotating] = useState<SiteSummary | null>(null);
  const [deleting, setDeleting] = useState<SiteSummary | null>(null);
  const [oauthFlow, setOauthFlow] = useState<SiteSummary | null>(null);
  const [webSelected, setWebSelected] = useState<string[]>([]);
  const [tab, setTab] = useState("overview");
  const search = useRef<HTMLInputElement>(null);
  const content = useRef<HTMLElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const action = useAction();
  const current = sites.find((site) => site.alias === selected);
  useEffect(() => {
    content.current?.scrollTo(0, 0);
  }, [selected, creating, granting?.alias, tab]);
  const attention = sites.filter(needsAttention);
  const groups = Array.from(
    new Set(sites.map((site) => siteDetails(site).group).filter(Boolean)),
  ) as string[];
  const visible = sites.filter((site) => {
    const details = siteDetails(site);
    return (
      (filter !== "attention" || needsAttention(site)) &&
      (filter !== "favorites" || details.favorite) &&
      (!group || details.group === group) &&
      [
        site.name,
        site.alias,
        site.site_url,
        details.account,
        details.environment,
        ...site.tags,
      ]
        .join(" ")
        .toLowerCase()
        .includes(query.toLowerCase())
    );
  });
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (
        (event.ctrlKey || event.metaKey) &&
        event.key.toLowerCase() === "k" &&
        !search.current?.closest("[hidden]") &&
        !document.querySelector('[aria-modal="true"]')
      ) {
        event.preventDefault();
        search.current?.focus();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);
  useEffect(() => {
    heading.current?.focus();
  }, [selected]);
  function select(site?: SiteSummary) {
    window.dispatchEvent(new Event("pman-hide-secrets"));
    setSelected(site?.alias || null);
    setTab("overview");
    setGranting(null);
  }
  async function updateDetails(
    site: SiteSummary,
    patch: Record<string, unknown>,
  ) {
    await call("site_update_metadata", {
      alias: site.alias,
      siteUrl: site.site_url,
      name: site.name || null,
      purpose: site.purpose || null,
      tags: site.tags,
      details: { ...siteDetails(site), ...patch },
    });
    await onRefresh();
  }
  async function runCheck(site: SiteSummary) {
    await action.run(async () => {
      const result = await call<{
        outcome: { message: string; state: string; saved_only: boolean };
      }>("connection_check", { alias: site.alias });
      action.setMessage(result.outcome.message);
      await onRefresh();
    });
  }
  const recent = [...sites]
    .sort((a, b) => (b.last_used_at || "").localeCompare(a.last_used_at || ""))
    .slice(0, 3);
  const grants = current ? connectionGrants(current, harnesses) : [];
  const activeClients = clients.filter(clientActive);
  const isPersonal = current ? current.auth_type === "password" : false;
  const webEnabled = current
    ? Boolean(siteDetails(current).web_enabled)
    : false;
  const webDim = current?.dimensions?.web;
  const webOrigin = (() => {
    try {
      return current ? new URL(current.site_url).origin : "";
    } catch {
      return "";
    }
  })();
  const webGrantedClients = current
    ? harnesses
        .filter((harness) =>
          (harness.policy.web || []).some(
            (rule) => rule.site === current.alias,
          ),
        )
        .flatMap((harness) =>
          activeClients
            .filter((client) => client.harness === harness.name)
            .map((client) => client.id),
        )
    : [];

  return (
    <div className="connection-library">
      <aside className="library-rail" aria-label="连接书架">
        <header className="library-heading">
          <button
            className="library-home"
            onClick={() => select()}
            disabled={creating}
          >
            <h1>连接</h1>
            <span>{sites.length}</span>
          </button>
          <IconButton
            icon="refresh"
            label="刷新连接"
            onClick={() => void action.run(onRefresh)}
            disabled={action.busy || loading}
          />
        </header>
        <label className="search-field">
          <Icon name="search" />
          <input
            ref={search}
            aria-label="搜索服务或账号"
            placeholder="搜索服务或账号"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
          <kbd>Ctrl K</kbd>
        </label>
        <div className="library-filters" aria-label="连接筛选">
          {[
            ["all", "全部"],
            [
              "attention",
              `待处理${attention.length ? ` ${attention.length}` : ""}`,
            ],
            ["favorites", "收藏"],
          ].map(([id, label]) => (
            <button
              key={id}
              aria-pressed={filter === id}
              className={filter === id ? "active" : ""}
              onClick={() => setFilter(id)}
            >
              {label}
            </button>
          ))}
        </div>
        {groups.length > 0 && (
          <label className="library-group">
            <span className="sr-only">连接分组</span>
            <select
              value={group}
              onChange={(event) => setGroup(event.target.value)}
            >
              <option value="">全部分组</option>
              {groups.map((item) => (
                <option key={item}>{item}</option>
              ))}
            </select>
          </label>
        )}
        <div className="library-items">
          {loading && !sites.length ? (
            <p className="loading-state" role="status">
              正在读取连接…
            </p>
          ) : (
            visible.map((site) => {
              const status = statusLabel(site);
              return (
                <button
                  key={site.alias}
                  className={`library-item${selected === site.alias && !creating ? " selected" : ""}`}
                  aria-pressed={selected === site.alias && !creating}
                  disabled={creating}
                  onClick={() => select(site)}
                >
                  <ServiceMark
                    name={site.name || site.alias}
                    kind={site.auth_type}
                  />
                  <span className="library-item-name">
                    <strong>{site.name || site.alias}</strong>
                    <small>
                      {siteDetails(site).account ||
                        siteDetails(site).environment ||
                        typeLabel(site.auth_type)}
                    </small>
                  </span>
                  <Badge tone={status.tone}>{status.text}</Badge>
                </button>
              );
            })
          )}
          {!loading && !visible.length && (
            <Empty
              title={sites.length ? "没有匹配的连接" : "连接你的第一个服务"}
              icon="globe"
            >
              {sites.length
                ? "试试其他关键词或筛选条件。"
                : "从网站、API 或工作账号开始。"}
            </Empty>
          )}
        </div>
        <button
          className="button library-add"
          disabled={creating}
          onClick={() => {
            setCreating(true);
            setGranting(null);
          }}
        >
          <Icon name="plus" />
          添加连接
        </button>
      </aside>

      <section ref={content} className="library-content" aria-label="连接内容">
        <Notice error={action.error} message={action.message} />
        {creating ? (
          <ConnectionWizard
            sites={sites}
            clients={clients}
            harnesses={harnesses}
            onRefresh={onRefresh}
            onClose={() => setCreating(false)}
            onFinished={(alias) => {
              setCreating(false);
              setSelected(alias);
              setTab("overview");
            }}
          />
        ) : granting ? (
          <>
            <button
              className="text-button back-link"
              onClick={() => setGranting(null)}
            >
              ← 返回连接
            </button>
            <header className="connection-page-heading">
              <h1>授权 AI 使用 {granting.name || granting.alias}</h1>
              <p>选择信任的 AI，持续使用这个账号连接。</p>
            </header>
            <ConnectionConsent
              site={
                sites.find((site) => site.alias === granting.alias) || granting
              }
              clients={clients}
              harnesses={harnesses}
              onRefresh={onRefresh}
              onClose={() => setGranting(null)}
              onAdvanced={() => onAuthorize(granting.alias)}
            />
          </>
        ) : current ? (
          <>
            <button className="text-button back-link" onClick={() => select()}>
              ← 我的连接
            </button>
            <header className="connection-detail-heading">
              <ServiceMark
                name={current.name || current.alias}
                kind={current.auth_type}
              />
              <div>
                <div className="button-row">
                  <h1 ref={heading} tabIndex={-1}>
                    {current.name || current.alias}
                  </h1>
                  <Badge tone={statusLabel(current).tone}>
                    {statusLabel(current).text}
                  </Badge>
                </div>
                <p>{accountLabel(current)}</p>
                <small>{connectionHost(current)}</small>
              </div>
              <div className="heading-actions">
                <IconButton
                  icon="star"
                  label={
                    siteDetails(current).favorite ? "取消收藏" : "收藏连接"
                  }
                  active={siteDetails(current).favorite}
                  onClick={() =>
                    void action.run(() =>
                      updateDetails(current, {
                        favorite: !siteDetails(current).favorite,
                      }),
                    )
                  }
                  disabled={action.busy}
                />
                <button className="button" onClick={() => setEditing(current)}>
                  <Icon name="edit" size={15} />
                  编辑
                </button>
              </div>
            </header>
            <div className="connection-tabs" aria-label="连接内容分类">
              {[
                ["overview", "概览"],
                ["access", "AI 访问"],
                ["activity", "活动"],
              ].map(([id, label]) => (
                <button
                  key={id}
                  aria-pressed={tab === id}
                  className={tab === id ? "active" : ""}
                  onClick={() => setTab(id)}
                >
                  {label}
                </button>
              ))}
            </div>
            {tab === "overview" && (
              <div className="capability-grid">
                <section className="library-panel">
                  <header>
                    <h2>
                      {current.auth_type === "password"
                        ? "个人密码"
                        : "接口访问"}
                    </h2>
                    <Badge tone={connectionAbility(current).tone}>
                      {connectionAbility(current).text}
                    </Badge>
                  </header>
                  <dl className="connection-facts">
                    <div>
                      <dt>认证方式</dt>
                      <dd>{typeLabel(current.auth_type)}</dd>
                    </div>
                    <div>
                      <dt>账号</dt>
                      <dd>{siteDetails(current).account || "未填写"}</dd>
                    </div>
                    <div>
                      <dt>最近检查</dt>
                      <dd>{timestamp(current.last_checked_at)}</dd>
                    </div>
                  </dl>
                  <p className="panel-hint">
                    {connectionAbility(current).detail}
                  </p>
                  <div className="button-row">
                    {["login", "authflow", "e10"].includes(current.auth_type) ? (
                      <button
                        className="button small"
                        onClick={() => setLoggingIn(current)}
                      >
                        <Icon name="globe" size={15} />
                        {needsAttention(current) ? "重新登录" : "登录账号"}
                      </button>
                    ) : (
                      <button
                        className="button small"
                        onClick={() => setRotating(current)}
                      >
                        更新凭据
                      </button>
                    )}
                    {current.auth_type !== "password" && <>
                      <button className="button small" disabled={action.busy} onClick={() => void runCheck(current)}>检查连接</button>
                      <button className="button small" onClick={() => setAuthConfig(current)}>认证配置</button>
                      {siteDetails(current).extra?.has_refresh === true && <button className="button small" disabled={action.busy} onClick={() => void action.run(async () => { await call("authflow_refresh", { alias: current.alias }); action.setMessage("凭据已刷新"); await onRefresh(); })}>刷新凭据</button>}
                    </>}
                    {(current.auth_type === "e10"
                      ? connectionProvider(current) === "e10"
                      : !["login", "authflow", "e10", "cookie_jar", "password"].includes(
                          current.auth_type,
                        ) &&
                        connectionProvider(current) &&
                        siteDetails(current).oauth_client_id) && (
                      <button
                        className="button small"
                        disabled={action.busy}
                        onClick={() => setOauthFlow(current)}
                      >
                        <Icon name="globe" size={15} />
                        OAuth 登录
                      </button>
                    )}
                  </div>
                  {!["login", "authflow", "e10", "cookie_jar", "password"].includes(
                      current.auth_type,
                    ) &&
                    connectionProvider(current) &&
                    !siteDetails(current).oauth_client_id && (
                      <p className="panel-hint">
                        OAuth 免密登录（无需 client secret）可用：在“检查与
                        OAuth 设置”中保存应用 client_id
                        后，这里会出现登录入口。也可以继续使用 Token。
                      </p>
                    )}
                  {current.auth_type === "e10" &&
                    connectionProvider(current) === "e10" && (
                      <p className="panel-hint">
                        E10 浏览器授权（OAuth）可用；平台未回传 state
                        时会提示改用本页的独立登录窗口。
                      </p>
                    )}
                </section>
                <section className="library-panel">
                  <header>
                    <h2>网页操作</h2>
                    <Badge
                      tone={dimensionTone(webDim?.state || "not_available")}
                    >
                      {webDim?.label || "尚未开启"}
                    </Badge>
                  </header>
                  <div className="browser-capability">
                    <Icon name="globe" size={28} />
                    <h3>AI 网页操作（独立授权）</h3>
                    <p>{webDim?.detail || "AI 网页操作未开启。"}</p>
                    <p className="panel-hint">
                      网页能力与接口授权互相独立；密码与验证码始终由你在隔离窗口输入，AI
                      看不到。文件上传下载与支付/删除类操作不受支持。
                    </p>
                    {!isPersonal && !webEnabled && (
                      <button
                        className="button small"
                        disabled={action.busy}
                        onClick={() =>
                          void action.run(async () => {
                            await updateDetails(current, { web_enabled: true });
                            action.setMessage(
                              "网页操作已开启。请选择允许的 AI 客户端完成授权。",
                            );
                          })
                        }
                      >
                        开启网页操作
                      </button>
                    )}
                    {!isPersonal && webEnabled && (
                      <>
                        <div className="client-selection">
                          {activeClients.map((client) => (
                            <label
                              className={`client-choice${webSelected.includes(client.id) ? " selected" : ""}`}
                              key={client.id}
                            >
                              <ServiceMark name={client.name} />
                              <span>
                                <strong>{client.name}</strong>
                                <small>
                                  {webGrantedClients.includes(client.id)
                                    ? "已有网页授权 · 可重复保存"
                                    : "已配对本机"}
                                </small>
                              </span>
                              <input
                                type="checkbox"
                                checked={webSelected.includes(client.id)}
                                disabled={action.busy}
                                onChange={(event) =>
                                  setWebSelected((ids) =>
                                    event.target.checked
                                      ? [...ids, client.id]
                                      : ids.filter((id) => id !== client.id),
                                  )
                                }
                              />
                            </label>
                          ))}
                        </div>
                        <div className="button-row">
                          <button
                            className="button small"
                            disabled={action.busy || !webSelected.length}
                            onClick={() =>
                              void action.run(async () => {
                                await call("grant_web_clients", {
                                  site: current.alias,
                                  clientIds: webSelected,
                                  origins: [webOrigin],
                                });
                                action.setMessage(
                                  "网页授权已保存。AI 客户端可通过 browser_* 动作操作该连接的页面。",
                                );
                                await onRefresh();
                              })
                            }
                          >
                            授权网页操作
                          </button>
                          <button
                            className="button small"
                            disabled={action.busy}
                            onClick={() =>
                              void action.run(async () => {
                                const result = await call<{ closed: number }>(
                                  "web_sessions_stop",
                                  { alias: current.alias },
                                );
                                action.setMessage(
                                  `已停止 ${result.closed} 个网页会话。`,
                                );
                              })
                            }
                          >
                            停止网页会话
                          </button>
                          <button
                            className="text-button danger-text"
                            disabled={action.busy}
                            onClick={() =>
                              void action.run(async () => {
                                await call("web_enable", {
                                  alias: current.alias,
                                  enabled: false,
                                });
                                setWebSelected([]);
                                await onRefresh();
                              })
                            }
                          >
                            关闭网页操作
                          </button>
                        </div>
                      </>
                    )}
                  </div>
                </section>
              </div>
            )}
            {tab !== "activity" && (
              <section className="library-panel access-summary">
                <header>
                  <div>
                    <h2>允许使用此连接的 AI</h2>
                    <p>每项授权都可以单独管理和撤销。</p>
                  </div>
                  <button
                    className="button"
                    disabled={current.auth_type === "password"}
                    onClick={() => setGranting(current)}
                  >
                    <Icon name="plus" />
                    授权 AI
                  </button>
                </header>
                {siteDetails(current).ai_enabled === false &&
                  grants.length > 0 && (
                    <div className="inline-warning">
                      此连接已暂停 AI 使用，以下授权当前不生效。
                    </div>
                  )}
                {grants.length ? (
                  grants.map((harness) => {
                    const client = activeClients.find(
                      (item) => item.harness === harness.name,
                    );
                    const full = harness.policy.allow?.some(
                      (rule) =>
                        rule.site === current.alias && wholeConnection(rule),
                    );
                    const limited = harness.policy.deny?.some(
                      (rule) =>
                        rule.site === current.alias &&
                        !expired(rule.expires_at),
                    );
                    return (
                      <div className="authorized-client" key={harness.name}>
                        <ServiceMark name={client?.name || harness.name} />
                        <div>
                          <strong>{client?.name || harness.name}</strong>
                          <small>
                            {full ? "整个连接" : "自定义范围"}
                            {limited ? " · 含拒绝规则" : ""} · 接口调用
                          </small>
                        </div>
                        <Badge
                          tone={
                            siteDetails(current).ai_enabled === false
                              ? "neutral"
                              : "success"
                          }
                        >
                          {siteDetails(current).ai_enabled === false
                            ? "已暂停"
                            : client ||
                                !clients.some(
                                  (item) => item.harness === harness.name,
                                )
                              ? "已授权"
                              : "客户端已失效"}
                        </Badge>
                        <button
                          className="text-button"
                          onClick={() =>
                            onAuthorize(current.alias, harness.name)
                          }
                        >
                          管理
                          <Icon name="chevron" size={14} />
                        </button>
                      </div>
                    );
                  })
                ) : (
                  <Empty title="还没有 AI 可以使用此连接" icon="shield">
                    {current.auth_type === "password"
                      ? "普通密码仅供本人使用。接入 AI 请添加 API 或网站连接。"
                      : "选择信任的 AI，确认后即可持续使用。"}
                  </Empty>
                )}
                <div className="privacy-note">
                  <Icon name="shield" size={17} />
                  AI 通过 pman 使用账号，不会获得密码或令牌。
                </div>
              </section>
            )}
            {tab === "overview" && (
              <StatusPanel
                key={current.alias}
                site={current}
                dimensions={current.dimensions}
                busy={action.busy}
                onCheck={() => runCheck(current)}
                onUpdateDetails={(patch) => updateDetails(current, patch)}
              />
            )}
            {tab !== "access" && (
              <section className="library-panel">
                <header>
                  <h2>最近活动</h2>
                  <button className="text-button" onClick={onActivity}>
                    查看全部
                    <Icon name="arrow" size={14} />
                  </button>
                </header>
                <RecentActivity
                  entries={entries.filter(
                    (entry) => entry.site === current.alias,
                  )}
                  sites={sites}
                />
              </section>
            )}
            <footer className="connection-footer">
              <button
                className="text-button"
                onClick={() => setManaging(current)}
              >
                <Icon name="key" size={14} />
                凭据与高级管理
              </button>
              <span>更新于 {timestamp(current.updated_at)}</span>
              <button
                className="text-button danger-text"
                onClick={() => setDeleting(current)}
              >
                删除连接
              </button>
            </footer>
          </>
        ) : (
          <>
            <span className="library-breadcrumb">我的连接</span>
            <header className="connection-page-heading">
              <h1 ref={heading} tabIndex={-1}>
                {sites.length ? "连接你的服务，继续工作" : "从第一个连接开始"}
              </h1>
              <p>账号留在本机，AI 通过授权使用服务。</p>
            </header>
            {attention.length > 0 && (
              <div className="attention-banner">
                <Icon name="bell" size={21} />
                <div>
                  <strong>
                    {attention[0].name || attention[0].alias} ·{" "}
                    {statusLabel(attention[0]).text}
                  </strong>
                  <p>
                    {attention.length > 1
                      ? `共 ${attention.length} 个连接需要处理。`
                      : "其他连接的现有授权不受影响。"}
                  </p>
                </div>
                <button
                  className="text-button"
                  onClick={() => select(attention[0])}
                >
                  查看并处理
                  <Icon name="arrow" size={16} />
                </button>
              </div>
            )}
            <section className="recent-connections">
              <div className="section-label">
                <h2>最近使用</h2>
                <span>{sites.length} 个连接</span>
              </div>
              {recent.length ? (
                <div className="recent-table">
                  <div className="recent-table-header">
                    <span>服务与账号</span>
                    <span>账号状态</span>
                    <span>AI 授权</span>
                    <span />
                  </div>
                  {recent.map((site) => (
                    <button
                      className="recent-connection"
                      key={site.alias}
                      onClick={() => select(site)}
                    >
                      <span className="service-cell">
                        <ServiceMark
                          name={site.name || site.alias}
                          kind={site.auth_type}
                        />
                        <span>
                          <strong>{site.name || site.alias}</strong>
                          <small>{accountLabel(site)}</small>
                        </span>
                      </span>
                      <span>
                        <Badge tone={connectionAbility(site).tone}>
                          {connectionAbility(site).text}
                        </Badge>
                      </span>
                      <span className="client-chips">
                        {siteDetails(site).ai_enabled === false ? (
                          <small>仅本人使用</small>
                        ) : connectionGrants(site, harnesses).length ? (
                          connectionGrants(site, harnesses)
                            .slice(0, 2)
                            .map((h) => (
                              <span key={h.name}>
                                {activeClients.find((c) => c.harness === h.name)
                                  ?.name || h.name}
                              </span>
                            ))
                        ) : (
                          <small>未授权 AI</small>
                        )}
                      </span>
                      <Icon name="chevron" size={15} />
                    </button>
                  ))}
                </div>
              ) : (
                <Empty
                  icon="globe"
                  title="把常用服务连接到 pman"
                  action={
                    <button
                      className="button primary"
                      onClick={() => setCreating(true)}
                    >
                      <Icon name="plus" />
                      添加第一个连接
                    </button>
                  }
                >
                  保存账号，完成登录，再选择允许使用它的 AI。
                </Empty>
              )}
            </section>
            <div className="home-bottom-grid">
              <section className="library-panel">
                <header>
                  <h2>已接入的 AI</h2>
                  <button className="text-button" onClick={onClients}>
                    管理
                    <Icon name="arrow" size={14} />
                  </button>
                </header>
                {activeClients.length ? (
                  activeClients.map((client) => (
                    <button
                      className="home-client"
                      key={client.id}
                      onClick={onClients}
                    >
                      <ServiceMark name={client.name} />
                      <span>
                        <strong>{client.name}</strong>
                        <small>
                          {client.last_used_at
                            ? `最近使用 ${timestamp(client.last_used_at)}`
                            : "等待首次调用"}
                        </small>
                      </span>
                      <Badge tone="success">已配对</Badge>
                    </button>
                  ))
                ) : (
                  <Empty
                    icon="terminal"
                    title="接入你的 AI"
                    action={
                      <button className="text-button" onClick={onClients}>
                        接入 AI 工具 →
                      </button>
                    }
                  >
                    支持 Codex、Claude Code 与通用 MCP 客户端。
                  </Empty>
                )}
              </section>
              <section className="library-panel">
                <header>
                  <h2>最近活动</h2>
                  <button className="text-button" onClick={onActivity}>
                    查看全部
                    <Icon name="arrow" size={14} />
                  </button>
                </header>
                <RecentActivity entries={entries} sites={sites} />
              </section>
            </div>
          </>
        )}
      </section>
      {editing && (
        <MetadataDialog
          site={editing}
          onClose={() => setEditing(null)}
          onSaved={async () => {
            setEditing(null);
            await onRefresh();
          }}
        />
      )}
      {loggingIn && (
        <LoginDialog
          site={loggingIn}
          onClose={() => setLoggingIn(null)}
          onSaved={onRefresh}
        />
      )}
      {authConfig && <AuthenticationConfigDialog site={authConfig} onClose={() => setAuthConfig(null)} onSaved={async () => { setAuthConfig(null); await onRefresh(); }} />}
      {rotating && (
        <EntryDialog
          site={rotating}
          onClose={() => setRotating(null)}
          onSaved={async () => {
            setRotating(null);
            await onRefresh();
          }}
        />
      )}
      {oauthFlow && (
        <OAuthDialog
          site={oauthFlow}
          onClose={() => setOauthFlow(null)}
          onRefresh={onRefresh}
        />
      )}
      {managing && (
        <Modal title="凭据与高级管理" onClose={() => setManaging(null)}>
          <CredentialDetail
            site={
              sites.find((site) => site.alias === managing.alias) || managing
            }
            grants={connectionGrants(managing, harnesses).length}
            onEdit={() => {
              setEditing(managing);
              setManaging(null);
            }}
            onRotate={() => {
              setRotating(managing);
              setManaging(null);
            }}
            onDelete={() => {
              setDeleting(managing);
              setManaging(null);
            }}
            onLogin={() => {
              setLoggingIn(managing);
              setManaging(null);
            }}
            onRefresh={onRefresh}
            onAuthorize={() => {
              setGranting(managing);
              setManaging(null);
            }}
            onEnable={(enabled) =>
              updateDetails(managing, { ai_enabled: enabled })
            }
          />
        </Modal>
      )}
      {deleting && (
        <Modal
          title={`删除 ${deleting.name || deleting.alias}？`}
          onClose={() => {
            if (!action.busy) setDeleting(null);
          }}
        >
          <p>
            删除后立即生效：该连接保存的凭据被移除；所有 AI
            客户端对此连接的授权规则被撤销；正在进行的网页会话被关闭；AI
            后续调用会被拒绝。历史活动记录保留。
          </p>
          <Notice error={action.error} />
          <div className="modal-actions">
            <button
              className="button"
              disabled={action.busy}
              onClick={() => setDeleting(null)}
            >
              取消
            </button>
            <button
              className="button danger"
              disabled={action.busy}
              onClick={() =>
                void action.run(async () => {
                  await call("site_remove", { alias: deleting.alias });
                  setDeleting(null);
                  select();
                  await onRefresh();
                })
              }
            >
              删除连接
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}

/**
 * Five-dimension status detail. Rendered from backend-computed dimensions;
 * a missing dimension always shows 尚未检查 instead of assumed health.
 * The check action runs the native read-only check, never a webview request.
 */
export function StatusPanel({
  site,
  dimensions,
  busy,
  onUpdateDetails,
}: {
  site: SiteSummary;
  dimensions?: ConnectionStatus;
  busy: boolean;
  onCheck: () => Promise<void>;
  onUpdateDetails: (patch: Record<string, unknown>) => Promise<void>;
}) {
  const details = siteDetails(site);
  const canCheck = site.auth_type !== "password";
  const [provider, setProvider] = useState(details.provider || "auto");
  const [checkPath, setCheckPath] = useState(details.check_path || "");
  const [oauthClientId, setOauthClientId] = useState(
    details.oauth_client_id || "",
  );
  const [oauthScope, setOauthScope] = useState(details.oauth_scope || "");
  const [oauthTenant, setOauthTenant] = useState(details.oauth_tenant || "");
  return (
    <section className="library-panel status-panel" aria-label="状态明细">
      <details className="status-disclosure">
        <summary>
          <span>
            <strong>查看状态证据</strong>
            <small>保存、验证、授权与真实调用分别记录</small>
          </span>
          <Icon name="chevron" size={15} />
        </summary>
        <div className="status-rows">
          {statusDimensions.map(({ key, name }) => {
            const info = dimensionSummary(dimensions?.[key]);
            return (
              <div className="status-row" key={key}>
                <span className="status-name">{name}</span>
                <Badge tone={info.tone}>{info.label}</Badge>
                <div className="status-text">
                  <p>{info.detail}</p>
                  <small>
                    {info.checked_at
                      ? `检查于 ${timestamp(info.checked_at)}`
                      : "尚未检查"}
                    {info.error_code
                      ? ` · ${errorCodeInfo(info.error_code).text}`
                      : ""}
                  </small>
                </div>
                {info.recovery && (
                  <span className="status-recovery">{info.recovery}</span>
                )}
              </div>
            );
          })}
        </div>
        {canCheck && (
          <details className="check-settings">
            <summary>检查与 OAuth 设置</summary>
            <div className="check-settings-grid">
              <label>
                检查方式
                <select
                  value={provider}
                  onChange={(event) => setProvider(event.target.value)}
                >
                  <option value="auto">自动识别（按服务地址）</option>
                  <option value="github">GitHub 身份接口</option>
                  <option value="gitlab">GitLab 身份接口</option>
                  <option value="gitee">Gitee 身份接口（令牌）</option>
                  <option value="microsoft">Microsoft 身份接口</option>
                  <option value="google">Google 身份接口</option>
                  <option value="custom">自定义只读路径</option>
                </select>
              </label>
              <label>
                只读检查路径
                <input
                  value={checkPath}
                  placeholder="/health"
                  spellCheck={false}
                  onChange={(event) => setCheckPath(event.target.value)}
                />
              </label>
              <label>
                OAuth 应用 client_id
                <input
                  value={oauthClientId}
                  placeholder="在提供方注册的公开应用 ID（E10 无需填写）"
                  spellCheck={false}
                  onChange={(event) => setOauthClientId(event.target.value)}
                />
              </label>
              <label>
                OAuth scope
                <input
                  value={oauthScope}
                  placeholder="留空使用最小只读范围"
                  spellCheck={false}
                  onChange={(event) => setOauthScope(event.target.value)}
                />
              </label>
              {provider === "microsoft" && (
                <label>
                  Microsoft tenant
                  <input
                    value={oauthTenant}
                    placeholder="organizations（默认）/ consumers / common / 租户 ID"
                    spellCheck={false}
                    onChange={(event) => setOauthTenant(event.target.value)}
                  />
                </label>
              )}
            </div>
            <p className="panel-hint">
              OAuth 只支持无需 client secret 的官方流程（GitLab /
              Microsoft / Google 授权码 + PKCE、GitHub 设备码、E10
              平台授权）；令牌与会话只保存在本机保险库。
            </p>
            <button
              className="button small"
              disabled={busy}
              onClick={() =>
                void onUpdateDetails({
                  provider: provider === "auto" ? null : provider,
                  check_path: checkPath.trim() || null,
                  oauth_client_id: oauthClientId.trim() || null,
                  oauth_scope: oauthScope.trim() || null,
                  oauth_tenant: oauthTenant.trim() || null,
                })
              }
            >
              保存设置
            </button>
          </details>
        )}
      </details>
    </section>
  );
}

/**
 * OAuth login lifecycle: begin -> (browser or device code) -> complete.
 * The dialog only sees the session id, user code and redacted account;
 * token exchange happens entirely on the native side.
 */
export function OAuthDialog({
  site,
  onClose,
  onRefresh,
  onSucceeded,
  onFallbackLogin,
}: {
  site: SiteSummary;
  onClose: () => void;
  onRefresh: () => Promise<void>;
  onSucceeded?: () => void;
  /** Offer the isolated browser login window when the provider cannot echo
   * the OAuth state (E10 contract). */
  onFallbackLogin?: () => void;
}) {
  const [info, setInfo] = useState<OAuthStart | null>(null);
  const [stage, setStage] = useState<
    "starting" | "waiting" | "done" | "error" | "fallback"
  >("starting");
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const start = await call<OAuthStart>("oauth_begin", {
          alias: site.alias,
        });
        if (cancelled) {
          void call("oauth_cancel", { sessionId: start.session_id }).catch(
            () => undefined,
          );
          return;
        }
        setInfo(start);
        setStage("waiting");
        const result = await call<{ status?: string }>("oauth_complete", {
          sessionId: start.session_id,
          alias: site.alias,
        });
        if (cancelled) return;
        // The platform did not echo the OAuth state: nothing was exchanged.
        // The isolated browser login window is the supported fallback.
        if (result?.status === "state_not_returned") {
          setStage("fallback");
          return;
        }
        setStage("done");
        await onRefresh();
        onSucceeded?.();
      } catch (err) {
        if (!cancelled) {
          setError(errorText(err));
          setStage("error");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [site.alias]);
  async function cancelLogin() {
    if (info) {
      await call("oauth_cancel", { sessionId: info.session_id }).catch(
        () => undefined,
      );
    }
    onClose();
  }
  return (
    <Modal
      title={`使用 OAuth 登录 ${site.name || site.alias}`}
      onClose={stage === "waiting" ? () => void cancelLogin() : onClose}
    >
      {stage === "starting" && (
        <div className="loading-state" role="status">
          正在启动授权流程…
        </div>
      )}
      {stage === "waiting" && info && (
        <div className="stack-form">
          {info.kind === "device" && info.user_code && (
            <div className="info-box">
              <Icon name="terminal" />
              <p>
                在打开的页面中输入设备码 <code>{info.user_code}</code>
              </p>
            </div>
          )}
          <p className="muted small-text">
            浏览器窗口已打开。完成授权后这里会自动更新；请不要在任何页面输入
            pman 主密码。
          </p>
          <div className="loading-state" role="status">
            等待提供方确认授权…
          </div>
        </div>
      )}
      {stage === "done" && (
        <div className="consent-result" role="status">
          <div className="result-heading">
            <Icon name="check" size={24} />
            <div>
              <h2>登录成功</h2>
              <p>账号已接入并验证。返回后仍需选择 AI 并完成授权。</p>
            </div>
          </div>
        </div>
      )}
      {stage === "fallback" && (
        <div className="stack-form">
          <div className="info-box">
            <Icon name="globe" />
            <p>
              平台未回传 OAuth state，本次授权已终止且未交换任何凭据。
              {onFallbackLogin
                ? "可改用独立浏览器窗口完成登录。"
                : "请关闭后使用本页的“登录账号 / 重新登录”按钮，改用独立浏览器窗口完成登录。"}
            </p>
          </div>
        </div>
      )}
      {stage === "error" && (
        <div className="stack-form">
          <Notice error={error} />
          <p className="muted small-text">
            OAuth 未配置或被拒绝时，请使用 Token
            接入；失败的登录不会改动已保存的凭据或授权。
          </p>
        </div>
      )}
      <div className="modal-actions">
        {stage === "waiting" ? (
          <button className="button" onClick={() => void cancelLogin()}>
            取消登录
          </button>
        ) : stage === "fallback" && onFallbackLogin ? (
          <button className="button primary" onClick={onFallbackLogin}>
            改用浏览器窗口登录
          </button>
        ) : (
          <button className="button primary" onClick={onClose}>
            {stage === "done" ? "完成" : "关闭"}
          </button>
        )}
      </div>
    </Modal>
  );
}

function RecentActivity({
  entries,
  sites,
}: {
  entries: AuditEntry[];
  sites: SiteSummary[];
}) {
  if (!entries.length)
    return (
      <div className="quiet-empty">
        <Icon name="activity" size={22} />
        <p>暂无调用记录</p>
        <small>AI 使用连接后，结果会显示在这里。</small>
      </div>
    );
  return (
    <div className="recent-activity">
      {[...entries]
        .sort((a, b) => b.ts.localeCompare(a.ts))
        .slice(0, 3)
        .map((entry) => (
          <div className="recent-event" key={entry.id}>
            <span
              className={
                entry.status_code && entry.status_code < 400
                  ? "event-dot success"
                  : "event-dot warning"
              }
            />
            <div>
              <strong>
                {entry.harness} 使用了{" "}
                {sites.find((site) => site.alias === entry.site)?.name ||
                  entry.site ||
                  "本机服务"}
              </strong>
              <small>
                {entry.note === "pending_approval"
                  ? "等待批准"
                  : entry.status_code
                    ? `响应 ${entry.status_code}`
                    : "请求已记录"}
              </small>
            </div>
            <time>{timestamp(entry.ts)}</time>
          </div>
        ))}
    </div>
  );
}

type WizardTemplate = {
  id: string;
  title: string;
  hint: string;
  type: SiteInput["auth_type"];
  url: string;
  /** OAuth preset providers collect a client id instead of a token. */
  oauth?: "microsoft" | "google";
};

/** Preset providers get their own group; clicking one starts the provider's
 * real flow (OAuth by default, token only where the provider demands it). */
const presetTemplates: WizardTemplate[] = [
  { id: "e10", title: "E10 快捷授权", hint: "浏览器 OAuth 授权，未回传 state 时改用独立窗口", type: "e10", url: "https://www.e-cology.com.cn" },
  { id: "microsoft", title: "Microsoft (Entra ID)", hint: "OAuth 授权码 + PKCE，无需 client secret", type: "api_token", url: "https://graph.microsoft.com", oauth: "microsoft" },
  { id: "google", title: "Google 账号", hint: "OAuth 授权码 + PKCE，无需 client secret", type: "api_token", url: "https://www.googleapis.com", oauth: "google" },
  { id: "gitee", title: "Gitee 访问令牌", hint: "私人令牌接入并验证账号身份", type: "api_token", url: "https://gitee.com" },
];

const genericTemplates: WizardTemplate[] = [
  { id: "website", title: "浏览器登录", hint: "在独立窗口登录并保存会话", type: "login", url: "" },
  { id: "api", title: "访问密钥", hint: "API Key、Bearer Token 或自定义请求头", type: "api_token", url: "" },
  { id: "basic", title: "账号密码", hint: "使用 HTTP Basic 连接服务", type: "http_basic", url: "" },
  { id: "authorization", title: "授权登录", hint: "授权回调、令牌交换与会话续期", type: "authflow", url: "" },
];

function ConnectionWizard({
  sites,
  clients,
  harnesses,
  onRefresh,
  onClose,
  onFinished,
}: Pick<Props, "sites" | "clients" | "harnesses" | "onRefresh"> & {
  onClose: () => void;
  onFinished: (alias: string) => void;
}) {
  const [template, setTemplate] = useState<WizardTemplate | null>(null);
  const [saved, setSaved] = useState<SiteSummary | null>(null);
  const [loginOpen, setLoginOpen] = useState(false);
  const [loginComplete, setLoginComplete] = useState(false);
  const [oauthOpen, setOauthOpen] = useState(false);
  const [oauthDone, setOauthDone] = useState(false);
  const wizard = useRef<HTMLDivElement>(null);
  useEffect(() => {
    wizard.current?.closest(".library-content")?.scrollTo(0, 0);
  }, [template?.id, saved?.alias, loginComplete]);
  const title = template?.type === "password" ? "保存个人密码" : "添加连接";
  function uniqueAlias(base: string) {
    let alias = base;
    let suffix = 2;
    while (sites.some((site) => site.alias === alias))
      alias = `${base}-${suffix++}`;
    return alias;
  }
  const liveSite = saved
    ? sites.find((site) => site.alias === saved.alias) || saved
    : null;
  // Preset OAuth connections carry extra.oauth_pending until the native
  // exchange finishes, so they stay in the login step instead of consent.
  const oauthPending = !!liveSite && siteDetails(liveSite).extra?.oauth_pending === true;
  const needsLogin =
    !!saved &&
    (["login", "authflow", "e10"].includes(saved.auth_type) || oauthPending);
  const step = !template
    ? 0
    : !saved || (needsLogin && !loginComplete)
      ? 1
      : 2;
  const resumeUsesOAuth =
    !!liveSite && (liveSite.auth_type === "e10" || oauthPending);
  return (
    <div ref={wizard} className="connection-wizard">
      <div className="wizard-top">
        <button className="text-button" onClick={onClose}>
          ← 返回连接
        </button>
        <button className="text-button" onClick={onClose}>
          {saved ? "稍后继续" : "取消"}
        </button>
      </div>
      <header className="connection-page-heading">
        <h1>{title}</h1>
        <p>完成账号连接，再选择可以使用它的 AI。</p>
      </header>
      {template?.type !== "password" && <ol className="connection-steps">
        {["连接方式", "连接账号", "授权 AI"].map((text, index) => (
          <li
            key={text}
            className={
              index === step ? "current" : index < step ? "complete" : ""
            }
            aria-current={index === step ? "step" : undefined}
          >
            <span>
              {index < step ? <Icon name="check" size={14} /> : index + 1}
            </span>
            {text}
          </li>
        ))}
      </ol>}
      {!template ? (
        <>
          <h2 className="wizard-section-title">预置提供商</h2>
          <div className="service-templates">
            {presetTemplates.map((item) => (
              <button
                className="service-template"
                key={item.id}
                onClick={() => {
                  setTemplate(item);
                }}
              >
                <ServiceMark name={item.title} kind={item.type} />
                <span>
                  <strong>{item.title}</strong>
                  <small>{item.hint}</small>
                </span>
                <Icon name="chevron" size={16} />
              </button>
            ))}
          </div>
          <h2 className="wizard-section-title">通用方式</h2>
          <div className="service-templates">
            {genericTemplates.map((item) => (
              <button
                className="service-template"
                key={item.id}
                onClick={() => {
                  setTemplate(item);
                }}
              >
                <ServiceMark name={item.title} kind={item.type} />
                <span>
                  <strong>{item.title}</strong>
                  <small>{item.hint}</small>
                </span>
                <Icon name="chevron" size={16} />
              </button>
            ))}
          </div>
          <button className="text-button" onClick={() => setTemplate({ id: "password", title: "个人密码", hint: "仅保管", type: "password", url: "" })}>只需保管密码？保存个人密码</button>
          <p className="panel-hint">
            账号信息保存在本机。选择 AI 并确认授权前，连接仅供你本人使用。
          </p>
        </>
      ) : !saved ? (
        <>
          {template.oauth ? (
            <OAuthPresetDialog
              key={template.id}
              provider={template.oauth}
              initial={{
                alias: uniqueAlias(template.id),
                site_url: template.url,
              }}
              onClose={() => setTemplate(null)}
              onSaved={async (input) => {
                // Never retain user-entered secrets in the flow's metadata state.
                const { secret: _secret, ...metadata } = input;
                const summary: SiteSummary = {
                  ...metadata,
                  id: input.alias,
                  status: "pending",
                  created_at: "",
                  updated_at: "",
                };
                setSaved(summary);
                await onRefresh();
                setOauthDone(false);
                setOauthOpen(true);
              }}
            />
          ) : (
            <EntryDialog
              key={template.id}
              embedded
              initial={{
                name: "",
                alias: uniqueAlias(template.id),
                site_url: template.url,
                auth_type: template.type,
              }}
              onClose={() => setTemplate(null)}
              onSaved={async (input) => {
                // Never retain user-entered secrets in the flow's metadata state.
                const { secret: _secret, ...metadata } = input;
                const summary: SiteSummary = {
                  ...metadata,
                  id: input.alias,
                  status: ["login", "authflow", "e10"].includes(input.auth_type)
                    ? "pending"
                    : "active",
                  created_at: "",
                  updated_at: "",
                };
                setSaved(summary);
                await onRefresh();
                // E10 defaults to the OAuth authorization; the isolated
                // browser window stays available as the fallback.
                if (input.auth_type === "e10") {
                  setOauthDone(false);
                  setOauthOpen(true);
                } else if (["login", "authflow"].includes(input.auth_type)) {
                  setLoginOpen(true);
                }
                if (input.auth_type === "password") onFinished(input.alias);
              }}
            />
          )}
        </>
      ) : needsLogin && !loginComplete ? (
        <section className="library-panel login-resume">
          <ServiceMark name={saved.name || saved.alias} />
          <h2>继续完成账号登录</h2>
          <p>连接已保存。完成登录后，再选择允许使用它的 AI。</p>
          {resumeUsesOAuth ? (
            <>
              <button
                className="button primary"
                onClick={() => {
                  setOauthDone(false);
                  setOauthOpen(true);
                }}
              >
                <Icon name="globe" />
                开始 OAuth 授权
              </button>
              {liveSite?.auth_type === "e10" && (
                <button className="text-button" onClick={() => setLoginOpen(true)}>
                  改用浏览器窗口登录
                </button>
              )}
            </>
          ) : (
            <button
              className="button primary"
              onClick={() => setLoginOpen(true)}
            >
              <Icon name="globe" />
              打开登录窗口
            </button>
          )}
          <button
            className="text-button"
            onClick={() => onFinished(saved.alias)}
          >
            稍后登录，查看连接
          </button>
        </section>
      ) : (
        liveSite && (
          <ConnectionConsent
            site={liveSite}
            clients={clients}
            harnesses={harnesses}
            onRefresh={onRefresh}
            onClose={() => onFinished(saved.alias)}
          />
        )
      )}
      {loginOpen && liveSite && (
        <LoginDialog
          site={liveSite}
          onClose={() => setLoginOpen(false)}
          onSaved={async () => {
            await onRefresh();
            setLoginComplete(true);
            setLoginOpen(false);
          }}
        />
      )}
      {oauthOpen && liveSite && (
        <OAuthDialog
          site={liveSite}
          onClose={() => {
            setOauthOpen(false);
            if (oauthDone) setLoginComplete(true);
          }}
          onRefresh={onRefresh}
          onSucceeded={() => setOauthDone(true)}
          onFallbackLogin={
            liveSite.auth_type === "e10"
              ? () => {
                  setOauthOpen(false);
                  setLoginOpen(true);
                }
              : undefined
          }
        />
      )}

    </div>
  );
}

function ConnectionConsent({
  site,
  clients,
  harnesses,
  onRefresh,
  onClose,
  onAdvanced,
}: Pick<Props, "clients" | "harnesses" | "onRefresh"> & {
  site: SiteSummary;
  onClose: () => void;
  onAdvanced?: () => void;
}) {
  const [selected, setSelected] = useState<string[]>([]);
  const [pairing, setPairing] = useState(false);
  const [configuring, setConfiguring] = useState<Client | null>(null);
  const [saved, setSaved] = useState(false);
  const [checks, setChecks] = useState<
    { id: string; ok: boolean; message: string }[]
  >([]);
  const action = useAction();
  const eligible = clients.filter(clientActive);
  const granted = connectionGrants(site, harnesses);
  const blocked = selected.some(
    (id) => !eligible.some((client) => client.id === id),
  );
  const captured = useRef({
    alias: site.alias,
    url: site.site_url,
    account: siteDetails(site).account,
    tenant: siteDetails(site).tenant,
  });
  const changed =
    captured.current.alias !== site.alias ||
    captured.current.url !== site.site_url ||
    captured.current.account !== siteDetails(site).account ||
    captured.current.tenant !== siteDetails(site).tenant;
  async function checkClients(ids: string[]) {
    const result = await Promise.all(
      ids.map(async (id) => {
        try {
          return {
            id,
            ...(await call<{ ok: boolean; message: string }>("client_test", {
              id,
            })),
          };
        } catch (error) {
          return { id, ok: false, message: errorText(error) };
        }
      }),
    );
    setChecks(result);
  }
  async function submit() {
    await action.run(async () => {
      if (!selected.length || blocked || changed)
        throw new Error("连接或客户端状态已变化，请返回并重新确认授权。");
      try {
        await call("grant_connection", {
          site: site.alias,
          clientIds: selected,
          siteUrl: captured.current.url,
          account: captured.current.account || "",
          tenant: captured.current.tenant || "",
        });
      } catch (error) {
        // The backend rejects the whole batch atomically; name the tools that
        // turned ineligible so the user can fix one without re-granting all.
        const ineligible = selected
          .map((id) => clients.find((client) => client.id === id))
          .filter((client) => client && !clientActive(client))
          .map((client) => client!.name);
        if (ineligible.length) {
          throw new Error(
            `以下客户端已失效，本次授权未保存：${ineligible.join("、")}。请取消勾选后重试。`,
          );
        }
        throw error;
      }
      setSaved(true);
      await onRefresh();
      await checkClients(selected);
    });
  }
  return (
    <div className="connection-consent">
      <section className="consent-account">
        <ServiceMark name={site.name || site.alias} />
        <div>
          <strong>{site.name || site.alias}</strong>
          <small>{accountLabel(site)}</small>
        </div>
        <Badge tone={connectionAbility(site).tone}>
          {connectionAbility(site).text}
        </Badge>
      </section>
      {saved ? (
        <section className="consent-result" role="status">
          <div className="result-heading">
            <Icon name="check" size={24} />
            <div>
              <h2>授权已保存</h2>
              <p>已选择的 AI 可持续使用此连接，直到撤销。</p>
            </div>
          </div>
          {checks.length ? (
            checks.map((check) => (
              <div className="check-result" key={check.id}>
                <Badge tone={check.ok ? "success" : "warning"}>
                  {check.ok ? "本机代理正常" : "需要处理"}
                </Badge>
                <div>
                  <strong>
                    {clients.find((client) => client.id === check.id)?.name}
                  </strong>
                  <p>{check.message}</p>
                </div>
                {!check.ok && (
                  <button
                    className="text-button"
                    onClick={() =>
                      setConfiguring(
                        clients.find((client) => client.id === check.id) ||
                          null,
                      )
                    }
                  >
                    接入配置
                  </button>
                )}
              </div>
            ))
          ) : (
            <p>正在检查本机代理…</p>
          )}
          <div className="privacy-note">
            <Icon name="terminal" size={17} />
            代理检查不代表 AI 客户端已加载配置，也不代表服务端业务请求成功。
          </div>
          <div className="modal-actions">
            <button
              className="button"
              disabled={action.busy}
              onClick={() => void action.run(() => checkClients(selected))}
            >
              重新检查
            </button>
            <button
              className="button primary"
              disabled={action.busy}
              onClick={onClose}
            >
              查看连接
            </button>
          </div>
        </section>
      ) : (
        <>
          <header className="consent-heading">
            <h2>允许哪些 AI 使用这个连接？</h2>
            <p>选中的 AI 可以持续使用该账号，直到你撤销授权。</p>
          </header>
          <div className="client-selection">
            {eligible.map((client) => (
              <label
                className={`client-choice${selected.includes(client.id) ? " selected" : ""}`}
                key={client.id}
              >
                <ServiceMark name={client.name} />
                <span>
                  <strong>{client.name}</strong>
                  <small>
                    {granted.some((h) => h.name === client.harness)
                      ? "已有授权 · 本次可扩展到整个连接"
                      : "已配对本机"}
                  </small>
                </span>
                <input
                  type="checkbox"
                  checked={selected.includes(client.id)}
                  disabled={action.busy}
                  onChange={(event) =>
                    setSelected((ids) =>
                      event.target.checked
                        ? [...ids, client.id]
                        : ids.filter((id) => id !== client.id),
                    )
                  }
                />
              </label>
            ))}
            {!eligible.length && (
              <Empty icon="terminal" title="先接入一个 AI 工具">
                配对完成后返回这里，选择它可以使用的连接。
              </Empty>
            )}
          </div>
          {eligible.length > 1 && (
            <div className="button-row consent-bulk">
              <button
                className="text-button"
                disabled={action.busy}
                onClick={() => setSelected(eligible.map((client) => client.id))}
              >
                全选
              </button>
              <button
                className="text-button"
                disabled={action.busy || !selected.length}
                onClick={() => setSelected([])}
              >
                清除选择
              </button>
              <small className="muted">
                已选 {selected.length} / {eligible.length}
              </small>
            </div>
          )}
          <button
            className="text-button"
            disabled={action.busy}
            onClick={() => setPairing(true)}
          >
            <Icon name="plus" size={16} />
            接入其他 AI
          </button>
          <section className="consent-scope">
            <h3>本次授权</h3>
            <dl>
              <div>
                <dt>使用范围</dt>
                <dd>整个连接</dd>
              </div>
              <div>
                <dt>有效期</dt>
                <dd>直到撤销</dd>
              </div>
              <div>
                <dt>当前能力</dt>
                <dd>接口调用</dd>
              </div>
            </dl>
            <p>仅限此账号连接和服务端已有权限。原有拒绝规则继续生效。</p>
            {siteDetails(site).ai_enabled === false && granted.length > 0 && (
              <p className="inline-warning">
                恢复 AI 使用后，此连接已有的其他授权也会重新生效。
              </p>
            )}
            {onAdvanced && (
              <details>
                <summary>高级设置</summary>
                <p>
                  需要限定方法、路径或有效期时，可在 AI 工具中设置自定义范围。
                </p>
                <button className="text-button" onClick={onAdvanced}>
                  管理自定义范围 →
                </button>
              </details>
            )}
          </section>
          {changed && (
            <Notice error="账号信息已变化，请返回连接详情后重新授权。" />
          )}
          <Notice error={action.error} />
          <p className="consent-next">
            <Icon name="check" size={16} />
            完成后检查所选 AI 的本机配对和代理连接。
          </p>
          <div className="consent-actions">
            <button className="button" disabled={action.busy} onClick={onClose}>
              稍后授权
            </button>
            <button
              className="button primary"
              disabled={action.busy || !selected.length || blocked || changed}
              onClick={() => void submit()}
            >
              {action.busy ? "授权并检查中…" : "授权并检查"}
              <Icon name="arrow" size={16} />
            </button>
          </div>
        </>
      )}
      {saved && <Notice error={action.error} />}
      {pairing && (
        <PairDialog
          skipGrant
          sites={[site]}
          existingHarnesses={harnesses.map((h) => h.name)}
          onClose={() => {
            setPairing(false);
            void onRefresh();
          }}
          onSaved={async (client) => {
            await onRefresh();
            setSelected((ids) =>
              ids.includes(client.id) ? ids : [...ids, client.id],
            );
          }}
        />
      )}
      {configuring && (
        <ConfigDialog
          client={configuring}
          onClose={() => setConfiguring(null)}
        />
      )}
    </div>
  );
}

function AuthenticationConfigDialog({site,onClose,onSaved}:{site:SiteSummary;onClose:()=>void;onSaved:()=>Promise<void>}) {
  const [kind,setKind]=useState(["login","authflow","e10","api_token","http_basic","cookie_jar"].includes(site.auth_type)?site.auth_type:"login");
  const [config,setConfig]=useState("");
  const action=useAction();
  return <Modal title="认证配置" subtitle={site.name || site.alias} onClose={onClose}>
    <form className="stack-form" onSubmit={e=>{e.preventDefault();void action.run(async()=>{const profile=JSON.parse(config);await call("authflow_configure",{alias:site.alias,authType:kind,profile});await onSaved();});}}>
      <label>连接方式<select value={kind} onChange={e=>setKind(e.target.value as typeof kind)}><option value="login">浏览器登录</option><option value="e10">E10 快捷授权</option><option value="authflow">授权登录</option><option value="api_token">访问密钥</option><option value="http_basic">HTTP Basic 账号密码</option><option value="cookie_jar">导入的 Cookie</option></select></label>
      <label>替换认证流程 JSON<textarea required rows={12} value={config} onChange={e=>setConfig(e.target.value)} placeholder={'{"headers":{"X-Session":"${cookie:SESSION}"}}'} spellCheck={false}/></label>
      <p className="panel-hint">现有凭据和账号绑定会保留。填写完整的新配置；原配置不会回显其中可能包含的秘密。保存后需重新检查连接。旧版连接也可在这里转换为通用连接方式。</p>
      <Notice error={action.error}/><div className="modal-actions"><button type="button" className="button" onClick={onClose}>取消</button><button className="button primary" disabled={action.busy}>保存配置</button></div>
    </form>
  </Modal>;
}
