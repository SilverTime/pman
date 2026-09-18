import { useEffect, useRef, useState } from "react";
import { ConfigDialog, PairDialog } from "./Access";
import {
  CredentialDetail,
  EntryDialog,
  LoginDialog,
  MetadataDialog,
} from "./Credentials";
import {
  AuditEntry,
  Client,
  ConnectionCheck,
  HarnessSummary,
  SiteInput,
  SiteSummary,
  call,
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
  expired,
  needsAttention,
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
            : key.includes("e10")
              ? "E10"
              : key.includes("openai")
                ? "AI"
                : "";
  return (
    <span
      className={`service-mark${label ? ` mark-${label.toLowerCase().replace(/[^a-z0-9]/g, "claude")}` : ""}`}
      aria-hidden="true"
    >
      {label || <Icon name={kind === "password" ? "key" : "globe"} size={22} />}
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
  const [rotating, setRotating] = useState<SiteSummary | null>(null);
  const [deleting, setDeleting] = useState<SiteSummary | null>(null);
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
  const recent = [...sites]
    .sort((a, b) => (b.last_used_at || "").localeCompare(a.last_used_at || ""))
    .slice(0, 3);
  const grants = current ? connectionGrants(current, harnesses) : [];
  const activeClients = clients.filter(clientActive);

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
                    {["login", "e10"].includes(current.auth_type) ? (
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
                    {current.auth_type === "e10" && (
                      <button
                        className="button small"
                        disabled={action.busy}
                        onClick={() =>
                          void action.run(async () => {
                            const result = await call<ConnectionCheck>(
                              "e10_check",
                              { alias: current.alias },
                            );
                            action.setMessage(
                              result.message || `连接状态：${result.status}`,
                            );
                            await onRefresh();
                          })
                        }
                      >
                        检查连接
                      </button>
                    )}
                  </div>
                </section>
                <section className="library-panel">
                  <header>
                    <h2>网页访问</h2>
                    <Badge>尚未接入</Badge>
                  </header>
                  <div className="browser-capability">
                    <Icon name="globe" size={28} />
                    <h3>登录与网页操作分开验证</h3>
                    <p>
                      当前版本可保存网站登录会话供接口调用。AI
                      操作网页的通道尚未提供。
                    </p>
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
          <p>删除账号连接后，AI 将无法继续使用这个连接。历史活动记录保留。</p>
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

const templates: {
  id: string;
  title: string;
  hint: string;
  type: SiteInput["auth_type"];
  url: string;
}[] = [
  {
    id: "github",
    title: "GitHub",
    hint: "通过个人访问令牌连接 API",
    type: "api_token",
    url: "https://api.github.com",
  },
  {
    id: "gitlab",
    title: "GitLab",
    hint: "支持自建实例与访问令牌",
    type: "api_token",
    url: "https://gitlab.com",
  },
  {
    id: "website",
    title: "网站登录",
    hint: "在独立窗口中登录并保存会话",
    type: "login",
    url: "",
  },
  {
    id: "api",
    title: "通用 API",
    hint: "API Token 或 HTTP Basic",
    type: "api_token",
    url: "",
  },
  {
    id: "e10",
    title: "E10",
    hint: "独立登录窗口或 OAuth 回调",
    type: "e10",
    url: "",
  },
  {
    id: "password",
    title: "个人密码",
    hint: "仅本人保管，不向 AI 开放",
    type: "password",
    url: "",
  },
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
  const [template, setTemplate] = useState<(typeof templates)[number] | null>(
    null,
  );
  const [saved, setSaved] = useState<SiteSummary | null>(null);
  const [loginOpen, setLoginOpen] = useState(false);
  const [loginComplete, setLoginComplete] = useState(false);
  const wizard = useRef<HTMLDivElement>(null);
  useEffect(() => {
    wizard.current?.closest(".library-content")?.scrollTo(0, 0);
  }, [template?.id, saved?.alias, loginComplete]);
  const title = template
    ? `添加${template.id === "website" || template.id === "api" ? "" : ` ${template.title} `}连接`
    : "添加连接";
  const needsLogin = saved && ["login", "e10"].includes(saved.auth_type);
  const step = !template ? 0 : !saved || (needsLogin && !loginComplete) ? 1 : 2;
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
      <ol className="connection-steps">
        {["选择服务", "连接账号", "授权 AI"].map((text, index) => (
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
      </ol>
      {!template ? (
        <>
          <h2 className="wizard-section-title">你想连接什么服务？</h2>
          <div className="service-templates">
            {templates.map((item) => (
              <button
                className="service-template"
                key={item.id}
                onClick={() => setTemplate(item)}
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
          <p className="panel-hint">
            账号信息保存在本机。选择 AI 并确认授权前，连接仅供你本人使用。
          </p>
        </>
      ) : !saved ? (
        <EntryDialog
          key={template.id}
          embedded
          initial={{
            name: template.title,
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
              status: ["login", "e10"].includes(input.auth_type)
                ? "pending"
                : "active",
              created_at: "",
              updated_at: "",
            };
            setSaved(summary);
            await onRefresh();
            if (["login", "e10"].includes(input.auth_type)) setLoginOpen(true);
            if (input.auth_type === "password") onFinished(input.alias);
          }}
        />
      ) : needsLogin && !loginComplete ? (
        <section className="library-panel login-resume">
          <ServiceMark name={saved.name || saved.alias} />
          <h2>继续完成账号登录</h2>
          <p>连接已保存。完成登录后，再选择允许使用它的 AI。</p>
          <button className="button primary" onClick={() => setLoginOpen(true)}>
            <Icon name="globe" />
            打开登录窗口
          </button>
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
      await call("grant_connection", {
        site: site.alias,
        clientIds: selected,
        siteUrl: captured.current.url,
        account: captured.current.account || "",
        tenant: captured.current.tenant || "",
      });
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
