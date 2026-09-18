import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  AllowRule,
  AuditEntry,
  call,
  Client,
  ClientKind,
  ConfigPreview,
  HarnessSummary,
  RequestedScope,
  SiteSummary,
  siteDetails,
  timestamp,
} from "./api";
import { Badge, Empty, Icon, IconButton, Modal, Notice, useAction } from "./ui";
import { clientActive, wholeConnection } from "./connections";

const clientLabels: Record<ClientKind, string> = {
  codex: "Codex",
  claude: "Claude Code",
  generic: "通用 MCP / CLI",
};

export function Access({
  clients,
  harnesses,
  sites,
  audit,
  onRefresh,
  focusSite,
  focusHarness,
}: {
  clients: Client[];
  harnesses: HarnessSummary[];
  sites: SiteSummary[];
  audit: AuditEntry[];
  onRefresh: () => Promise<void>;
  focusSite: string | null;
  focusHarness: string | null;
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const [pairing, setPairing] = useState(false);
  const [granting, setGranting] = useState(false);
  const [configuring, setConfiguring] = useState<Client | null>(null);
  const [editing, setEditing] = useState<HarnessSummary | null>(null);
  const [revoking, setRevoking] = useState<Client | null>(null);
  const [removing, setRemoving] = useState<AllowRule | null>(null);
  const [handshake, setHandshake] = useState<{
    ok: boolean;
    message: string;
    connections?: { alias?: string }[];
  } | null>(null);
  const action = useAction();
  const entries = useMemo(
    () => [
      ...clients.map((client) => ({
        key: client.id,
        name: client.name,
        harness: client.harness,
        client,
      })),
      ...harnesses
        .filter(
          (harness) =>
            !clients.some((client) => client.harness === harness.name),
        )
        .map((harness) => ({
          key: `legacy:${harness.name}`,
          name: harness.name,
          harness: harness.name,
          client: null,
        })),
    ],
    [clients, harnesses],
  );
  useEffect(() => {
    if (focusHarness) {
      const target = entries.find((entry) => entry.harness === focusHarness);
      if (target) setSelected(target.key);
    }
  }, [focusHarness, entries]);
  const active = entries.find((entry) => entry.key === selected) || entries[0];
  const harness = harnesses.find((item) => item.name === active?.harness);
  const rules = harness?.policy.allow || [];
  const denied = harness?.policy.deny || [];
  useEffect(() => {
    if (focusSite && active) setGranting(true);
  }, [focusSite]);
  useEffect(() => {
    setHandshake(null);
  }, [selected]);
  // Real usage evidence: business-shaped audit records from this harness.
  // A handshake or CLI self-check never writes these entries.
  const lastRealCall = useMemo(() => {
    if (!active) return null;
    return (
      [...audit]
        .filter(
          (entry) =>
            entry.harness === active.harness &&
            entry.status_code != null &&
            entry.note !== "pending_approval",
        )
        .sort((a, b) => b.ts.localeCompare(a.ts))[0] || null
    );
  }, [entries, active]);
  async function runHandshake() {
    if (!active?.client) return;
    await action.run(async () => {
      const result = await call<{
        ok: boolean;
        message: string;
        connections?: { alias?: string }[];
      }>("client_handshake", { id: active.client!.id });
      setHandshake(result);
    });
  }
  return (
    <div className="page access-page">
      <div className="page-heading">
        <div>
          <h1>AI 工具</h1>
          <p>接入你的 AI，管理它可以使用的账号连接。</p>
        </div>
        <button className="button primary" onClick={() => setPairing(true)}>
          <Icon name="plus" />
          接入 AI 客户端
        </button>
      </div>
      <Notice error={action.error} message={action.message} />
      <div className="access-layout">
        <aside className="client-rail">
          <div className="section-label">
            <h2>客户端</h2>
            <span>{entries.length}</span>
          </div>
          {entries.length ? (
            entries.map((entry) => (
              <button
                key={entry.key}
                className={`client-item${active?.key === entry.key ? " selected" : ""}`}
                onClick={() => setSelected(entry.key)}
                aria-pressed={active?.key === entry.key}
              >
                <span className="client-mark">
                  <Icon name="terminal" size={19} />
                </span>
                <span>
                  <strong>{entry.name}</strong>
                  <small>
                    {entry.client
                      ? entry.client.revoked_at
                        ? "已撤销"
                        : clientLabels[entry.client.kind]
                      : "旧版调用身份"}
                  </small>
                </span>
                <Icon name="chevron" size={14} />
              </button>
            ))
          ) : (
            <Empty icon="terminal" title="接入你的 AI">
              配对客户端后，选择它能使用的连接。
            </Empty>
          )}
          <div className="rail-note">
            <Icon name="shield" size={16} />
            <p>客户端名称用于辨识。配对身份由本机保护，配置中不写入秘密。</p>
          </div>
        </aside>
        <section className="access-content">
          {active ? (
            <>
              <header className="access-header">
                <div>
                  <div className="button-row">
                    <h2>{active.name}</h2>
                    <Badge
                      tone={active.client?.revoked_at ? "neutral" : "success"}
                    >
                      {active.client
                        ? active.client.revoked_at
                          ? "已撤销"
                          : "已配对"
                        : "旧版兼容"}
                    </Badge>
                  </div>
                  <p className="muted">
                    身份 <span className="mono">{active.harness}</span>
                    {active.client?.last_used_at
                      ? ` · 最近使用 ${timestamp(active.client.last_used_at)}`
                      : ""}
                  </p>
                </div>
                <div className="button-row">
                  {active.client && (
                    <button
                      className="button small"
                      onClick={() => setConfiguring(active.client!)}
                      disabled={Boolean(active.client.revoked_at)}
                    >
                      <Icon name="terminal" size={15} />
                      接入配置
                    </button>
                  )}
                  <IconButton
                    icon="refresh"
                    label="刷新客户端授权"
                    onClick={() => void action.run(onRefresh)}
                    disabled={action.busy}
                  />
                </div>
              </header>
              {active.client && !active.client.revoked_at && (
                <section className="access-loop" aria-label="接入闭环">
                  <header>
                    <h3>接入闭环</h3>
                    <p>配对握手与真实调用是不同证据，分别显示。</p>
                  </header>
                  <div className="loop-row">
                    <Badge tone={handshake?.ok ? "success" : "neutral"}>
                      {handshake ? (handshake.ok ? "本机配对正常" : "握手失败") : "尚未握手"}
                    </Badge>
                    <span className="loop-text">
                      {handshake
                        ? `${handshake.message}${
                            handshake.connections?.length
                              ? ` · 已授权 ${handshake.connections.length} 个连接`
                              : " · 尚无已授权连接"
                          }`
                        : "写入配置并重载工具后，用“身份握手”确认配对通道。"}
                    </span>
                    <button
                      className="text-button"
                      disabled={action.busy}
                      onClick={() => void runHandshake()}
                    >
                      身份握手
                    </button>
                  </div>
                  <div className="loop-row">
                    <Badge tone={lastRealCall ? "success" : "neutral"}>
                      {lastRealCall ? "工具已实际调用" : "等待首次调用"}
                    </Badge>
                    <span className="loop-text">
                      {lastRealCall
                        ? `最近真实调用 ${sites.find((site) => site.alias === lastRealCall.site)?.name || lastRealCall.site} · 响应 ${lastRealCall.status_code} · ${timestamp(lastRealCall.ts)}`
                        : "重载工具之前的首次真实请求不会显示在这里；握手通过不代表工具已加载配置。"}
                    </span>
                  </div>
                </section>
              )}
              <div className="scope-heading">
                <div>
                  <h3>允许使用的连接</h3>
                  <p>范围外的请求等待批准；拒绝规则优先。</p>
                </div>
                <button
                  className="button"
                  onClick={() => setGranting(true)}
                  disabled={Boolean(active.client?.revoked_at)}
                >
                  <Icon name="plus" size={16} />
                  添加授权
                </button>
              </div>
              {rules.length ? (
                <div className="grant-list">
                  {rules.map((rule, index) => {
                    const site = sites.find((item) => item.alias === rule.site);
                    const detail = site ? siteDetails(site) : {};
                    const expired = Boolean(
                      rule.expires_at &&
                        Date.parse(rule.expires_at) <= Date.now(),
                    );
                    return (
                      <article
                        className="grant-card"
                        key={`${rule.site}-${index}`}
                      >
                        <div className="grant-card-head">
                          <div>
                            <strong>{site?.name || rule.site}</strong>
                            <span>
                              {detail.account || rule.site}
                              {detail.environment
                                ? ` · ${detail.environment}`
                                : ""}
                            </span>
                          </div>
                          <Badge
                            tone={
                              expired || detail.ai_enabled === false
                                ? "warning"
                                : "success"
                            }
                          >
                            {expired
                              ? "已到期"
                              : detail.ai_enabled === false
                                ? "连接未开放"
                                : "已授权"}
                          </Badge>
                        </div>
                        <div className="grant-scope">
                          {rule.capability && (
                            <span className="capability-id">
                              {rule.capability}
                            </span>
                          )}
                          <span className="method">
                            {rule.methods?.join(" · ") || "全部方法"}
                          </span>
                          <code>
                            {wholeConnection(rule)
                              ? "整个连接 · 持续授权"
                              : rule.paths?.join(" · ") || "全部路径"}
                          </code>
                        </div>
                        {rule.constraints &&
                          Object.keys(rule.constraints).length > 0 && (
                            <div className="constraint-summary">
                              {Object.entries(rule.constraints).flatMap(
                                ([source, fields]) =>
                                  Object.entries(fields).map(
                                    ([key, values]) => (
                                      <code key={`${source}-${key}`}>
                                        {source}.{key} = {values.join(" | ")}
                                      </code>
                                    ),
                                  ),
                              )}
                            </div>
                          )}
                        <footer>
                          <span>
                            {rule.operation === "write"
                              ? "写入操作"
                              : rule.operation === "query"
                                ? "查询操作"
                                : "已配置范围"}{" "}
                            ·{" "}
                            {rule.expires_at
                              ? `有效至 ${timestamp(rule.expires_at)}`
                              : "持续授权，直至撤销"}
                          </span>
                          <button
                            className="text-button danger-text"
                            onClick={() => setRemoving(rule)}
                          >
                            撤销
                          </button>
                        </footer>
                      </article>
                    );
                  })}
                </div>
              ) : (
                <Empty
                  icon="shield"
                  title="还没有开放任何连接"
                  action={
                    <button
                      className="button"
                      onClick={() => setGranting(true)}
                      disabled={Boolean(active.client?.revoked_at)}
                    >
                      选择连接与范围
                    </button>
                  }
                >
                  这个客户端需要你的授权才能使用凭据。
                </Empty>
              )}
              {denied.length > 0 && (
                <section className="deny-summary">
                  <h3>明确拒绝的范围</h3>
                  {denied.map((rule, index) => (
                    <div className="scope-line" key={index}>
                      <Badge tone="danger">拒绝</Badge>
                      <code>
                        {rule.site} · {rule.methods?.join(", ") || "全部方法"} ·{" "}
                        {rule.paths?.join(", ") || "全部路径"}
                      </code>
                    </div>
                  ))}
                </section>
              )}
              {harness?.policy.default_action === "allow" && (
                <div className="notice warning">
                  此旧版策略的默认动作为允许，未命中范围的请求可能被放行。可在高级策略中改为
                  deny。
                </div>
              )}
              <footer className="access-footer">
                <button
                  className="text-button"
                  onClick={() => harness && setEditing(harness)}
                  disabled={!harness}
                >
                  编辑高级策略
                </button>
                {active.client && !active.client.revoked_at && (
                  <button
                    className="text-button danger-text"
                    onClick={() => setRevoking(active.client!)}
                  >
                    撤销客户端配对
                  </button>
                )}
              </footer>
            </>
          ) : (
            <Empty
              icon="terminal"
              title="把授权交给 pman 管理"
              action={
                <button
                  className="button primary"
                  onClick={() => setPairing(true)}
                >
                  接入第一个客户端
                </button>
              }
            >
              选择 Codex、Claude Code，或使用通用 MCP / CLI。
            </Empty>
          )}
        </section>
      </div>
      {pairing && (
        <PairDialog
          sites={sites}
          existingHarnesses={harnesses.map((item) => item.name)}
          onClose={() => setPairing(false)}
          onSaved={async (client) => {
            setSelected(client.id);
            await onRefresh();
          }}
        />
      )}
      {granting && active && (
        <GrantDialog
          harness={active.harness}
          sites={sites}
          initialSite={focusSite || undefined}
          onClose={() => setGranting(false)}
          onSaved={async () => {
            setGranting(false);
            await onRefresh();
          }}
        />
      )}
      {configuring && (
        <ConfigDialog
          client={configuring}
          onClose={() => setConfiguring(null)}
        />
      )}
      {editing && (
        <PolicyDialog
          harness={editing}
          onClose={() => setEditing(null)}
          onSaved={async () => {
            setEditing(null);
            await onRefresh();
          }}
        />
      )}
      {revoking && (
        <Modal
          title={`撤销 ${revoking.name} 的配对`}
          onClose={() => {
            if (!action.busy) setRevoking(null);
          }}
        >
          <p>
            此客户端的配对身份立即失效。再次使用需要重新配对，历史记录保留。
          </p>
          <Notice error={action.error} />
          <div className="modal-actions">
            <button
              className="button"
              onClick={() => setRevoking(null)}
              disabled={action.busy}
            >
              取消
            </button>
            <button
              className="button danger"
              disabled={action.busy}
              onClick={() =>
                void action.run(async () => {
                  await call("client_revoke", { id: revoking.id });
                  setRevoking(null);
                  await onRefresh();
                })
              }
            >
              撤销配对
            </button>
          </div>
        </Modal>
      )}
      {removing && active && (
        <Modal
          title="撤销这项授权"
          onClose={() => {
            if (!action.busy) setRemoving(null);
          }}
        >
          <p>
            <strong>{active.name}</strong> 将不能再通过这条规则访问{" "}
            <strong>{removing.site}</strong>。其他规则保持有效。
          </p>
          <div className="code-block">
            {removing.methods?.join(", ")} {removing.paths?.join(", ")}
          </div>
          <Notice error={action.error} />
          <div className="modal-actions">
            <button
              className="button"
              onClick={() => setRemoving(null)}
              disabled={action.busy}
            >
              取消
            </button>
            <button
              className="button danger"
              disabled={action.busy}
              onClick={() =>
                void action.run(async () => {
                  await call("remove_harness_allow_rule", {
                    name: active.harness,
                    rule: removing,
                  });
                  setRemoving(null);
                  await onRefresh();
                })
              }
            >
              撤销授权
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}

function GrantForm({
  harness,
  sites,
  initialSite,
  initialScope,
  fixedSite,
  onSaved,
  onCancel,
}: {
  harness: string;
  sites: SiteSummary[];
  initialSite?: string;
  initialScope?: RequestedScope | null;
  fixedSite?: boolean;
  onSaved: () => Promise<void>;
  onCancel: () => void;
}) {
  const eligible = sites.filter(
    (site) => site.auth_type !== "password" && Boolean(site.site_url),
  );
  const [alias, setAlias] = useState(initialSite || eligible[0]?.alias || "");
  const [scope, setScope] = useState<"connection" | "custom">(
    initialScope ? "custom" : "connection",
  );
  const [operation, setOperation] = useState<"query" | "write">(
    initialScope?.operation === "write" ? "write" : "query",
  );
  const [method, setMethod] = useState(initialScope?.method || "GET");
  const [path, setPath] = useState(initialScope?.path || "/");
  const [capability, setCapability] = useState("");
  const [constraints, setConstraints] = useState<
    { source: "query" | "json_body" | "form"; key: string; values: string }[]
  >([]);
  const [duration, setDuration] = useState("persistent");
  const [expiry, setExpiry] = useState("");
  const action = useAction();
  async function save(event: FormEvent) {
    event.preventDefault();
    await action.run(async () => {
      if (scope === "connection") {
        const connection = eligible.find((item) => item.alias === alias);
        if (!connection) throw new Error("请选择一个连接。");
        const clients = await call<Client[]>("clients_list");
        const client = clients.find(
          (item) => item.harness === harness && clientActive(item),
        );
        if (!client)
          throw new Error(
            "请先配对有效的 AI 客户端；旧版身份可使用自定义范围。",
          );
        const details = siteDetails(connection);
        await call("grant_connection", {
          site: alias,
          clientIds: [client.id],
          siteUrl: connection.site_url,
          account: details.account || "",
          tenant: details.tenant || "",
        });
        await onSaved();
        return;
      }
      if (!eligible.some((site) => site.alias === alias))
        throw new Error("请先在凭据详情中启用“允许向 AI 授权”。");
      if (
        !path.startsWith("/") ||
        path.includes("?") ||
        path.includes("#") ||
        path.includes("\\") ||
        /\s/.test(path)
      )
        throw new Error("路径以 / 开头，不包含空格、查询参数或 #。");
      const expiresAt =
        duration === "persistent"
          ? undefined
          : duration === "custom"
            ? new Date(expiry).toISOString()
            : new Date(Date.now() + Number(duration) * 3600000).toISOString();
      if (expiresAt && Date.parse(expiresAt) <= Date.now())
        throw new Error("有效期必须晚于当前时间。");
      const constraintPayload: Record<string, Record<string, string[]>> = {};
      for (const constraint of constraints) {
        const key = constraint.key.trim();
        const values = constraint.values
          .split(",")
          .map((value) => value.trim())
          .filter(Boolean);
        if (!key || !values.length)
          throw new Error("参数约束必须同时填写参数名和允许值。");
        (constraintPayload[constraint.source] ||= {})[key] = values;
      }
      await call("grant_add", {
        harness,
        site: alias,
        method,
        path: path.trim(),
        expiresAt: expiresAt || null,
        operation,
        capability: capability.trim() || null,
        constraints: Object.keys(constraintPayload).length
          ? constraintPayload
          : null,
      });
      await onSaved();
    });
  }
  return (
    <form className="stack-form" onSubmit={save}>
      <label>
        连接
        <select
          required
          disabled={fixedSite}
          value={alias}
          onChange={(event) => setAlias(event.target.value)}
        >
          <option value="" disabled>
            选择账号连接
          </option>
          {eligible.map((site) => (
            <option key={site.id} value={site.alias}>
              {site.name || site.alias} ·{" "}
              {siteDetails(site).environment ||
                siteDetails(site).account ||
                site.alias}
            </option>
          ))}
        </select>
      </label>
      {!eligible.length && (
        <div className="info-box">
          <Icon name="key" />
          <p>还没有可授权的连接。先添加 API 或网站连接，并填写站点地址。</p>
        </div>
      )}
      <label>
        授权范围
        <select
          value={scope}
          onChange={(event) =>
            setScope(event.target.value as "connection" | "custom")
          }
        >
          <option value="connection">整个连接 · 持续到撤销</option>
          <option value="custom">自定义方法、路径和有效期</option>
        </select>
      </label>
      {scope === "connection" ? (
        <div className="info-box">
          <Icon name="shield" />
          <p>
            允许此 AI
            持续使用该连接的全部接口操作。原有限制继续生效。若连接此前暂停 AI
            使用，已有授权也会恢复。
          </p>
        </div>
      ) : (
        <>
          <label>
            操作用途
            <select
              value={operation}
              onChange={(event) =>
                setOperation(event.target.value as "query" | "write")
              }
            >
              <option value="query">查询业务数据</option>
              <option value="write">写入或修改业务数据</option>
            </select>
            <small>用途由你确认，HTTP 方法不能代表业务风险。</small>
          </label>
          <div className="form-grid method-path">
            <label>
              请求方法
              <select
                value={method}
                onChange={(event) => setMethod(event.target.value)}
              >
                {[
                  "GET",
                  "POST",
                  "PUT",
                  "PATCH",
                  "DELETE",
                  "HEAD",
                  "OPTIONS",
                ].map((value) => (
                  <option key={value}>{value}</option>
                ))}
              </select>
            </label>
            <label>
              允许的路径
              <input
                required
                value={path}
                onChange={(event) => setPath(event.target.value)}
                placeholder="/api/items/**"
                spellCheck={false}
              />
            </label>
          </div>
          <div className="field-note">
            <code>/api/items</code> 精确路径 · <code>/*</code> 单层 ·{" "}
            <code>/**</code> 所有子路径
          </div>
          <label>
            业务能力 ID
            <input
              value={capability}
              onChange={(event) => setCapability(event.target.value)}
              placeholder="jenkins.build.test"
              spellCheck={false}
            />
            <small>场景调用必须携带相同能力 ID；留空则保持旧版路径授权。</small>
          </label>
          <section
            className="constraint-editor"
            aria-labelledby="parameter-constraints-title"
          >
            <div className="section-heading compact">
              <div>
                <strong id="parameter-constraints-title">参数约束</strong>
                <p>
                  约束服务、环境或分支等实际请求参数，避免同一路径被扩大使用。
                </p>
              </div>
              <button
                className="button small"
                type="button"
                onClick={() =>
                  setConstraints((current) => [
                    ...current,
                    { source: "query", key: "", values: "" },
                  ])
                }
              >
                添加约束
              </button>
            </div>
            {constraints.map((constraint, index) => (
              <div className="constraint-row" key={index}>
                <select
                  aria-label="参数来源"
                  value={constraint.source}
                  onChange={(event) =>
                    setConstraints((current) =>
                      current.map((item, itemIndex) =>
                        itemIndex === index
                          ? {
                              ...item,
                              source: event.target.value as typeof item.source,
                            }
                          : item,
                      ),
                    )
                  }
                >
                  <option value="query">Query</option>
                  <option value="form">Form</option>
                  <option value="json_body">JSON</option>
                </select>
                <input
                  aria-label="参数名"
                  value={constraint.key}
                  onChange={(event) =>
                    setConstraints((current) =>
                      current.map((item, itemIndex) =>
                        itemIndex === index
                          ? { ...item, key: event.target.value }
                          : item,
                      ),
                    )
                  }
                  placeholder="service"
                  spellCheck={false}
                />
                <input
                  aria-label="允许值"
                  value={constraint.values}
                  onChange={(event) =>
                    setConstraints((current) =>
                      current.map((item, itemIndex) =>
                        itemIndex === index
                          ? { ...item, values: event.target.value }
                          : item,
                      ),
                    )
                  }
                  placeholder="xxx-service, web-*"
                  spellCheck={false}
                />
                <button
                  className="text-button danger-text"
                  type="button"
                  onClick={() =>
                    setConstraints((current) =>
                      current.filter((_, itemIndex) => itemIndex !== index),
                    )
                  }
                >
                  移除
                </button>
              </div>
            ))}
          </section>
          <label>
            有效期
            <select
              value={duration}
              onChange={(event) => setDuration(event.target.value)}
            >
              <option value="persistent">持续授权，直至撤销</option>
              <option value="1">1 小时</option>
              <option value="24">24 小时</option>
              <option value="custom">自定义到期时间</option>
            </select>
          </label>
          {duration === "custom" && (
            <label>
              到期时间
              <input
                type="datetime-local"
                required
                value={expiry}
                onChange={(event) => setExpiry(event.target.value)}
              />
            </label>
          )}
        </>
      )}
      <Notice error={action.error} />
      <div className="modal-actions">
        <button
          className="button"
          type="button"
          onClick={onCancel}
          disabled={action.busy}
        >
          取消
        </button>
        <button
          className="button primary"
          type="submit"
          disabled={
            action.busy || !eligible.some((site) => site.alias === alias)
          }
        >
          {action.busy
            ? "保存中…"
            : scope === "connection"
              ? "授权整个连接"
              : "授予此范围"}
        </button>
      </div>
    </form>
  );
}
export function GrantDialog(props: {
  harness: string;
  sites: SiteSummary[];
  initialSite?: string;
  initialScope?: RequestedScope | null;
  fixedSite?: boolean;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  return (
    <Modal
      title={`向 ${props.harness} 授权`}
      subtitle="这项授权绑定具体连接，切换当前账号不会改变调用目标。"
      onClose={props.onClose}
    >
      <GrantForm {...props} onCancel={props.onClose} />
    </Modal>
  );
}

export function PairDialog({
  sites,
  existingHarnesses,
  onClose,
  onSaved,
  skipGrant = false,
}: {
  sites: SiteSummary[];
  existingHarnesses: string[];
  onClose: () => void;
  onSaved: (client: Client) => Promise<void>;
  skipGrant?: boolean;
}) {
  const uniqueHarness = (base: string) => {
    let value = base;
    let suffix = 2;
    while (existingHarnesses.includes(value)) value = `${base}-${suffix++}`;
    return value;
  };
  const [kind, setKind] = useState<ClientKind>("codex");
  const [name, setName] = useState("Codex");
  const [harness, setHarness] = useState(() => uniqueHarness("codex"));
  const [client, setClient] = useState<Client | null>(null);
  const [phase, setPhase] = useState<"pair" | "grant" | "config">("pair");
  const action = useAction();
  async function pair(event: FormEvent) {
    event.preventDefault();
    await action.run(async () => {
      if (!name.trim() || !/^[A-Za-z0-9_.-]+$/.test(harness.trim()))
        throw new Error("身份标识请使用英文字母、数字、短横线或下划线。");
      if (existingHarnesses.includes(harness.trim()))
        throw new Error(
          "该身份已有授权策略。请使用新标识，为此客户端独立配置范围。",
        );
      const result = await call<Client>("client_pair", {
        name: name.trim(),
        kind,
        harness: harness.trim(),
      });
      setClient(result);
      await onSaved(result);
      setPhase(skipGrant ? "config" : "grant");
    });
  }
  return (
    <Modal
      title="接入 AI 客户端"
      subtitle="配对身份 → 选择访问范围 → 写入并检查配置"
      onClose={() => {
        if (!action.busy) onClose();
      }}
      wide={phase === "config"}
    >
      <div className="wizard-progress" aria-label="接入进度">
        {["配对", "授权范围", "接入配置"].map((label, index) => (
          <span
            key={label}
            className={
              ["pair", "grant", "config"].indexOf(phase) === index
                ? "current"
                : ""
            }
          >
            {index + 1}
            <b>{label}</b>
          </span>
        ))}
      </div>
      {phase === "pair" && (
        <form className="stack-form" onSubmit={pair}>
          <label>
            客户端
            <select
              value={kind}
              onChange={(event) => {
                const next = event.target.value as ClientKind;
                setKind(next);
                setName(clientLabels[next]);
                setHarness(
                  uniqueHarness(next === "generic" ? "my-agent" : next),
                );
              }}
            >
              {Object.entries(clientLabels).map(([key, label]) => (
                <option key={key} value={key}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <label>
            显示名称
            <input
              autoFocus
              required
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
          </label>
          <label>
            身份标识
            <input
              required
              value={harness}
              onChange={(event) => setHarness(event.target.value)}
              spellCheck={false}
            />
            <small>写入配置与活动记录，不能代替本机配对凭证。</small>
          </label>
          <Notice error={action.error} />
          <div className="modal-actions">
            <button className="button" type="button" onClick={onClose}>
              取消
            </button>
            <button
              className="button primary"
              type="submit"
              disabled={action.busy}
            >
              {action.busy ? "配对中…" : "配对此客户端"}
            </button>
          </div>
        </form>
      )}
      {phase === "grant" && client && (
        <>
          <p className="muted">
            已配对 {client.name}
            ，当前没有访问权限。添加第一项授权，或稍后再配置。
          </p>
          <GrantForm
            harness={client.harness}
            sites={sites}
            onSaved={async () => {
              await onSaved(client);
              setPhase("config");
            }}
            onCancel={() => setPhase("config")}
          />
          <button className="text-button" onClick={() => setPhase("config")}>
            稍后授权，继续配置
          </button>
        </>
      )}
      {phase === "config" && client && (
        <ConfigContent client={client} onClose={onClose} />
      )}
    </Modal>
  );
}
export function ConfigDialog({
  client,
  onClose,
}: {
  client: Client;
  onClose: () => void;
}) {
  return (
    <Modal
      title={`${client.name} 接入配置`}
      subtitle="配置仅包含本机程序路径和身份标识。已有配置会保留，并可恢复。"
      onClose={onClose}
      wide
    >
      <ConfigContent client={client} onClose={onClose} />
    </Modal>
  );
}
function ConfigContent({
  client,
  onClose,
}: {
  client: Client;
  onClose: () => void;
}) {
  const [preview, setPreview] = useState<ConfigPreview | null>(null);
  const [applied, setApplied] = useState(false);
  const action = useAction();
  useEffect(() => {
    void action.run(async () =>
      setPreview(
        await call<ConfigPreview>("client_config_preview", { id: client.id }),
      ),
    );
  }, [client.id]);
  return (
    <div className="stack-form">
      <Notice error={action.error} message={action.message} />
      {preview ? (
        <>
          <div className="config-target">
            <span>
              {preview.exists
                ? "检测到现有配置，将合并 pman 条目"
                : "将创建配置"}
            </span>
            <code>{preview.path}</code>
          </div>
          <pre className="code-block config-preview" tabIndex={0}>
            {preview.content}
          </pre>
          <p className="muted small-text">
            写入后，在客户端重新加载 MCP 服务。其他服务器条目保持不变。
          </p>
        </>
      ) : (
        <div className="loading-state">
          {action.busy ? "正在检测配置…" : "配置尚未加载"}
          <button
            className="text-button"
            disabled={action.busy}
            onClick={() =>
              void action.run(async () =>
                setPreview(
                  await call<ConfigPreview>("client_config_preview", {
                    id: client.id,
                  }),
                ),
              )
            }
          >
            重新检测
          </button>
        </div>
      )}
      <div className="button-row">
        <button
          className="button"
          disabled={action.busy || !preview}
          onClick={() =>
            void action.run(async () => {
              const result = await call<{ ok: boolean; message: string }>(
                "client_test",
                { id: client.id },
              );
              if (!result.ok) throw new Error(result.message);
              action.setMessage(result.message);
            })
          }
        >
          <Icon name="refresh" size={16} />
          检查连通性
        </button>
        <button
          className="button"
          disabled={action.busy || (!preview?.exists && !applied)}
          onClick={() =>
            void action.run(async () => {
              const result = await call<{ path: string }>(
                "client_config_restore",
                { id: client.id },
              );
              setApplied(false);
              action.setMessage(`已恢复 ${result.path}`);
              setPreview(
                await call<ConfigPreview>("client_config_preview", {
                  id: client.id,
                }),
              );
            })
          }
        >
          恢复上次配置
        </button>
      </div>
      <div className="modal-actions">
        <button className="button" onClick={onClose} disabled={action.busy}>
          完成
        </button>
        <button
          className="button primary"
          disabled={action.busy || !preview}
          onClick={() =>
            void action.run(async () => {
              const result = await call<{ path: string; backup_path?: string }>(
                "client_config_apply",
                { id: client.id },
              );
              setApplied(true);
              action.setMessage(
                `已写入 ${result.path}${result.backup_path ? "，原配置已备份。" : "。"}`,
              );
            })
          }
        >
          {action.busy ? "处理中…" : applied ? "重新写入配置" : "写入配置"}
        </button>
      </div>
    </div>
  );
}
function PolicyDialog({
  harness,
  onClose,
  onSaved,
}: {
  harness: HarnessSummary;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const [draft, setDraft] = useState(() =>
    JSON.stringify(harness.policy, null, 2),
  );
  const [allowConfirmed, setAllowConfirmed] = useState(false);
  const action = useAction();
  return (
    <Modal
      title={`编辑 ${harness.name} 的高级策略`}
      subtitle="可配置拒绝规则与旧版兼容策略。编辑内容不随后台刷新变化。"
      onClose={() => {
        if (!action.busy) onClose();
      }}
      wide
    >
      <form
        className="stack-form"
        onSubmit={(event) => {
          event.preventDefault();
          void action.run(async () => {
            let policy: unknown;
            try {
              policy = JSON.parse(draft);
            } catch {
              throw new Error("JSON 格式有误，请检查括号与逗号。");
            }
            if (!policy || typeof policy !== "object" || Array.isArray(policy))
              throw new Error("策略必须是 JSON 对象。");
            const value = policy as Record<string, unknown>;
            const actionValue = value.default_action ?? value.default ?? "deny";
            if (!["deny", "allow"].includes(String(actionValue)))
              throw new Error("default_action 只能是 deny 或 allow。");
            if (actionValue === "allow" && !allowConfirmed)
              throw new Error(
                "默认允许会扩大访问范围，请勾选确认或将 default_action 设为 deny。",
              );
            await call("set_harness_policy", {
              name: harness.name,
              policy: { ...value, default_action: actionValue },
            });
            await onSaved();
          });
        }}
      >
        <label>
          策略 JSON
          <textarea
            className="policy-editor"
            value={draft}
            onChange={(event) => {
              setDraft(event.target.value);
              setAllowConfirmed(false);
            }}
            spellCheck={false}
            rows={16}
          />
        </label>
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={allowConfirmed}
            onChange={(event) => setAllowConfirmed(event.target.checked)}
          />
          <span>如使用默认允许，我确认未匹配允许范围的请求也可被放行。</span>
        </label>
        <Notice error={action.error} />
        <div className="modal-actions">
          <button
            className="button"
            type="button"
            onClick={onClose}
            disabled={action.busy}
          >
            取消
          </button>
          <button
            className="button primary"
            type="submit"
            disabled={action.busy}
          >
            保存策略
          </button>
        </div>
      </form>
    </Modal>
  );
}
