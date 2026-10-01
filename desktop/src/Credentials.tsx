import { FormEvent, ReactNode, useEffect, useRef, useState } from "react";
import {
  AuthSession,
  call,
  ConnectionCheck,
  EntryKind,
  LoginCapture,
  LoginWindow,
  SiteDetails,
  ScenarioRoute,
  SiteInput,
  SiteSummary,
  siteDetails,
  statusLabel,
  timestamp,
  typeLabel,
} from "./api";
import { Badge, Empty, Icon, IconButton, Modal, Notice, useAction } from "./ui";

const kinds: {
  id: EntryKind;
  title: string;
  hint: string;
  icon: "key" | "terminal" | "globe" | "shield";
}[] = [
  { id: "password", title: "保存密码", hint: "账号、密码与备注", icon: "key" },
  {
    id: "api_token",
    title: "接入 API",
    hint: "Token 与请求头",
    icon: "terminal",
  },
  { id: "login", title: "登录网站", hint: "独立窗口保存会话", icon: "globe" },
  { id: "e10", title: "E10 快捷授权", hint: "独立窗口登录并验证 E10 账号", icon: "globe" },
  { id: "authflow", title: "授权登录", hint: "OAuth 与自定义认证流程", icon: "shield" },
];

function parseCookies(value: string): unknown[] {
  if (value.trim().startsWith("[")) {
    const result: unknown = JSON.parse(value);
    if (
      !Array.isArray(result) ||
      !result.length ||
      result.some(
        (item) =>
          !item ||
          typeof item !== "object" ||
          typeof item.name !== "string" ||
          typeof item.value !== "string",
      )
    )
      throw new Error("Cookie JSON 必须是包含 name、value 的对象数组。");
    return result;
  }
  const parts = value
    .split(/[;\n]/)
    .map((item) => item.trim())
    .filter(Boolean);
  if (!parts.length || parts.some((item) => item.indexOf("=") < 1))
    throw new Error("请填写 name=value，多个 Cookie 用分号或换行分隔。");
  return parts.map((item) => ({
    name: item.slice(0, item.indexOf("=")).trim(),
    value: item.slice(item.indexOf("=") + 1),
  }));
}

export function CredentialDetail({
  site,
  grants,
  onEdit,
  onRotate,
  onDelete,
  onLogin,
  onRefresh,
  onAuthorize,
  onEnable,
}: {
  site: SiteSummary;
  grants: number;
  onEdit: () => void;
  onRotate: () => void;
  onDelete: () => void;
  onLogin: () => void;
  onRefresh: () => Promise<void>;
  onAuthorize: () => void;
  onEnable: (enabled: boolean) => Promise<void>;
}) {
  const details = siteDetails(site);
  const state = statusLabel(site);
  const action = useAction();
  const [secret, setSecret] = useState<Record<string, unknown> | null>(null);
  const loginType = ["login", "authflow", "e10"].includes(site.auth_type);
  const secretField =
    site.auth_type === "api_token"
      ? "token"
      : loginType || site.auth_type === "cookie_jar"
        ? "cookies"
        : "password";
  useEffect(() => {
    const clear = () => setSecret(null);
    window.addEventListener("blur", clear);
    window.addEventListener("pman-hide-secrets", clear);
    document.addEventListener("visibilitychange", clear);
    return () => {
      window.removeEventListener("blur", clear);
      window.removeEventListener("pman-hide-secrets", clear);
      document.removeEventListener("visibilitychange", clear);
    };
  }, []);
  useEffect(() => {
    if (!secret) return;
    const timer = window.setTimeout(() => setSecret(null), 30000);
    return () => window.clearTimeout(timer);
  }, [secret]);
  useEffect(() => setSecret(null), [site.updated_at]);
  const displayedSecret = secret
    ? typeof secret[secretField] === "string"
      ? String(secret[secretField])
      : JSON.stringify(secret[secretField] ?? secret, null, 2)
    : "";
  return (
    <aside className="credential-detail" aria-label="凭据详情">
      <header>
        <span className="entry-type">
          <Icon name={loginType ? "globe" : "key"} size={22} />
        </span>
        <div>
          <h2>{site.name || site.alias}</h2>
          <span className="mono muted">{site.alias}</span>
        </div>
        <IconButton icon="edit" label="编辑账号信息" onClick={onEdit} />
      </header>
      <div className="detail-badges">
        <Badge tone={state.tone}>{state.text}</Badge>
        <span>{typeLabel(site.auth_type)}</span>
      </div>
      <dl className="detail-list">
        <div>
          <dt>账号</dt>
          <dd>{details.account || "未填写"}</dd>
        </div>
        <div>
          <dt>环境</dt>
          <dd>{details.environment || "默认"}</dd>
        </div>
        <div>
          <dt>站点</dt>
          <dd className="break-word">{site.site_url || "未关联网站"}</dd>
        </div>
        {details.tenant && (
          <div>
            <dt>租户</dt>
            <dd>{details.tenant}</dd>
          </div>
        )}
        <div>
          <dt>分组</dt>
          <dd>{details.group || "未分组"}</dd>
        </div>
        <div>
          <dt>最近使用</dt>
          <dd>{timestamp(site.last_used_at)}</dd>
        </div>
        {loginType && (
          <>
            <div>
              <dt>最近检查</dt>
              <dd>{timestamp(site.last_checked_at)}</dd>
            </div>
            <div>
              <dt>会话有效期</dt>
              <dd>{site.expires_at ? timestamp(site.expires_at) : "未提供"}</dd>
            </div>
          </>
        )}
      </dl>
      <section className="detail-section">
        <div className="section-label">
          <h3>
            {loginType || site.auth_type === "cookie_jar"
              ? "会话凭据"
              : site.auth_type === "api_token"
                ? "Token"
                : "密码"}
          </h3>
          <span>按需解密</span>
        </div>
        <div className="secret-box">
          <span className="secret-placeholder">••••••••••••••••</span>
          <IconButton
            icon={secret ? "hide" : "eye"}
            label={secret ? "隐藏秘密" : "查看秘密 30 秒"}
            onClick={() =>
              secret
                ? setSecret(null)
                : void action.run(async () =>
                    setSecret(
                      await call<Record<string, unknown>>("site_reveal", {
                        alias: site.alias,
                      }),
                    ),
                  )
            }
            disabled={action.busy}
          />
          <IconButton
            icon="copy"
            label="复制秘密，30 秒后清除"
            onClick={() =>
              void action.run(
                () =>
                  call("site_copy", { alias: site.alias, field: secretField }),
                "已复制，30 秒后自动清除剪贴板。",
              )
            }
            disabled={action.busy}
          />
        </div>
        {secret && (
          <pre
            className="revealed-secret"
            tabIndex={0}
            aria-label="临时显示的秘密"
          >
            {displayedSecret}
          </pre>
        )}
        <small className="muted">离开窗口或 30 秒后隐藏。</small>
        <div className="button-row">
          {loginType ? (
            <button className="button small" onClick={onLogin}>
              <Icon name="globe" size={15} />
              重新登录
            </button>
          ) : (
            <button className="button small" onClick={onRotate}>
              <Icon name="refresh" size={15} />
              更新凭据
            </button>
          )}
          {["authflow", "e10"].includes(site.auth_type) && (
            <button
              className="button small"
              disabled={action.busy}
              onClick={() =>
                void action.run(async () => {
                  const result = await call<ConnectionCheck>("authflow_check", {
                    alias: site.alias,
                  });
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
      <section className="detail-section">
        <div className="section-label">
          <h3>AI 使用权限</h3>
          <Badge
            tone={
              grants && details.ai_enabled !== false ? "success" : "neutral"
            }
          >
            {details.ai_enabled === false ? "仅本人" : `${grants} 项授权`}
          </Badge>
        </div>
        <label className="toggle-line">
          <span>允许向 AI 授权</span>
          <input
            type="checkbox"
            checked={
              details.ai_enabled === true && site.auth_type !== "password"
            }
            onChange={(event) =>
              void action.run(() => onEnable(event.target.checked))
            }
            disabled={action.busy || site.auth_type === "password"}
          />
        </label>
        <p className="muted small-text">
          {site.auth_type === "password"
            ? "普通密码仅供本人管理。接口账号请创建 HTTP Basic 或登录连接。"
            : "启用后，仍需给每个客户端指定访问范围。"}
        </p>
        <button
          className="button full"
          disabled={
            details.ai_enabled !== true || site.auth_type === "password"
          }
          onClick={onAuthorize}
        >
          <Icon name="shield" size={16} />
          管理此连接的授权
        </button>
      </section>
      {(details.notes || site.purpose) && (
        <section className="detail-section">
          <h3>备注</h3>
          <p className="notes">{details.notes || site.purpose}</p>
        </section>
      )}
      <Notice error={action.error} message={action.message} />
      <footer className="detail-footer">
        <span>更新于 {timestamp(site.updated_at)}</span>
        <IconButton icon="trash" label="删除此凭据" onClick={onDelete} />
      </footer>
    </aside>
  );
}

function EntryFrame({
  embedded,
  children,
  ...props
}: {
  embedded?: boolean;
  children: ReactNode;
  title: string;
  subtitle?: string;
  onClose: () => void;
}) {
  return embedded ? (
    <section className="entry-inline" aria-label={props.title}>
      {children}
    </section>
  ) : (
    <Modal {...props}>{children}</Modal>
  );
}

export function EntryDialog({
  site,
  onClose,
  onSaved,
  embedded = false,
  initial,
}: {
  site?: SiteSummary;
  onClose: () => void;
  onSaved: (input: SiteInput) => Promise<void>;
  embedded?: boolean;
  initial?: Partial<SiteInput>;
}) {
  const [kind, setKind] = useState<EntryKind | null>(
    site ? (site.auth_type as EntryKind) : initial?.auth_type || null,
  );
  const [name, setName] = useState(site?.name || initial?.name || "");
  const [alias, setAlias] = useState(site?.alias || initial?.alias || "");
  const [url, setUrl] = useState(site?.site_url || initial?.site_url || "");
  const [account, setAccount] = useState(
    site ? siteDetails(site).account || "" : "",
  );
  const [environment, setEnvironment] = useState(
    site ? siteDetails(site).environment || "" : "",
  );
  const [group, setGroup] = useState("");
  const [password, setPassword] = useState("");
  const [token, setToken] = useState("");
  const [header, setHeader] = useState(
    "",
  );
  const [cookies, setCookies] = useState("");
  const [profileText, setProfileText] = useState("");
  const [clientId, setClientId] = useState("");
  const [grantKind, setGrantKind] = useState("code");
  const [authOrigin, setAuthOrigin] = useState("");
  const [authPath, setAuthPath] = useState("/oauth/authorize");
  const [tokenPath, setTokenPath] = useState("/oauth/token");
  const [identityPath, setIdentityPath] = useState("/user");
  const [identityPointer, setIdentityPointer] = useState("/id");
  const [visible, setVisible] = useState(false);
  const action = useAction();
  useEffect(() => {
    const hide = () => setVisible(false);
    window.addEventListener("blur", hide);
    return () => window.removeEventListener("blur", hide);
  }, []);
  async function save(event: FormEvent) {
    event.preventDefault();
    await action.run(async () => {
      if (!kind) throw new Error("请选择凭据类型。");
      if (!alias.trim() || !/^[\p{L}\p{N}_.-]+$/u.test(alias.trim()))
        throw new Error("别名使用文字、数字、短横线或下划线，不能包含空格。");
      if (kind !== "password" || url.trim()) {
        const origin = new URL(url.trim());
        if (!["https:", "http:"].includes(origin.protocol))
          throw new Error("请输入完整的 HTTP 或 HTTPS 站点地址。");
      }
      let secret: Record<string, unknown>;
      if (kind === "password" || kind === "http_basic") {
        if (!password) throw new Error("请填写密码。");
        if (kind === "http_basic" && !account)
          throw new Error("HTTP Basic 需要填写用户名。");
        secret = { username: account, password };
      } else if (kind === "api_token") {
        if (!token) throw new Error("请填写 Token。");
        secret = { token, ...(header.trim() ? { header: header.trim() } : {}) };
      } else if (kind === "cookie_jar")
        secret = { cookies: parseCookies(cookies) };
      else secret = { cookies: [] };
      let authProfile: Record<string, unknown> | undefined;
      if (profileText.trim()) {
        authProfile = JSON.parse(profileText);
        if (!authProfile || typeof authProfile !== "object" || Array.isArray(authProfile)) throw new Error("认证配置必须是 JSON 对象。");
      } else if (kind === "authflow") {
        if (!clientId.trim()) throw new Error("请填写应用 Client ID，或使用完整的高级认证配置。");
        authProfile = {
          authorization: { path: authPath, params: { client_id: clientId }, pkce: grantKind === "code", kind: grantKind, ...(authOrigin.trim() ? { origin: authOrigin.trim() } : {}) },
          exchange: [{ path: tokenPath, method: "POST", form: grantKind === "device" ? { grant_type: "urn:ietf:params:oauth:grant-type:device_code", client_id: clientId, device_code: "${code}" } : { grant_type: "authorization_code", client_id: clientId, code: "${code}", redirect_uri: "${redirect_uri}", code_verifier: "${verifier}" }, extract: { access_token: ["/access_token"] }, optional_extract: { refresh_token: ["/refresh_token"] } }],
          headers: { Authorization: "Bearer ${var:access_token}" },
          check: { request: { path: identityPath }, user_id: [identityPointer] },
        };
      }
      if (authProfile) { secret.auth_profile = authProfile; secret.origin = new URL(url || site?.site_url || "").origin; }
      const input: SiteInput = {
        alias: alias.trim(),
        site_url: url.trim(),
        auth_type: site?.auth_type || kind,
        secret,
        name: name.trim() || null,
        purpose: null,
        tags: [],
        details: {
          account: account.trim(),
          environment: environment.trim(),
          group: group.trim(),
          provider: kind === "e10" ? "e10" : null,
          ai_enabled: false,
          extra: { oauth_pending: kind === "authflow", configured_auth: Boolean(authProfile), has_identity_check: Boolean(authProfile?.check), has_refresh: Array.isArray(authProfile?.refresh) && authProfile.refresh.length > 0 },
        },
      };
      if (site) await call("site_rotate", { alias: site.alias, secret });
      else await call("site_add", { input });
      setPassword("");
      setToken("");
      setCookies("");
      await onSaved(input);
    });
  }
  return (
    <EntryFrame
      embedded={embedded}
      title={
        site
          ? `更新“${site.name || site.alias}”的凭据`
          : kind
            ? kinds.find((item) => item.id === kind)?.title ||
              (kind === "http_basic" ? "接入 API" : "保存 Cookie")
            : "添加凭据"
      }
      subtitle={
        site
          ? "只替换秘密，账号信息与授权范围保留。"
          : "默认仅本人使用。保存后可以单独授予 AI 访问权限。"
      }
      onClose={() => {
        if (!action.busy) onClose();
      }}
    >
      {!kind ? (
        <>
          <div className="entry-options">
            {kinds.map((item) => (
              <button
                className="entry-option"
                key={item.id}
                onClick={() => setKind(item.id)}
              >
                <Icon name={item.icon} size={24} />
                <div>
                  <strong>{item.title}</strong>
                  <small>{item.hint}</small>
                </div>
                <Icon name="chevron" size={16} />
              </button>
            ))}
          </div>
          <button className="text-button" onClick={() => setKind("cookie_jar")}>
            已有 Cookie？手动导入
          </button>
        </>
      ) : (
        <form onSubmit={save} className="stack-form">
          {!site && (
            <>
              <div className={embedded ? "entry-name-row" : "form-grid"}>
                <label>
                  显示名称
                  <input
                    autoFocus
                    value={name}
                    onChange={(event) => setName(event.target.value)}
                    placeholder="例如 公司办公系统"
                  />
                </label>
                {!embedded && (
                  <label>
                    AI 使用的别名
                    <input
                      required
                      value={alias}
                      onChange={(event) => setAlias(event.target.value)}
                      placeholder="例如 office-test"
                      autoCapitalize="none"
                      spellCheck={false}
                    />
                  </label>
                )}
              </div>
              <label>
                站点地址 {kind === "password" && <small>（可选）</small>}
                <input
                  type="url"
                  required={kind !== "password"}
                  value={url}
                  onChange={(event) => setUrl(event.target.value)}
                  placeholder="https://example.com"
                  autoCapitalize="none"
                  spellCheck={false}
                />
              </label>
            </>
          )}
          {kind !== "password" && kind !== "http_basic" && !site && (
            <label>
              账号备注 <small>（可选）</small>
              <input
                value={account}
                onChange={(event) => setAccount(event.target.value)}
                placeholder="例如：个人账号 / 工作账号"
                autoComplete="off"
              />
            </label>
          )}
          {(kind === "password" || kind === "http_basic") && (
            <>
              <label>
                账号
                <input
                  value={account}
                  onChange={(event) => setAccount(event.target.value)}
                  autoComplete="off"
                  placeholder="用户名或邮箱"
                />
              </label>
              <label>
                密码
                <div className="input-with-actions">
                  <input
                    type={visible ? "text" : "password"}
                    required
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    autoComplete="new-password"
                  />
                  <IconButton
                    icon={visible ? "hide" : "eye"}
                    label={visible ? "隐藏密码" : "显示密码"}
                    onClick={() => setVisible(!visible)}
                  />
                </div>
              </label>
              <div className="generator-row">
                <span className="muted">随机生成 24 位密码</span>
                <button
                  className="button small"
                  type="button"
                  disabled={action.busy}
                  onClick={() =>
                    void action.run(async () => {
                      setPassword(
                        await call<string>("generate_password", { length: 24 }),
                      );
                      setVisible(false);
                    })
                  }
                >
                  <Icon name="refresh" size={14} />
                  生成密码
                </button>
              </div>
            </>
          )}
          {!site &&
            (!embedded) &&
            (kind === "api_token" || kind === "http_basic") && (
              <label>
                API 认证方式
                <select
                  value={kind}
                  onChange={(event) => setKind(event.target.value as EntryKind)}
                >
                  <option value="api_token">API Token</option>
                  <option value="http_basic">HTTP Basic 账号与密码</option>
                </select>
              </label>
            )}
          {kind === "api_token" && (
            <>
              <label>
                Token
                <input
                  type="password"
                  required
                  value={token}
                  onChange={(event) => setToken(event.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                />
              </label>
              <details className="connection-extra">
                <summary>请求头设置（可选）</summary>
                <label>
                  请求头名称
                  <input
                    value={header}
                    onChange={(event) => setHeader(event.target.value)}
                    placeholder="默认 Authorization · 可用 Private-Token"
                    spellCheck={false}
                  />
                </label>
              </details>
            </>
          )}
          {kind === "cookie_jar" && (
            <label>
              Cookie
              <textarea
                required
                rows={5}
                value={cookies}
                onChange={(event) => setCookies(event.target.value)}
                placeholder="name=value; name2=value2"
                spellCheck={false}
              />
              <small>支持 Cookie JSON 数组，保留域、路径和有效期。</small>
            </label>
          )}
          {kind === "authflow" && !site && (
            <div className="stack-form">
              <label>授权方式<select value={grantKind} onChange={e => setGrantKind(e.target.value)}><option value="code">授权码 + PKCE</option><option value="device">设备码</option></select></label>
              <label>授权服务器地址（可选）<input type="url" value={authOrigin} onChange={e => setAuthOrigin(e.target.value)} placeholder="默认使用连接地址" /></label>
              <label>应用 Client ID<input value={clientId} onChange={e => setClientId(e.target.value)} /></label>
              <div className="form-grid">
                <label>授权路径<input value={authPath} onChange={e => setAuthPath(e.target.value)} /></label>
                <label>令牌交换路径<input value={tokenPath} onChange={e => setTokenPath(e.target.value)} /></label>
                <label>身份检查路径<input value={identityPath} onChange={e => setIdentityPath(e.target.value)} /></label>
                <label>账号 ID 的 JSON Pointer<input value={identityPointer} onChange={e => setIdentityPointer(e.target.value)} /></label>
              </div>
              <small>默认使用授权码与 PKCE；回调地址使用本机端口。固定回调端口及多步交换可在高级配置中设置。</small>
            </div>
          )}
          {kind !== "password" && kind !== "e10" && (
            <details className="connection-extra">
              <summary>高级认证配置（可选）</summary>
              <label>认证流程 JSON<textarea rows={10} value={profileText} onChange={e => setProfileText(e.target.value)} placeholder={'{"headers":{"X-Session":"${cookie:SESSION}"}}'} spellCheck={false} /></label>
              <small>支持 Cookie 映射、固定请求头、多步交换、身份检查和续期。完整配置会覆盖上面的授权默认值；凭据变量仅在本机解析。</small>
            </details>
          )}
          {(kind === "login" || kind === "authflow" || kind === "e10") && (
            <div className="info-box">
              <Icon name="globe" />
              <p>
                {kind === "authflow"
                  ? "保存连接后打开系统浏览器授权。完成授权后，将自动交换凭据并验证身份。"
                  : kind === "e10"
                    ? "保存连接后打开浏览器完成 E10 OAuth 授权；平台未回传 state 时改用独立登录窗口。"
                    : "保存连接后打开独立登录窗口。完成登录，再回到这里保存并验证会话。"}
              </p>
            </div>
          )}
          {!site && (
            <details className="connection-extra">
              <summary>环境、分组与高级设置</summary>
              {embedded && (
                <label>
                  连接别名
                  <input
                    value={alias}
                    onChange={(event) => setAlias(event.target.value)}
                    autoCapitalize="none"
                    spellCheck={false}
                  />
                  <small>已自动生成，通常无需修改。</small>
                </label>
              )}
              <div className="form-grid">
                <label>
                  环境
                  <input
                    value={environment}
                    onChange={(event) => setEnvironment(event.target.value)}
                    placeholder="例如 测试 / 生产"
                  />
                </label>
                <label>
                  分组
                  <input
                    value={group}
                    onChange={(event) => setGroup(event.target.value)}
                    placeholder="例如 工作"
                  />
                </label>
              </div>
            </details>
          )}
          <Notice error={action.error} />
          <div className="modal-actions">
            <button
              className="button"
              type="button"
              onClick={() => (site || embedded ? onClose() : setKind(null))}
              disabled={action.busy}
            >
              {site ? "取消" : "返回"}
            </button>
            <button
              className="button primary"
              disabled={action.busy}
              type="submit"
            >
              {action.busy
                ? "保存中…"
                : kind === "login" || kind === "authflow" || kind === "e10"
                  ? "保存并登录"
                  : embedded
                    ? "保存并继续"
                    : "保存凭据"}
            </button>
          </div>
        </form>
      )}
    </EntryFrame>
  );
}

/** Step-1 form for preset OAuth providers (Microsoft / Google): collect the
 * client id, save a pending connection and hand over to the OAuth dialog.
 * No token is ever typed here — the access token arrives only through the
 * native OAuth exchange. */
export function OAuthPresetDialog({
  provider,
  initial,
  onClose,
  onSaved,
}: {
  provider: "microsoft" | "google";
  initial: { alias: string; site_url: string };
  onClose: () => void;
  onSaved: (input: SiteInput) => Promise<void>;
}) {
  const [name, setName] = useState("");
  const [alias, setAlias] = useState(initial.alias);
  const [url, setUrl] = useState(initial.site_url);
  const [clientId, setClientId] = useState("");
  const [scope, setScope] = useState("");
  const [tenant, setTenant] = useState("");
  const action = useAction();
  const microsoft = provider === "microsoft";
  async function save(event: FormEvent) {
    event.preventDefault();
    await action.run(async () => {
      if (!alias.trim() || !/^[\p{L}\p{N}_.-]+$/u.test(alias.trim()))
        throw new Error("别名使用文字、数字、短横线或下划线，不能包含空格。");
      const origin = new URL(url.trim());
      if (!["https:", "http:"].includes(origin.protocol))
        throw new Error("请输入完整的 HTTP 或 HTTPS 站点地址。");
      if (!clientId.trim())
        throw new Error(
          "请填写在提供方注册的 OAuth 应用 client_id（无需 client secret）。",
        );
      const input: SiteInput = {
        alias: alias.trim(),
        site_url: url.trim(),
        auth_type: "api_token",
        secret: { oauth_pending: true },
        name: name.trim() || null,
        purpose: null,
        tags: [],
        details: {
          account: "",
          environment: "",
          group: "",
          provider,
          ai_enabled: false,
          oauth_client_id: clientId.trim(),
          oauth_scope: scope.trim() || null,
          oauth_tenant: microsoft ? tenant.trim() || null : null,
          extra: { oauth_pending: true },
        },
      };
      await call("site_add", { input });
      await onSaved(input);
    });
  }
  return (
    <EntryFrame
      embedded
      title={microsoft ? "接入 Microsoft (Entra ID)" : "接入 Google 账号"}
      subtitle="OAuth 授权码 + PKCE，全程无需 client secret；令牌只保存在本机保险库。"
      onClose={() => {
        if (!action.busy) onClose();
      }}
    >
      <form className="stack-form" onSubmit={(event) => void save(event)}>
        <Notice error={action.error} message={action.message} />
        <div className="form-grid">
          <label>
            名称
            <input
              value={name}
              placeholder="例如 公司账号"
              onChange={(event) => setName(event.target.value)}
            />
          </label>
          <label>
            服务地址
            <input
              type="url"
              value={url}
              spellCheck={false}
              onChange={(event) => setUrl(event.target.value)}
            />
          </label>
        </div>
        <label>
          OAuth 应用 client_id
          <input
            value={clientId}
            placeholder="在提供方注册的公开应用 ID"
            spellCheck={false}
            onChange={(event) => setClientId(event.target.value)}
          />
        </label>
        <div className="form-grid">
          <label>
            OAuth scope
            <input
              value={scope}
              placeholder={
                microsoft ? "User.Read offline_access" : "openid email profile"
              }
              spellCheck={false}
              onChange={(event) => setScope(event.target.value)}
            />
            <small>留空使用最小只读范围。</small>
          </label>
          {microsoft && (
            <label>
              tenant
              <input
                value={tenant}
                placeholder="organizations（默认）/ consumers / common"
                spellCheck={false}
                onChange={(event) => setTenant(event.target.value)}
              />
              <small>个人账号需改为 consumers 或 common。</small>
            </label>
          )}
        </div>
        <div className="info-box">
          <Icon name="shield" />
          <p>
            保存后立即打开浏览器完成授权。访问令牌由本机原生交换获得；
            此表单不收集任何令牌、密码或 client secret。
          </p>
        </div>
        <div className="modal-actions">
          <button type="button" className="button" onClick={onClose}>
            取消
          </button>
          <button
            type="submit"
            className="button primary"
            disabled={action.busy}
          >
            {action.busy ? "保存中…" : "保存并开始授权"}
          </button>
        </div>
      </form>
    </EntryFrame>
  );
}

export function MetadataDialog({
  site,
  onClose,
  onSaved,
}: {
  site: SiteSummary;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const [name, setName] = useState(site.name || "");
  const [url, setUrl] = useState(site.site_url);
  const [details, setDetails] = useState<SiteDetails>(() => ({
    ...siteDetails(site),
    notes: siteDetails(site).notes || site.purpose || "",
  }));
  const action = useAction();
  const field = (key: keyof SiteDetails, value: string) =>
    setDetails((draft) => ({ ...draft, [key]: value }));
  const scenarios = details.scenarios || [];
  const updateScenario = (index: number, patch: Partial<ScenarioRoute>) =>
    setDetails((draft) => ({
      ...draft,
      scenarios: (draft.scenarios || []).map((route, routeIndex) =>
        routeIndex === index ? { ...route, ...patch } : route,
      ),
    }));
  return (
    <Modal
      title="编辑账号信息"
      subtitle={`别名 ${site.alias} 保持不变，后台刷新不会覆盖本次编辑。`}
      onClose={() => {
        if (!action.busy) onClose();
      }}
    >
      <form
        className="stack-form"
        onSubmit={(event) => {
          event.preventDefault();
          void action.run(async () => {
            await call("site_update_metadata", {
              alias: site.alias,
              siteUrl: url.trim(),
              name: name.trim() || null,
              purpose: details.notes || null,
              tags: site.tags,
              details,
            });
            await onSaved();
          });
        }}
      >
        <label>
          显示名称
          <input
            autoFocus
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        </label>
        <label>
          站点地址
          <input
            type="url"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
          />
        </label>
        <div className="form-grid">
          <label>
            账号
            <input
              value={details.account || ""}
              onChange={(event) => field("account", event.target.value)}
            />
          </label>
          <label>
            环境
            <input
              value={details.environment || ""}
              onChange={(event) => field("environment", event.target.value)}
            />
          </label>
          <label>
            分组
            <input
              value={details.group || ""}
              onChange={(event) => field("group", event.target.value)}
            />
          </label>
          <label>
            租户
            <input
              value={details.tenant || ""}
              onChange={(event) => field("tenant", event.target.value)}
            />
          </label>
        </div>
        <label>
          备注
          <textarea
            rows={4}
            value={details.notes || ""}
            onChange={(event) => field("notes", event.target.value)}
            placeholder="填写用途和说明，密码请保存在凭据字段中。"
          />
        </label>
        <section
          className="scenario-editor"
          aria-labelledby="scenario-routes-title"
        >
          <div className="section-heading compact">
            <div>
              <strong id="scenario-routes-title">场景路由</strong>
              <p>AI 按意图、环境和服务唯一选择此连接；账号始终随连接固定。</p>
            </div>
            <button
              className="button small"
              type="button"
              onClick={() =>
                setDetails((draft) => ({
                  ...draft,
                  scenarios: [
                    ...(draft.scenarios || []),
                    { intent: "", capability: "", services: [], selectors: {} },
                  ],
                }))
              }
            >
              添加场景
            </button>
          </div>
          {scenarios.length ? (
            <div className="scenario-list">
              {scenarios.map((route, index) => (
                <article
                  className="scenario-row"
                  key={`${route.intent}-${index}`}
                >
                  <div className="form-grid">
                    <label>
                      业务意图
                      <input
                        required
                        value={route.intent}
                        onChange={(event) =>
                          updateScenario(index, { intent: event.target.value })
                        }
                        placeholder="jenkins.build"
                        spellCheck={false}
                      />
                    </label>
                    <label>
                      能力 ID
                      <input
                        required
                        value={route.capability}
                        onChange={(event) =>
                          updateScenario(index, {
                            capability: event.target.value,
                          })
                        }
                        placeholder="jenkins.build.test"
                        spellCheck={false}
                      />
                    </label>
                  </div>
                  <label>
                    适用服务
                    <input
                      value={route.services.join(", ")}
                      onChange={(event) =>
                        updateScenario(index, {
                          services: event.target.value
                            .split(",")
                            .map((value) => value.trim())
                            .filter(Boolean),
                        })
                      }
                      placeholder="xxx-service, web-*；留空表示不限服务"
                      spellCheck={false}
                    />
                  </label>
                  <footer>
                    <span className="small-text muted">
                      环境来自上方连接信息；多条命中时 AI 必须补充上下文。
                    </span>
                    <button
                      className="text-button danger-text"
                      type="button"
                      onClick={() =>
                        setDetails((draft) => ({
                          ...draft,
                          scenarios: (draft.scenarios || []).filter(
                            (_, routeIndex) => routeIndex !== index,
                          ),
                        }))
                      }
                    >
                      移除
                    </button>
                  </footer>
                </article>
              ))}
            </div>
          ) : (
            <p className="small-text muted">
              未配置时，AI 只能使用明确指定的连接别名。
            </p>
          )}
        </section>
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
            {action.busy ? "保存中…" : "保存修改"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function LoginDialog({
  site,
  onClose,
  onSaved,
}: {
  site: SiteSummary;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const [mode, setMode] = useState<"browser" | "oauth">(site.auth_type === "authflow" ? "oauth" : "browser");
  const [login, setLogin] = useState<LoginWindow | null>(null);
  const [session, setSession] = useState<AuthSession | null>(null);
  const [complete, setComplete] = useState(false);

  const action = useAction();
  const closed = useRef(false);
  const resources = useRef<{
    login: LoginWindow | null;
    session: AuthSession | null;
  }>({ login: null, session: null });
  useEffect(() => {
    resources.current = { login, session };
  }, [login, session]);
  useEffect(
    () => () => {
      closed.current = true;
      const current = resources.current;
      if (current.login)
        void call("close_login_window", { label: current.login.label }).catch(
          () => undefined,
        );
      if (current.session)
        void call("authflow_cancel", {
          sessionId: current.session.session_id,
        }).catch(() => undefined);
    },
    [],
  );
  async function start() {
    await action.run(async () => {
      if (mode === "oauth") {
        const next = await call<AuthSession>("authflow_begin", {
          alias: site.alias,
          siteUrl: site.site_url,
        });
        resources.current.session = next;
        setSession(next);
        const result = await call<ConnectionCheck>("authflow_complete", {
          sessionId: next.session_id,
          alias: site.alias,
        });
        if (closed.current) return;
        setComplete(true);
        action.setMessage(result.message || "登录验证完成。");
        await onSaved();
      } else {
        const next = await call<LoginWindow>("open_login_window", {
          alias: site.alias,
          siteUrl: site.site_url,
        });
        resources.current.login = next;
        setLogin(next);
      }
    });
  }
  async function finish() {
    await action.run(async () => {
      if (session) {
        const result = await call<ConnectionCheck>("authflow_complete", {
          sessionId: session.session_id,
          alias: site.alias,
        });
        action.setMessage(result.message || "登录验证完成。");
      } else if (login) {
        const capture = await call<LoginCapture>("login_capture_cookies", {
          alias: site.alias,
          label: login.label,
          siteUrl: site.site_url,
        });
        if (!capture.saved)
          throw new Error("未获取到可保存的会话，请确认已经完成登录。");
        action.setMessage(
            ["authflow", "e10"].includes(site.auth_type)
              ? "登录成功，身份检查已通过。"
            : `已保存 ${capture.cookie_count} 个 Cookie，尚未验证业务访问权限。`,
        );
      }
      setComplete(true);
      await onSaved();
    });
  }
  function close() {
    if (!action.busy || session) onClose();
  }
  return (
    <Modal
      title={`连接 ${site.name || site.alias}`}
      subtitle={site.site_url}
      onClose={close}
    >
      {!login && !session && site.auth_type === "authflow" && (
        <div className="stack-form">
          <label>
            登录方式
            <select
              value={mode}
              onChange={(event) =>
                setMode(event.target.value as "browser" | "oauth")
              }
            >
              <option value="browser">独立 WebView2 登录窗口</option>
              <option value="oauth">浏览器授权回调</option>
            </select>
          </label>

        </div>
      )}
      <ol className="login-steps">
        <li className={login || session ? "done" : "current"}>
          <span>1</span>
          <div>
            <strong>打开专属登录窗口</strong>
            <p>账号之间独立保存浏览器会话。</p>
          </div>
        </li>
        <li className={login || session ? (complete ? "done" : "current") : ""}>
          <span>2</span>
          <div>
            <strong>在窗口中完成登录</strong>
            <p>完成密码、验证码或企业身份验证。</p>
          </div>
        </li>
        <li className={complete ? "done" : ""}>
          <span>3</span>
          <div>
            <strong>
              {["authflow", "e10"].includes(site.auth_type) ? "保存并检查身份" : "保存 Cookie 会话"}
            </strong>
            <p>会话写入本机保险库，登录信息不返回 AI。</p>
          </div>
        </li>
      </ol>
      {session?.user_code && <div className="info-box"><p>在授权页面输入设备码：<strong>{session.user_code}</strong></p></div>}
      {session && action.busy && (
        <div className="info-box">
          <Icon name="globe" />
          <p>
            正在等待浏览器授权回调。完成登录后将自动检查身份，也可随时取消。
          </p>
        </div>
      )}
      <Notice error={action.error} message={action.message} />
      <div className="modal-actions">
        <button
          className="button"
          onClick={close}
          disabled={action.busy && !session}
        >
          {complete ? "完成" : "取消"}
        </button>
        {!complete && (
          <button
            className="button primary"
            disabled={action.busy}
            onClick={() => void (login || session ? finish() : start())}
          >
            {action.busy
              ? session
                ? "等待授权回调…"
                : "处理中…"
              : login || session
                ? "已完成登录，保存并检查"
                : "打开登录窗口"}
          </button>
        )}
      </div>
    </Modal>
  );
}
