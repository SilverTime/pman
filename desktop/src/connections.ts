import {
  AllowRule,
  Client,
  DimensionStatus,
  HarnessSummary,
  SiteSummary,
  siteDetails,
  statusLabel,
} from "./api";

const methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
export const expired = (value?: string | null) =>
  Boolean(
    value &&
      (!Number.isFinite(Date.parse(value)) || Date.parse(value) <= Date.now()),
  );
export const clientActive = (client: Client) =>
  client.paired && !client.revoked_at && !expired(client.expires_at);
export const harnessActive = (harness: HarnessSummary) =>
  !harness.revoked_at && !expired(harness.expires_at);
export function wholeConnection(rule: AllowRule) {
  return (
    !rule.capability &&
    !Object.values(rule.constraints || {}).some(
      (value) => Object.keys(value).length,
    ) &&
    !expired(rule.expires_at) &&
    rule.require_approval === false &&
    methods.every((method) =>
      rule.methods?.some((item) => item.toUpperCase() === method),
    ) &&
    (!rule.paths?.length || rule.paths.includes("/**"))
  );
}
export function connectionGrants(
  site: SiteSummary,
  harnesses: HarnessSummary[],
) {
  return harnesses.filter(
    (harness) =>
      harnessActive(harness) &&
      (harness.policy.default_action === "allow" ||
        harness.policy.allow?.some(
          (rule) => rule.site === site.alias && !expired(rule.expires_at),
        )),
  );
}
export function needsAttention(site: SiteSummary) {
  return (
    ["warning", "danger"].includes(statusLabel(site).tone) ||
    ["pending", "inactive"].includes(site.status)
  );
}
export function connectionAbility(site: SiteSummary) {
  const status = statusLabel(site);
  if (site.auth_type === "password")
    return {
      text: "仅本人使用",
      tone: "neutral",
      detail: "普通密码不作为 AI 连接使用。",
    };
  if (needsAttention(site))
    return { ...status, detail: "请先处理账号状态，再检查业务访问。" };
  if (["connected", "authenticated"].includes(site.status))
    return {
      text: "身份已验证",
      tone: "success",
      detail: "账号验证已通过；具体操作仍受服务端权限限制。",
    };
  if (["login", "e10"].includes(site.auth_type))
    return {
      text: "会话已保存",
      tone: "neutral",
      detail: "已保存登录会话，业务访问尚待验证。",
    };
  return {
    text: "凭据已保存",
    tone: "neutral",
    detail: "已保存接口凭据，实际访问权限以请求结果为准。",
  };
}
export function connectionHost(site: SiteSummary) {
  try {
    return new URL(site.site_url).host;
  } catch {
    return "本机保存";
  }
}
/** OAuth-capable preset providers. Gitee is deliberately absent: it is a
 * token-only provider (its official exchange requires a client secret). */
export type ConnectionProvider =
  | "github"
  | "gitlab"
  | "microsoft"
  | "google"
  | "e10";
/** Mirrors the native provider detection in check.rs / oauth_login.rs. */
export function connectionProvider(site: SiteSummary): ConnectionProvider | null {
  const details = siteDetails(site);
  if (site.auth_type === "e10" || details.provider === "e10") return "e10";
  if (
    details.provider === "github" ||
    details.provider === "gitlab" ||
    details.provider === "microsoft" ||
    details.provider === "google"
  )
    return details.provider;
  try {
    const host = new URL(site.site_url).hostname.toLowerCase();
    if (host === "api.github.com") return "github";
    if (host === "gitlab.com" || host === "www.gitlab.com" || host.endsWith(".gitlab.com"))
      return "gitlab";
    if (host === "graph.microsoft.com") return "microsoft";
    if (host === "www.googleapis.com" || host.endsWith(".googleapis.com"))
      return "google";
  } catch {
    return null;
  }
  return null;
}
/** Badge tone for a status-dimension state. Unknown states stay cautious. */
export function dimensionTone(state: string): string {
  switch (state) {
    case "verified":
    case "ready":
    case "granted":
    case "saved":
      return "success";
    case "unchecked":
    case "none":
    case "not_available":
    case "not_granted":
      return "neutral";
    case "stale":
    case "expired":
    case "unauthorized":
    case "forbidden":
    case "rate_limited":
    case "restricted":
    case "paused":
    case "invalid":
    case "client_invalid":
      return "warning";
    default:
      return "danger";
  }
}
export type DimensionKey = "credential" | "identity" | "api" | "web" | "clients";
export const statusDimensions: { key: DimensionKey; name: string }[] = [
  { key: "credential", name: "凭据保存" },
  { key: "identity", name: "身份验证" },
  { key: "api", name: "接口可用性" },
  { key: "clients", name: "客户端授权" },
  { key: "web", name: "网页操作" },
];
export function dimensionSummary(
  dimension?: DimensionStatus,
): {
  label: string;
  tone: string;
  detail: string;
  checked_at?: string;
  error_code?: string;
  recovery?: string;
} {
  if (!dimension)
    return {
      label: "尚未检查",
      tone: "neutral",
      detail: "还没有可用的状态信息。",
    };
  return {
    label: dimension.label,
    tone: dimensionTone(dimension.state),
    detail: dimension.detail,
    checked_at: dimension.checked_at,
    error_code: dimension.error_code,
    recovery: dimension.recovery,
  };
}
export function accountLabel(site: SiteSummary) {
  const details = siteDetails(site);
  return [details.account || "未填写账号", details.environment]
    .filter(Boolean)
    .join(" · ");
}
