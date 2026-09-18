import {
  AllowRule,
  Client,
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
  if (site.auth_type === "login")
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
export function accountLabel(site: SiteSummary) {
  const details = siteDetails(site);
  return [details.account || "未填写账号", details.environment]
    .filter(Boolean)
    .join(" · ");
}
