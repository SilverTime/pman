import { invoke } from "@tauri-apps/api/core";

export type Route = "credentials" | "access" | "activity" | "settings";
export type AuthType =
  "password" | "api_token" | "http_basic" | "cookie_jar" | "login" | "e10";
export type EntryKind =
  "password" | "api_token" | "http_basic" | "cookie_jar" | "login" | "e10";
export type VaultStatus = {
  home: string;
  initialized: boolean;
  unlocked: boolean;
  management_locked: boolean;
  service_running: boolean;
  service_paused: boolean;
  pending_approvals: number;
  hello_available: boolean;
  ai_proxy: {
    state: string;
    address: string;
    managed: boolean;
    detail: string;
  };
};
export type SiteDetails = {
  group?: string;
  favorite?: boolean;
  account?: string;
  environment?: string;
  tenant?: string;
  notes?: string;
  ai_enabled?: boolean;
  scenarios?: ScenarioRoute[];
};
export type ScenarioRoute = {
  intent: string;
  capability: string;
  services: string[];
  selectors: Record<string, string[]>;
};
export type SiteSummary = {
  id: string;
  alias: string;
  name?: string | null;
  site_url: string;
  auth_type: AuthType;
  purpose?: string | null;
  tags: string[];
  details?: SiteDetails;
  created_at: string;
  updated_at: string;
  last_used_at?: string | null;
  last_checked_at?: string | null;
  expires_at?: string | null;
  status: string;
};
export type SiteInput = {
  alias: string;
  site_url: string;
  auth_type: AuthType;
  secret: Record<string, unknown>;
  name?: string | null;
  purpose?: string | null;
  tags: string[];
  details?: SiteDetails;
};
export type AllowRule = {
  site: string;
  methods?: string[];
  paths?: string[];
  expires_at?: string;
  operation?: string;
  capability?: string;
  constraints?: Record<string, Record<string, string[]>>;
};
export type HarnessSummary = {
  name: string;
  policy: {
    allow?: AllowRule[];
    deny?: AllowRule[];
    default_action?: string;
    [key: string]: unknown;
  };
  created_at: string;
  expires_at?: string | null;
  revoked_at?: string | null;
};
export type ClientKind = "codex" | "claude" | "generic";
export type Client = {
  id: string;
  name: string;
  kind: ClientKind;
  harness: string;
  paired: boolean;
  created_at: string;
  last_used_at?: string | null;
  revoked_at?: string | null;
};
export type ConfigPreview = { path: string; content: string; exists: boolean };
export type ApprovalSummary = {
  id: string;
  ts: string;
  harness: string;
  site: string;
  method: string;
  path: string;
  payload: Record<string, unknown>;
  status: string;
  decided_at?: string | null;
};
export type RequestedScope = {
  method: string;
  path: string;
  operation: "query" | "write";
};
export type AssistanceRequest = {
  id: string;
  client_id: string;
  harness: string;
  site: string;
  kind: "login" | "access";
  requested_scope?: RequestedScope | null;
  reason?: string;
  status: string;
  created_at: string;
  updated_at: string;
};
export type AuditEntry = {
  id: number;
  ts: string;
  harness: string;
  site?: string | null;
  method?: string | null;
  path?: string | null;
  status_code?: number | null;
  resp_bytes: number;
  redactions: number;
  truncated: boolean;
  approved: boolean;
  req_id?: string | null;
  note?: string | null;
};
export type Settings = {
  autostart: boolean;
  idle_lock_minutes: number;
  theme: "dark" | "light";
  reduced_motion: boolean;
  hello_enabled: boolean;
  legacy_http_enabled?: boolean;
};
export type LoginWindow = { label: string; url: string };
export type LoginCapture = {
  alias: string;
  cookie_count: number;
  cookie_names: string[];
  saved: boolean;
};
export type AuthSession = {
  session_id: string;
  authorize_url: string;
  expires_at: string;
  origin: string;
};
export type ConnectionCheck = {
  status: string;
  last_checked_at?: string;
  message?: string;
  account?: string;
  tenant?: string;
};

export const defaultSettings: Settings = {
  autostart: true,
  idle_lock_minutes: 15,
  theme: "dark",
  reduced_motion: false,
  hello_enabled: true,
};
export const nativeAvailable = () => "__TAURI_INTERNALS__" in window;

/** The only desktop IPC entry; never log arguments or failures containing request data. */
export async function call<T = void>(
  command: string,
  args?: Record<string, unknown>,
): Promise<T> {
  if (!nativeAvailable())
    throw new Error(
      "请在 pman 桌面应用中使用此操作。浏览器预览不会连接保险库。",
    );
  return invoke<T>(command, args);
}

export function managementLocked(status: VaultStatus): boolean {
  return status.management_locked ?? !status.unlocked;
}
export function siteDetails(site: SiteSummary): SiteDetails {
  // Existing tags remain readable during metadata migration; new edits use details.
  const tag = (prefix: string) =>
    site.tags
      .find((value) => value.startsWith(`${prefix}:`))
      ?.slice(prefix.length + 1);
  return {
    group: tag("group"),
    account: tag("account"),
    environment: tag("env"),
    favorite: site.tags.includes("favorite"),
    ...site.details,
  };
}
export function typeLabel(type: string): string {
  return (
    (
      {
        password: "密码",
        api_token: "API Token",
        http_basic: "HTTP Basic",
        cookie_jar: "Cookie",
        login: "网站登录",
        e10: "E10",
      } as Record<string, string>
    )[type] || type
  );
}
export function statusLabel(site: SiteSummary): { text: string; tone: string } {
  const login = site.auth_type === "login" || site.auth_type === "e10";
  if (site.expires_at && Date.parse(site.expires_at) < Date.now())
    return { text: login ? "需重新登录" : "已过期", tone: "warning" };
  if (site.expires_at && Date.parse(site.expires_at) < Date.now() + 86400000)
    return { text: "即将过期", tone: "warning" };
  const states: Record<string, { text: string; tone: string }> = {
    connected: { text: "已连接", tone: "success" },
    authenticated: { text: "已连接", tone: "success" },
    expired: { text: "需重新登录", tone: "warning" },
    unauthorized: { text: "需重新登录", tone: "warning" },
    forbidden: { text: "权限不足", tone: "warning" },
    network_error: { text: "网络异常", tone: "danger" },
    error: { text: "连接异常", tone: "danger" },
    pending: { text: "待登录", tone: "neutral" },
    inactive: { text: "已停用", tone: "neutral" },
    revoked: { text: "已撤销", tone: "neutral" },
  };
  if (states[site.status]) return states[site.status];
  if (site.auth_type === "login" || site.auth_type === "e10")
    return { text: "待检查", tone: "neutral" };
  return { text: "已保存", tone: "neutral" };
}
export function timestamp(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString("zh-CN", {
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      });
}
export function errorText(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  if (/invalid master password/i.test(message)) return "主密码不正确，请重试。";
  if (/management.*locked|vault is locked/i.test(message))
    return "管理界面已锁定，请重新验证身份。";
  return message;
}
