import {
  ApprovalSummary,
  AssistanceRequest,
  AuditEntry,
  Client,
  ConnectionStatus,
  DimensionStatus,
  HarnessSummary,
  SiteSummary,
  VaultStatus,
} from "./api";

// Explicit browser-only, read-only visual preview. No credentials or live connection data.
const date = "2026-09-15T09:36:00+08:00";

const dim = (
  state: string,
  label: string,
  detail: string,
  extra?: Partial<DimensionStatus>,
): DimensionStatus => ({ state, label, detail, ...extra });

/** Synthetic status dimensions so the preview shows the contract honestly. */
const status = (alias: string, patch: Partial<ConnectionStatus>): ConnectionStatus => ({
  alias,
  credential: dim("saved", "已保存", "凭据已加密保存在本机保险库。"),
  identity: dim("unchecked", "尚未检查", "还没有用远端只读接口验证过此账号身份。"),
  api: dim("not_granted", "未授权 AI", "还没有任何 AI 客户端被允许使用此连接。"),
  web: dim("not_available", "尚未接入", "AI 网页操作通道尚未提供；已保存的登录会话仅供接口调用。"),
  clients: dim("none", "未授权", "没有客户端被允许使用此连接。"),
  ...patch,
});

export const previewData: {
  status: VaultStatus;
  sites: SiteSummary[];
  harnesses: HarnessSummary[];
  clients: Client[];
  approvals: ApprovalSummary[];
  assistance: AssistanceRequest[];
  entries: AuditEntry[];
} = {
  status: {
    home: "",
    initialized: true,
    unlocked: true,
    management_locked: false,
    service_running: true,
    service_paused: false,
    pending_approvals: 1,
    hello_available: false,
    ai_proxy: {
      state: "ready",
      address: "",
      managed: true,
      detail: "合成数据预览",
    },
  },
  sites: [
    {
      id: "sample-github",
      alias: "github",
      name: "GitHub",
      site_url: "https://api.github.com",
      auth_type: "api_token",
      tags: [],
      details: {
        account: "alex-dev",
        environment: "个人",
        favorite: true,
        ai_enabled: true,
      },
      created_at: date,
      updated_at: date,
      last_used_at: date,
      status: "active",
      dimensions: status("github", {
        api: dim("unchecked", "尚未检查", "已授权，但还没有通过本机代理验证或真实调用记录。"),
        clients: dim("granted", "1 个客户端已授权", "授权持续到撤销；拒绝规则继续生效。"),
      }),
    },
    {
      id: "sample-notion",
      alias: "notion",
      name: "Notion",
      site_url: "https://notion.example.test",
      auth_type: "login",
      tags: [],
      details: { account: "个人空间", ai_enabled: true },
      created_at: date,
      updated_at: date,
      status: "expired",
      dimensions: status("notion", {
        credential: dim(
          "expired",
          "需重新登录",
          "凭据有效期已过，需要重新验证。",
          { error_code: "session_expired", recovery: "重新登录或更新凭据" },
        ),
      }),
    },
    {
      id: "sample-e10",
      alias: "e10-test",
      name: "E10 测试环境",
      site_url: "https://e10.example.test",
      auth_type: "e10",
      purpose: "前端调试与国际化接口。",
      tags: [],
      details: {
        account: "developer@example.test",
        environment: "测试",
        group: "工作",
        tenant: "演示租户",
        favorite: true,
        ai_enabled: true,
      },
      created_at: date,
      updated_at: date,
      last_used_at: date,
      last_checked_at: date,
      status: "connected",
      dimensions: status("e10-test", {
        identity: dim("verified", "身份已验证", "远端确认账号身份：developer@example.test。", {
          checked_at: date,
        }),
        api: dim("ready", "本机检查通过", "通过本机代理的只读检查请求成功返回。", {
          checked_at: date,
        }),
        clients: dim("granted", "1 个客户端已授权", "授权持续到撤销；拒绝规则继续生效。"),
      }),
    },
    {
      id: "sample-git",
      alias: "gitlab",
      name: "GitLab",
      site_url: "https://git.example.test",
      auth_type: "api_token",
      tags: [],
      details: {
        account: "developer",
        environment: "工作",
        group: "工作",
        favorite: true,
        ai_enabled: true,
      },
      created_at: date,
      updated_at: date,
      last_used_at: date,
      status: "active",
      dimensions: status("gitlab", {
        api: dim("ready", "最近调用正常", "最近真实 AI 调用（GET /api/v4/projects）返回 200。", {
          checked_at: date,
        }),
        clients: dim("granted", "1 个客户端已授权", "授权持续到撤销；拒绝规则继续生效。"),
      }),
    },
    {
      id: "sample-work",
      alias: "work-mail",
      name: "工作邮箱",
      site_url: "https://mail.example.test",
      auth_type: "password",
      tags: [],
      details: {
        account: "hello@example.test",
        environment: "个人",
        group: "个人",
        ai_enabled: false,
      },
      created_at: date,
      updated_at: date,
      status: "active",
      dimensions: status("work-mail", {
        identity: dim("not_available", "不适用", "个人密码不做身份验证。"),
        api: dim("not_available", "不开放", "普通密码不向 AI 开放。"),
        clients: dim("not_available", "不适用", "个人密码不做客户端授权。"),
      }),
    },
    {
      id: "sample-prod",
      alias: "e10-prod",
      name: "E10 生产环境",
      site_url: "https://production.example.test",
      auth_type: "e10",
      tags: [],
      details: {
        account: "developer@example.test",
        environment: "生产",
        group: "工作",
        ai_enabled: false,
      },
      created_at: date,
      updated_at: date,
      status: "expired",
      dimensions: status("e10-prod", {
        credential: dim(
          "expired",
          "需重新登录",
          "凭据有效期已过，需要重新验证。",
          { error_code: "session_expired", recovery: "重新登录或更新凭据" },
        ),
      }),
    },
  ],
  clients: [
    {
      id: "sample-claude",
      name: "Claude Code",
      kind: "claude",
      harness: "claude",
      paired: true,
      created_at: date,
    },
    {
      id: "sample-codex",
      name: "Codex",
      kind: "codex",
      harness: "codex",
      paired: true,
      created_at: date,
      last_used_at: date,
    },
  ],
  harnesses: [
    {
      name: "codex",
      created_at: date,
      policy: {
        default_action: "deny",
        allow: [
          {
            site: "github",
            methods: [
              "GET",
              "POST",
              "PUT",
              "PATCH",
              "DELETE",
              "HEAD",
              "OPTIONS",
            ],
            paths: ["/**"],
            require_approval: false,
          },
          {
            site: "e10-test",
            methods: ["GET"],
            paths: ["/api/ebuilder/**"],
            operation: "query",
          },
          {
            site: "gitlab",
            methods: ["GET"],
            paths: ["/api/v4/**"],
            operation: "query",
          },
        ],
      },
    },
  ],
  assistance: [
    {
      id: "sample-access",
      client_id: "sample-codex",
      harness: "codex",
      site: "gitlab",
      kind: "access",
      requested_scope: {
        method: "POST",
        path: "/api/v4/projects/42/issues",
        operation: "write",
      },
      reason: "为演示项目创建问题记录",
      status: "pending",
      created_at: date,
      updated_at: date,
    },
  ],
  approvals: [
    {
      id: "sample-request",
      ts: date,
      harness: "codex",
      site: "e10-test",
      method: "POST",
      path: "/api/ebuilder/label",
      payload: { body: { label: "示例词条" } },
      status: "pending",
    },
  ],
  entries: [
    {
      id: 1,
      ts: date,
      harness: "codex",
      site: "gitlab",
      method: "GET",
      path: "/api/v4/projects",
      status_code: 200,
      resp_bytes: 2064,
      redactions: 1,
      truncated: false,
      approved: false,
    },
    {
      id: 2,
      ts: date,
      harness: "codex",
      site: "e10-test",
      method: "POST",
      path: "/api/ebuilder/label",
      status_code: 403,
      resp_bytes: 0,
      redactions: 0,
      truncated: false,
      approved: false,
      note: "pending_approval",
    },
  ],
};
