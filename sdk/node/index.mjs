import { spawn } from 'node:child_process';
import { join } from 'node:path';

const MAX_OUTPUT = 3 * 1024 * 1024;
const ERROR_TEXT = Object.freeze({
  pending_approval: '请求等待 pman 桌面端审批；批准后重试相同请求。',
  policy_denied: 'pman 授权范围不允许该请求。',
  vault_locked: 'pman AI 服务已暂停；请在桌面端恢复。',
  service_paused: 'pman AI 服务已暂停；请在桌面端恢复。',
  harness_invalid: 'pman 客户端未配对或已撤销；请在桌面端重新配对。',
  client_invalid: 'pman 客户端未配对或已撤销；请在桌面端重新配对。',
  pairing_required: 'pman 客户端未配对；请在桌面端配对。',
  unknown_site: 'pman 中未找到指定连接。',
  site_inactive: 'pman 连接不可用；请在桌面端检查登录状态。',
  rate_limited: 'pman 请求频率超过授权限制。',
  expired: '连接登录已失效；请在 pman 中重新登录。',
  forbidden: '服务拒绝访问；请检查账号权限。',
  origin_mismatch: 'pman 连接地址与目标平台不一致。',
  broker_unavailable: '无法连接 pman AI 服务；请确认桌面程序正在运行。',
  invalid_response: 'pman 返回了不兼容的响应。',
  invalid_request: '请求格式无效。',
  timeout: 'pman 请求超时；写操作结果可能不确定，请检查后再操作。',
  response_blocked: 'pman 已阻止包含凭据的响应。',
  scenario_not_found: '没有已配置的业务场景匹配当前意图和上下文。',
  scenario_ambiguous: '多个连接同时匹配；请补充环境、服务或其他上下文，不能自动选择账号。',
});

export class PmanError extends Error {
  constructor(code, requestId) {
    const safeCode = Object.hasOwn(ERROR_TEXT, code) ? code : 'request_failed';
    super(ERROR_TEXT[safeCode] || 'pman 请求失败，请在桌面端查看活动记录。');
    this.name = 'PmanError';
    this.code = safeCode;
    if (typeof requestId === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(requestId)) this.reqId = requestId;
  }
}

function originOf(value) {
  try {
    const url = new URL(value);
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) return '';
    return url.origin;
  } catch { return ''; }
}

/** No credentials enter this process. The native paired client performs injection. */
export function createPmanClient(options = {}) {
  // A migrated skill never falls through to an unrelated legacy `pm` on PATH.
  const installedExecutable = process.platform === 'win32' && process.env.LOCALAPPDATA
    ? join(process.env.LOCALAPPDATA, 'pman Vault', 'pm.exe') : null;
  const executable = options.executable || process.env.PMAN_EXECUTABLE || installedExecutable;
  const clientId = options.clientId || process.env.PMAN_CLIENT_ID;
  const site = options.site || process.env.PMAN_SITE;
  const expectedOrigin = options.expectedOrigin ? originOf(options.expectedOrigin) : null;
  // Explicit argument prefix supports test launchers. Never interpolated into a shell.
  const executableArgs = options.executableArgs || [];
  if (!clientId) throw new PmanError('pairing_required');
  if (!executable) throw new PmanError('broker_unavailable');
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(clientId) || typeof site !== 'string' || !site.trim()
      || (options.expectedOrigin && !expectedOrigin)) throw new PmanError('invalid_request');

  function invoke(payload) {
    let requestJson;
    try { requestJson = JSON.stringify(payload); }
    catch { return Promise.reject(new PmanError('invalid_request')); }
    return new Promise((resolve, reject) => {
      let child;
      try {
        child = spawn(executable, [...executableArgs, '--client', clientId, '--stdin'], {
          shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'],
        });
      } catch { reject(new PmanError('broker_unavailable')); return; }
      let output = '';
      let bytes = 0;
      let settled = false;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error); else resolve(value);
      };
      const timer = setTimeout(() => {
        child.kill();
        finish(new PmanError('timeout'));
      }, options.timeoutMs || 75_000);
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', chunk => {
        bytes += Buffer.byteLength(chunk);
        if (bytes > MAX_OUTPUT) { child.kill(); finish(new PmanError('invalid_response')); return; }
        output += chunk;
      });
      child.on('error', () => finish(new PmanError('broker_unavailable')));
      child.stdin.on('error', () => finish(new PmanError('broker_unavailable')));
      child.on('close', code => {
        if (settled) return;
        let result;
        try { result = JSON.parse(output); } catch { finish(new PmanError('invalid_response')); return; }
        if (result?.protocol !== 'pman' || result?.protocol_version !== 2 || typeof result.ok !== 'boolean') {
          finish(new PmanError('invalid_response')); return;
        }
        if (!result.ok || result.pending_approval) {
          finish(new PmanError(result.error_code || 'request_failed', result.req_id)); return;
        }
        if (code !== 0) { finish(new PmanError('request_failed')); return; }
        finish(null, result);
      });
      child.stdin.end(requestJson);
    });
  }

  async function getActiveContext() {
    const response = await invoke({ operation: 'active_context', site });
    const context = response.context;
    if (!context || typeof context !== 'object') throw new PmanError('invalid_response');
    const origin = originOf(context.origin || context.site_url || '');
    if (!origin || (expectedOrigin && origin !== expectedOrigin)) throw new PmanError('origin_mismatch');
    const result = { site, origin };
    for (const key of ['auth_type', 'account_id', 'environment_id', 'user_id', 'tenant_key', 'agent_type', 'status', 'checked_at']) {
      if (typeof context[key] === 'string') result[key] = context[key];
    }
    return Object.freeze(result);
  }

  async function request(input) {
    if (!input || typeof input !== 'object' || typeof input.path !== 'string'
        || !input.path.startsWith('/') || input.path.startsWith('//') || /[\\\x00-\x20#]/.test(input.path)
        || input.headers || input.url || (input.site && input.site !== site)) throw new PmanError('invalid_request');
    const method = String(input.method || 'GET').toUpperCase();
    if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)
        || (input.json_body != null && input.form != null)) throw new PmanError('invalid_request');
    // Verify every operation, not just initialization: a human may edit the connection.
    if (expectedOrigin) await getActiveContext();
    const nativeRequest = { site, method, path: input.path };
    if (input.capability != null) {
      if (typeof input.capability !== 'string'
          || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(input.capability)) {
        throw new PmanError('invalid_request');
      }
      nativeRequest.capability = input.capability;
    }
    for (const key of ['query', 'json_body', 'form']) {
      if (input[key] != null) {
        if (typeof input[key] !== 'object' || Array.isArray(input[key])) throw new PmanError('invalid_request');
        nativeRequest[key] = input[key];
      }
    }
    const result = await invoke({ operation: 'http', request: nativeRequest, ...(expectedOrigin ? { expected_origin: expectedOrigin } : {}) });
    if (!Number.isInteger(result.status_code) || result.status_code < 100 || result.status_code > 599) throw new PmanError('invalid_response');
    return Object.freeze({
      status_code: result.status_code,
      headers: result.headers || {},
      body_json: result.body_json ?? null,
      body_text: result.body_text ?? null,
      redactions: result.redactions || 0,
      truncated: result.truncated === true,
    });
  }

  async function resolveScenario(intent, context = {}) {
    if (typeof intent !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(intent)
        || !context || typeof context !== 'object' || Array.isArray(context)
        || Object.values(context).some(value => typeof value !== 'string')) {
      throw new PmanError('invalid_request');
    }
    const result = await invoke({ operation: 'resolve_scenario', intent, context });
    if (result.status === 'ambiguous') throw new PmanError('scenario_ambiguous');
    if (result.status !== 'resolved' || !result.match?.site || !result.match?.capability) {
      throw new PmanError('invalid_response');
    }
    return Object.freeze(result.match);
  }

  return Object.freeze({ getActiveContext, resolveScenario, request });
}

export async function getActiveContext(options) { return createPmanClient(options).getActiveContext(); }
export async function resolveScenario(intent, context, options) { return createPmanClient(options).resolveScenario(intent, context); }
export async function request(input, options) { return createPmanClient(options).request(input); }
