import assert from "node:assert/strict";
import { test } from "node:test";
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { build } from "esbuild";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server.js";

const require = createRequire(import.meta.url);
const compiled = new Map();

/** In-memory module isolation only. No browser automation, live vault or injected production API. */
async function load(entry, search = "", native = false) {
  if (!compiled.has(entry)) {
    const result = await build({
      entryPoints: [fileURLToPath(new URL(entry, import.meta.url))],
      bundle: true,
      platform: "node",
      format: "cjs",
      write: false,
      external: [
        "react",
        "react-dom",
        "@tauri-apps/api/core",
        "@tauri-apps/api/event",
      ],
    });
    compiled.set(entry, result.outputFiles[0].text);
  }
  let invoked = 0;
  const module = { exports: {} };
  const context = vm.createContext({
    module,
    exports: module.exports,
    URLSearchParams,
    URL,
    window: {
      location: { search },
      ...(native ? { __TAURI_INTERNALS__: {} } : {}),
    },
    require(name) {
      if (name === "@tauri-apps/api/core")
        return {
          invoke: async () => {
            invoked += 1;
            throw new Error("Unexpected native call in render test");
          },
        };
      if (name === "@tauri-apps/api/event")
        return { listen: async () => () => {} };
      return require(name);
    },
  });
  vm.runInContext(compiled.get(entry), context);
  return { exports: module.exports, calls: () => invoked };
}

test("ordinary browser page does not silently pretend to be a live workbench", async () => {
  const loaded = await load("./App.tsx");
  const html = renderToStaticMarkup(
    React.createElement(loaded.exports.default),
  );
  assert.match(html, /打开 pman 桌面工作台/);
  assert.doesNotMatch(html, /developer@example\.test/);
  assert.equal(loaded.calls(), 0);
});

test("connection bookshelf renders without inventing browser or API verification", async () => {
  const loaded = await load("./App.tsx", "?preview=1");
  const html = renderToStaticMarkup(
    React.createElement(loaded.exports.default),
  );
  assert.match(html, /连接书架/);
  assert.match(html, /最近使用/);
  assert.match(html, /添加连接/);
  assert.match(html, /AI 工具/);
  assert.doesNotMatch(html, /网页可用/);
  assert.equal(loaded.calls(), 0);
});

test("whole connection labels exclude partial, expired and conditional rules", async () => {
  const { exports: logic } = await load("./connections.ts");
  const rule = {
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    paths: ["/**"],
    require_approval: false,
  };
  assert.equal(logic.wholeConnection(rule), true);
  assert.equal(logic.wholeConnection({ ...rule, methods: ["GET"] }), false);
  assert.equal(logic.wholeConnection({ ...rule, capability: "read" }), false);
  assert.equal(
    logic.wholeConnection({ ...rule, expires_at: "invalid" }),
    false,
  );
  assert.equal(
    logic.wholeConnection({ ...rule, require_approval: true }),
    false,
  );
  assert.equal(
    logic.wholeConnection({
      ...rule,
      constraints: { query: { tenant: ["one"] } },
    }),
    false,
  );
});

test("saved credentials and paired clients are not presented as verified usage", async () => {
  const { exports: logic } = await load("./connections.ts");
  assert.equal(
    logic.connectionAbility({ auth_type: "api_token", status: "active" }).text,
    "凭据已保存",
  );
  assert.equal(
    logic.connectionAbility({ auth_type: "login", status: "active" }).text,
    "会话已保存",
  );
  assert.equal(
    logic.clientActive({ paired: true, revoked_at: "2020-01-01" }),
    false,
  );
  assert.equal(
    logic.clientActive({ paired: true, expires_at: "invalid" }),
    false,
  );
  assert.equal(logic.clientActive({ paired: true }), true);
});

const noop = async () => {};

test("status dimensions render separate evidence and never a merged connected", async () => {
  const loaded = await load("./ConnectionLibrary.tsx");
  const html = renderToStaticMarkup(
    React.createElement(loaded.exports.StatusPanel, {
      site: { alias: "api", auth_type: "api_token", site_url: "https://api.github.com", tags: [] },
      busy: false,
      onCheck: noop,
      onUpdateDetails: noop,
      dimensions: {
        alias: "api",
        credential: {
          state: "saved",
          label: "已保存",
          detail: "凭据已加密保存在本机保险库。",
        },
        identity: {
          state: "unauthorized",
          label: "身份验证失败(401)",
          detail: "远端拒绝此凭据。",
          error_code: "session_expired",
          recovery: "重新登录或更新凭据",
        },
        api: {
          state: "unchecked",
          label: "尚未检查",
          detail: "已授权，但还没有通过本机代理验证或真实调用记录。",
        },
        web: {
          state: "not_available",
          label: "尚未接入",
          detail: "AI 网页操作通道尚未提供。",
        },
        clients: {
          state: "granted",
          label: "1 个客户端已授权",
          detail: "授权持续到撤销；拒绝规则继续生效。",
        },
      },
    }),
  );
  assert.match(html, /状态明细/);
  assert.match(html, /已保存/);
  assert.match(html, /身份验证失败\(401\)/);
  assert.match(html, /重新登录或更新凭据/);
  assert.match(html, /尚未检查/);
  assert.match(html, /尚未接入/);
  assert.doesNotMatch(html, /<i><\/i>已连接/);
});

test("missing status evidence always shows 尚未检查 instead of assumed health", async () => {
  const loaded = await load("./ConnectionLibrary.tsx");
  const empty = renderToStaticMarkup(
    React.createElement(loaded.exports.StatusPanel, {
      site: { alias: "api", auth_type: "api_token", site_url: "https://api.example.test", tags: [] },
      busy: false,
      onCheck: noop,
      onUpdateDetails: noop,
    }),
  );
  assert.match(empty, /尚未检查/);
  assert.doesNotMatch(empty, /已验证|检查通过|badge success/);
});

test("personal passwords and E10 connections never offer the generic API check", async () => {
  const loaded = await load("./ConnectionLibrary.tsx");
  const html = (authType) =>
    renderToStaticMarkup(
      React.createElement(loaded.exports.StatusPanel, {
        site: { alias: "x", auth_type: authType, site_url: "", tags: [] },
        busy: false,
        onCheck: noop,
        onUpdateDetails: noop,
      }),
    );
  assert.doesNotMatch(html("password"), /检查连接/);
  assert.doesNotMatch(html("e10"), /检查连接/);
  assert.match(html("api_token"), /检查连接/);
  assert.match(html("api_token"), /检查与 OAuth 设置/);
});

test("invalid or revoked client grants stay visibly broken until repaired", async () => {
  const { exports: logic } = await load("./connections.ts");
  const broken = logic.dimensionSummary({
    state: "client_invalid",
    label: "客户端已失效",
    detail: "已授权的客户端都已撤销或过期。",
    recovery: "重新配对客户端后再次授权",
  });
  assert.equal(broken.tone, "warning");
  assert.equal(broken.recovery, "重新配对客户端后再次授权");
  assert.equal(logic.dimensionTone("stale"), "warning");
  assert.equal(logic.dimensionTone("network_error"), "danger");
});

test("error codes map to stable recovery actions without credential text", async () => {
  const loaded = await load("./api.ts");
  assert.equal(
    loaded.exports.errorCodeInfo("session_expired").action,
    "重新登录或更新凭据。",
  );
  assert.equal(
    loaded.exports.errorCodeInfo("management_locked").text,
    "管理界面已锁定",
  );
  assert.equal(loaded.exports.errorCodeInfo("mystery_code").text, "状态未知");
});

test("connection summaries retain legacy default-allow policies but omit revoked policies", async () => {
  const { exports: logic } = await load("./connections.ts");
  const site = { alias: "api" };
  const profiles = [
    { name: "legacy", policy: { default_action: "allow" } },
    {
      name: "revoked",
      revoked_at: "2020-01-01",
      policy: { default_action: "allow" },
    },
    {
      name: "expired",
      expires_at: "2020-01-01",
      policy: { allow: [{ site: "api" }] },
    },
  ];
  assert.equal(logic.connectionGrants(site, profiles).length, 1);
  assert.equal(logic.connectionGrants(site, profiles)[0].name, "legacy");
});

test("management lock preserves the AI running state and hides account metadata", async () => {
  const loaded = await load("./App.tsx", "?preview=1&state=locked");
  const html = renderToStaticMarkup(
    React.createElement(loaded.exports.default),
  );
  assert.match(html, /管理界面已锁定/);
  assert.match(html, /AI 服务继续运行/);
  assert.doesNotMatch(html, /developer@example\.test/);
  assert.doesNotMatch(html, /验证并恢复 AI 服务/);
  assert.equal(loaded.calls(), 0);
});

test("explicit pause has a separate restore action and persistent-pause explanation", async () => {
  const loaded = await load("./App.tsx", "?preview=1&state=paused");
  const html = renderToStaticMarkup(
    React.createElement(loaded.exports.default),
  );
  assert.match(html, /AI 服务已由你暂停/);
  assert.match(html, /重启后也不会自动恢复/);
  assert.match(html, /验证并恢复 AI 服务/);
  assert.doesNotMatch(html, /AI 服务继续运行/);
  assert.equal(loaded.calls(), 0);
});

test("Tauri runtime cannot enable synthetic unlocked state through preview query", async () => {
  const loaded = await load("./App.tsx", "?preview=1", true);
  const html = renderToStaticMarkup(
    React.createElement(loaded.exports.default),
  );
  assert.match(html, /正在连接本机服务/);
  assert.doesNotMatch(html, /developer@example\.test|合成数据预览/);
  assert.equal(loaded.calls(), 0);
});

test("no native transport means credential calls reject before invoke", async () => {
  const loaded = await load("./api.ts");
  await assert.rejects(
    loaded.exports.call("site_reveal", { alias: "synthetic-only" }),
    /浏览器预览不会连接保险库/,
  );
  assert.equal(loaded.calls(), 0);
});

test("pending approvals offer both one-shot and persistent consent", async () => {
  const source = await readFile(new URL("./App.tsx", import.meta.url), "utf8");
  assert.match(source, /仅批准本次/);
  assert.match(source, /永久同意/);
  assert.match(source, /persistent:\s*mode === "persistent"/);
  assert.match(source, /可随时在 AI 访问中撤销/);
});

test("settings displays the runtime application version without hardcoding it", async () => {
  const source = await readFile(
    new URL("./Settings.tsx", import.meta.url),
    "utf8",
  );
  assert.match(source, /import \{ getVersion \} from "@tauri-apps\/api\/app"/);
  assert.match(source, /getVersion\(\)/);
  assert.match(source, /版本 \{appVersion \?\? "—"\}/);
  assert.doesNotMatch(source, /版本 0\.4\.1/);
});

test("login state does not falsely label stored tokens as connected", async () => {
  const loaded = await load("./api.ts");
  const status = loaded.exports.statusLabel;
  assert.equal(
    status({ auth_type: "api_token", status: "active" }).text,
    "已保存",
  );
  assert.equal(status({ auth_type: "login", status: "active" }).text, "待检查");
  assert.equal(
    status({ auth_type: "e10", status: "connected" }).text,
    "已连接",
  );
  assert.equal(
    status({ auth_type: "e10", status: "forbidden" }).text,
    "权限不足",
  );
  assert.equal(
    status({ auth_type: "e10", status: "network_error" }).text,
    "网络异常",
  );
  assert.equal(
    status({
      auth_type: "password",
      status: "active",
      expires_at: "2000-01-01T00:00:00Z",
    }).text,
    "已过期",
  );
});

test("recovery affordances: batch consent, named failures and delete impact", async () => {
  const source = await readFile(
    new URL("./ConnectionLibrary.tsx", import.meta.url),
    "utf8",
  );
  assert.match(source, /清除选择/);
  assert.match(source, /全选/);
  assert.match(source, /以下客户端已失效，本次授权未保存/);
  assert.match(source, /正在进行的网页会话被关闭/);
  assert.match(source, /授权规则被撤销/);
  // The refresh retry affordance lives on the workbench level.
  const app = await readFile(new URL("./App.tsx", import.meta.url), "utf8");
  assert.match(app, /重试刷新/);
});

test("oauth login presents real flows and never fakes success", async () => {
  const source = await readFile(
    new URL("./ConnectionLibrary.tsx", import.meta.url),
    "utf8",
  );
  // The dialog waits for the provider; it does not claim success up front.
  assert.match(source, /等待提供方确认授权/);
  assert.match(source, /oauth_complete/);
  assert.match(source, /oauth_cancel/);
  // The wizard discloses that OAuth needs a registered client_id and the
  // Token path stays available; unconfigured connections show no login button.
  assert.match(source, /需要在 \{template\.title\}/);
  assert.match(source, /oauth_client_id && \(/);
  assert.match(source, /未配置时继续使用 Token/);
  const { exports: logic } = await load("./connections.ts");
  assert.equal(
    logic.connectionProvider({
      site_url: "https://api.github.com",
      tags: [],
    }),
    "github",
  );
  assert.equal(
    logic.connectionProvider({
      site_url: "https://gitlab.example.test",
      tags: [],
    }),
    null,
  );
});

test("both themes meet 4.5:1 text contrast on their defined surfaces", async () => {
  const css = await readFile(new URL("./styles.css", import.meta.url), "utf8");
  const declarations = css
    .match(/:root(?:\[data-theme="light"\])?\s*\{[^}]+\}/g)
    .filter((block) => block.includes("--bg:"));
  assert.equal(declarations.length, 2);
  const luminance = (hex) => {
    const rgb = hex.match(/\w{2}/g).map((value) => parseInt(value, 16) / 255);
    return rgb
      .map((value) =>
        value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4,
      )
      .reduce(
        (sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index],
        0,
      );
  };
  for (const declaration of declarations) {
    const tokens = Object.fromEntries(
      [...declaration.matchAll(/--([a-z-]+):\s*#([a-f0-9]{6});/g)].map(
        (match) => [match[1], match[2]],
      ),
    );
    const pairs = [
      ...["bg", "sidebar", "surface", "raised", "hover", "selection"].flatMap(
        (background) =>
          ["text", "muted", "accent"].map((foreground) => [
            foreground,
            background,
          ]),
      ),
      ["subtle", "bg"],
      ["subtle", "sidebar"],
      ["subtle", "raised"],
      ["subtle", "surface"],
      ["accent-ink", "accent"],
      ["warning", "warning-bg"],
      ["danger", "danger-bg"],
    ];
    for (const [foreground, background] of pairs) {
      const first = luminance(tokens[foreground]);
      const second = luminance(tokens[background]);
      const ratio =
        (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
      assert.ok(
        ratio >= 4.5,
        `${declaration.includes("light") ? "Light" : "Dark"} ${foreground} on ${background}: ${ratio.toFixed(2)}:1`,
      );
    }
  }
});
