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
