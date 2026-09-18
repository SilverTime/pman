import { getVersion } from "@tauri-apps/api/app";
import { FormEvent, useEffect, useState } from "react";
import { call, Settings, VaultStatus } from "./api";
import { Icon, Modal, Notice, useAction } from "./ui";

export function SettingsPanel({
  settings,
  status,
  onSettings,
  onRefresh,
  onResume,
}: {
  settings: Settings;
  status: VaultStatus;
  onSettings: (settings: Settings) => void;
  onRefresh: () => Promise<void>;
  onResume: () => void;
}) {
  const [draft, setDraft] = useState(settings);
  const [importing, setImporting] = useState(false);
  const [appVersion, setAppVersion] = useState<string | null>(null);
  const action = useAction();
  const dirty = JSON.stringify(draft) !== JSON.stringify(settings);
  const change = <K extends keyof Settings>(key: K, value: Settings[K]) =>
    setDraft((current) => ({ ...current, [key]: value }));
  useEffect(() => {
    let active = true;
    void getVersion()
      .then((version) => {
        if (active) setAppVersion(version);
      })
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, []);
  return (
    <div className="page settings-page">
      <div className="page-heading">
        <div>
          <div className="eyebrow">LOCAL PREFERENCES</div>
          <h1>设置</h1>
          <p>常驻服务、管理验证和本机备份。</p>
        </div>
        {dirty && (
          <button
            className="button primary"
            disabled={action.busy}
            onClick={() =>
              void action.run(async () => {
                await call("settings_update", { settings: draft });
                onSettings(draft);
              }, "设置已保存。")
            }
          >
            保存设置
          </button>
        )}
      </div>
      <Notice error={action.error} message={action.message} />
      <section className="settings-section">
        <header>
          <Icon name="terminal" />
          <div>
            <h2>常驻授权服务</h2>
            <p>锁屏和界面锁定时，AI 继续使用已经获得的授权。</p>
          </div>
        </header>
        <label className="setting-row">
          <span>
            <strong>登录 Windows 后自动启动</strong>
            <small>自动恢复 AI 服务，管理界面保持锁定。</small>
          </span>
          <input
            type="checkbox"
            checked={draft.autostart}
            onChange={(event) => change("autostart", event.target.checked)}
          />
        </label>
        <div className="setting-row">
          <span>
            <strong>
              {status.service_paused
                ? "AI 服务已主动暂停"
                : status.service_running
                  ? "AI 服务正在运行"
                  : "AI 服务未就绪"}
            </strong>
            <small>主动暂停会记住选择，重启后也不会自动开放。</small>
          </span>
          {status.service_paused || !status.service_running ? (
            <button className="button small" onClick={onResume}>
              <Icon name="play" size={15} />
              恢复服务
            </button>
          ) : (
            <button
              className="button small"
              disabled={action.busy}
              onClick={() =>
                void action.run(async () => {
                  await call("service_pause");
                  await onRefresh();
                })
              }
            >
              <Icon name="pause" size={15} />
              暂停 AI 服务
            </button>
          )}
        </div>
      </section>
      <section className="settings-section">
        <header>
          <Icon name="globe" />
          <div>
            <h2>旧版接入兼容</h2>
            <p>已有旧令牌的迁移用户可以继续使用回环 HTTP 入口。</p>
          </div>
        </header>
        <label className="setting-row">
          <span>
            <strong>启用旧版 HTTP 入口</strong>
            <small>
              仅监听 127.0.0.1:9777，下次启动生效；新配对使用原生通道。
            </small>
          </span>
          <input
            type="checkbox"
            checked={draft.legacy_http_enabled || false}
            onChange={(event) =>
              change("legacy_http_enabled", event.target.checked)
            }
          />
        </label>
      </section>
      <section className="settings-section">
        <header>
          <Icon name="lock" />
          <div>
            <h2>管理界面验证</h2>
            <p>查看秘密、修改授权和批准请求时，验证本人身份。</p>
          </div>
        </header>
        <label className="setting-row">
          <span>
            <strong>Windows Hello 快捷验证</strong>
            <small>
              {status.hello_available
                ? "使用 Windows 本机身份验证，主密码始终可用。"
                : "本机暂不支持 Windows Hello，仍可使用主密码。"}
            </small>
          </span>
          <input
            type="checkbox"
            checked={draft.hello_enabled}
            onChange={(event) => change("hello_enabled", event.target.checked)}
            disabled={!status.hello_available}
          />
        </label>
        <label className="setting-row">
          <span>
            <strong>闲置后锁定管理界面</strong>
            <small>以系统闲置时间计算，AI 请求不会延长时间。</small>
          </span>
          <select
            aria-label="闲置锁定时间"
            value={draft.idle_lock_minutes}
            onChange={(event) =>
              change("idle_lock_minutes", Number(event.target.value))
            }
          >
            <option value={5}>5 分钟</option>
            <option value={15}>15 分钟</option>
            <option value={30}>30 分钟</option>
            <option value={60}>1 小时</option>
            <option value={0}>不自动锁定</option>
          </select>
        </label>
      </section>
      <section className="settings-section">
        <header>
          <Icon name="sun" />
          <div>
            <h2>外观</h2>
            <p>跟随你的工作环境，保持清晰、紧凑。</p>
          </div>
        </header>
        <label className="setting-row">
          <span>
            <strong>主题</strong>
            <small>授权终端 · Segoe UI / 微软雅黑</small>
          </span>
          <select
            value={draft.theme}
            onChange={(event) =>
              change("theme", event.target.value as Settings["theme"])
            }
          >
            <option value="dark">深色</option>
            <option value="light">浅色</option>
          </select>
        </label>
        <label className="setting-row">
          <span>
            <strong>减少动效</strong>
            <small>关闭 120 毫秒的选中与展开反馈。</small>
          </span>
          <input
            type="checkbox"
            checked={draft.reduced_motion}
            onChange={(event) => change("reduced_motion", event.target.checked)}
          />
        </label>
      </section>
      <section className="settings-section">
        <header>
          <Icon name="download" />
          <div>
            <h2>备份与迁移</h2>
            <p>备份使用保险库加密，不包含本机快捷解锁材料。</p>
          </div>
        </header>
        <div className="setting-row">
          <span>
            <strong>导出加密备份</strong>
            <small>保存到你选择的位置，恢复时需要主密码。</small>
          </span>
          <button
            className="button small"
            disabled={action.busy}
            onClick={() =>
              void action.run(async () => {
                const result = await call<{ path: string } | null>(
                  "vault_backup",
                );
                if (result)
                  action.setMessage(`加密备份已保存到 ${result.path}`);
              })
            }
          >
            <Icon name="download" size={15} />
            导出备份
          </button>
        </div>
        <div className="setting-row">
          <span>
            <strong>恢复备份或迁移旧版保险库</strong>
            <small>保留原始文件。恢复后重新配对 AI 客户端。</small>
          </span>
          <button className="button small" onClick={() => setImporting(true)}>
            <Icon name="upload" size={15} />
            导入保险库
          </button>
        </div>
      </section>
      <div className="settings-bottom">
        <div className="settings-product">
          <div className="settings-product-heading">
            <strong>pman Vault</strong>
            <span
              className="settings-version"
              aria-label={`pman Vault 当前版本 ${appVersion ?? "未知"}`}
            >
              版本 {appVersion ?? "—"}
            </span>
          </div>
          <span>本地授权工作台 · 原生 CLI / MCP</span>
        </div>
        <button
          className="text-button danger-text"
          disabled={action.busy}
          onClick={() => void action.run(() => call("application_exit"))}
        >
          <Icon name="logout" size={15} />
          退出并停止服务
        </button>
      </div>
      {importing && (
        <ImportDialog
          onClose={() => setImporting(false)}
          onSaved={async () => {
            setImporting(false);
            await onRefresh();
          }}
        />
      )}
    </div>
  );
}

export function ImportDialog({
  onClose,
  onSaved,
}: {
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const [mode, setMode] = useState("backup");
  const [password, setPassword] = useState("");
  const action = useAction();
  async function submit(event: FormEvent) {
    event.preventDefault();
    await action.run(async () => {
      const result = await call<{ path: string; detail: string } | null>(
        mode === "legacy" ? "vault_migrate_legacy" : "vault_import",
        { password },
      );
      setPassword("");
      if (result) {
        action.setMessage(result.detail || "导入完成，原文件已保留。");
        await onSaved();
      }
    });
  }
  return (
    <Modal
      title="导入保险库"
      subtitle="选择文件后，由本机核心校验并迁移。原始文件保持不变。"
      onClose={() => {
        if (!action.busy) onClose();
      }}
    >
      <form className="stack-form" onSubmit={submit}>
        <label>
          来源
          <select
            value={mode}
            onChange={(event) => setMode(event.target.value)}
          >
            <option value="backup">pman 加密备份</option>
            <option value="legacy">旧版 pman 保险库</option>
          </select>
        </label>
        <label>
          来源保险库的主密码
          <input
            autoFocus
            required
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="off"
          />
        </label>
        <div className="info-box">
          <Icon name="upload" />
          <p>
            {mode === "legacy"
              ? "迁移前请退出旧版代理。迁移保留别名、策略和历史记录。"
              : "导入将替换当前保险库，操作前自动保留一致性备份。恢复后需要重新配对 AI。"}
          </p>
        </div>
        <Notice error={action.error} message={action.message} />
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
            {action.busy ? "校验与导入中…" : "选择文件并导入"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function ResumeDialog({
  helloAvailable,
  onClose,
  onResumed,
}: {
  helloAvailable: boolean;
  onClose: () => void;
  onResumed: () => Promise<void>;
}) {
  const [password, setPassword] = useState("");
  const action = useAction();
  async function resume(hello: boolean) {
    await action.run(async () => {
      await call(
        "service_resume",
        hello ? { hello: true } : { password, hello: false },
      );
      setPassword("");
      await onResumed();
      onClose();
    });
  }
  return (
    <Modal
      title="恢复 AI 授权服务"
      subtitle="验证本人后恢复已有授权。之后 Windows 锁屏和重启不会暂停服务。"
      onClose={() => {
        if (!action.busy) onClose();
      }}
    >
      <form
        className="stack-form"
        onSubmit={(event) => {
          event.preventDefault();
          void resume(false);
        }}
      >
        <label>
          主密码
          <input
            autoFocus
            required
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="off"
          />
        </label>
        <Notice error={action.error} />
        <div className="modal-actions">
          {helloAvailable && (
            <button
              className="button"
              type="button"
              disabled={action.busy}
              onClick={() => void resume(true)}
            >
              使用 Windows Hello
            </button>
          )}
          <button
            className="button primary"
            type="submit"
            disabled={action.busy}
          >
            {action.busy ? "验证中…" : "验证并恢复服务"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
