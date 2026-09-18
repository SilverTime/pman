import { useState } from "react";
import { AuditEntry, timestamp } from "./api";
import { Badge, Empty, Icon, IconButton, Notice, useAction } from "./ui";

function outcome(entry: AuditEntry): "success" | "warning" | "danger" {
  if (entry.status_code && entry.status_code >= 200 && entry.status_code < 400)
    return "success";
  if (
    entry.status_code === 401 ||
    entry.status_code === 403 ||
    entry.note?.includes("denied") ||
    entry.note?.includes("approval")
  )
    return "warning";
  return "danger";
}
export function Activity({
  entries,
  onRefresh,
  onAuthorize,
}: {
  entries: AuditEntry[];
  onRefresh: () => Promise<void>;
  onAuthorize: (harness: string, site: string) => void;
}) {
  const [client, setClient] = useState("");
  const [site, setSite] = useState("");
  const [result, setResult] = useState("");
  const [expanded, setExpanded] = useState<number | null>(null);
  const action = useAction();
  const clients = Array.from(
    new Set(entries.map((entry) => entry.harness)),
  ).sort();
  const sites = Array.from(
    new Set(
      entries
        .map((entry) => entry.site)
        .filter((value): value is string => Boolean(value)),
    ),
  ).sort();
  const visible = entries.filter(
    (entry) =>
      (!client || entry.harness === client) &&
      (!site || entry.site === site) &&
      (!result || outcome(entry) === result),
  );
  return (
    <div className="page">
      <div className="page-heading">
        <div>
          <div className="eyebrow">REQUEST HISTORY</div>
          <h1>活动记录</h1>
          <p>查看调用结果、审批与脱敏记录，定位对应权限。</p>
        </div>
        <IconButton
          icon="refresh"
          label="刷新活动记录"
          onClick={() => void action.run(onRefresh)}
          disabled={action.busy}
        />
      </div>
      <div className="toolbar activity-toolbar">
        <label>
          客户端
          <select
            value={client}
            onChange={(event) => setClient(event.target.value)}
          >
            <option value="">全部客户端</option>
            {clients.map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
        <label>
          连接
          <select
            value={site}
            onChange={(event) => setSite(event.target.value)}
          >
            <option value="">全部连接</option>
            {sites.map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
        <label>
          结果
          <select
            value={result}
            onChange={(event) => setResult(event.target.value)}
          >
            <option value="">全部结果</option>
            <option value="success">成功</option>
            <option value="warning">拒绝 / 待审批</option>
            <option value="danger">异常 / 未完成</option>
          </select>
        </label>
        <span className="muted">最近 {entries.length} 条</span>
      </div>
      <Notice error={action.error} />
      <section className="activity-table" aria-label="活动列表">
        <div className="activity-row table-header" aria-hidden="true">
          <span>时间</span>
          <span>客户端 / 连接</span>
          <span>请求</span>
          <span>结果</span>
          <span />
        </div>
        {visible.length ? (
          visible.map((entry) => (
            <div className="activity-item" key={entry.id}>
              <button
                className={`activity-row${expanded === entry.id ? " selected" : ""}`}
                onClick={() =>
                  setExpanded(expanded === entry.id ? null : entry.id)
                }
                aria-expanded={expanded === entry.id}
              >
                <span className="mono small-text">{timestamp(entry.ts)}</span>
                <span className="activity-identity">
                  <strong>{entry.harness}</strong>
                  <small>{entry.site || "服务事件"}</small>
                </span>
                <span className="request-cell">
                  <span className="method">{entry.method || "—"}</span>
                  <code>{entry.path || "—"}</code>
                </span>
                <Badge tone={outcome(entry)}>
                  {entry.status_code ||
                    (outcome(entry) === "warning" ? "已阻断" : "未完成")}
                </Badge>
                <Icon name="chevron" size={14} />
              </button>
              {expanded === entry.id && (
                <div className="activity-expanded">
                  <dl>
                    <div>
                      <dt>响应大小</dt>
                      <dd>{entry.resp_bytes.toLocaleString()} B</dd>
                    </div>
                    <div>
                      <dt>脱敏次数</dt>
                      <dd>{entry.redactions}</dd>
                    </div>
                    <div>
                      <dt>审批放行</dt>
                      <dd>{entry.approved ? "是" : "否"}</dd>
                    </div>
                    <div>
                      <dt>内容截断</dt>
                      <dd>{entry.truncated ? "是" : "否"}</dd>
                    </div>
                  </dl>
                  {entry.req_id && (
                    <p className="mono small-text muted">
                      请求 ID：{entry.req_id}
                    </p>
                  )}
                  {entry.note && <p className="activity-note">{entry.note}</p>}
                  {entry.site && (
                    <button
                      className="button small"
                      onClick={() => onAuthorize(entry.harness, entry.site!)}
                    >
                      <Icon name="shield" size={14} />
                      查看对应授权
                    </button>
                  )}
                </div>
              )}
            </div>
          ))
        ) : (
          <Empty
            icon="activity"
            title={entries.length ? "没有匹配的记录" : "还没有调用记录"}
          >
            {entries.length
              ? "调整筛选条件查看其他活动。"
              : "AI 开始使用连接后，这里会显示每次调用的结果。"}
          </Empty>
        )}
      </section>
    </div>
  );
}
