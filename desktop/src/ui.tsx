import { ReactNode, useEffect, useRef, useState } from "react";
import { errorText } from "./api";

export type IconName =
  | "link"
  | "grid"
  | "vault"
  | "shield"
  | "activity"
  | "settings"
  | "search"
  | "plus"
  | "close"
  | "lock"
  | "refresh"
  | "arrow"
  | "key"
  | "terminal"
  | "chevron"
  | "copy"
  | "edit"
  | "trash"
  | "star"
  | "eye"
  | "hide"
  | "pause"
  | "play"
  | "bell"
  | "check"
  | "globe"
  | "download"
  | "upload"
  | "sun"
  | "moon"
  | "logout";
const paths: Record<IconName, ReactNode> = {
  link: (
    <>
      <path d="m10 13 4-4M8 15l-2 2a4 4 0 0 1-5-5l5-5a4 4 0 0 1 6 0M12 17a4 4 0 0 0 6 0l5-5a4 4 0 0 0-5-5l-2 2" />
    </>
  ),
  grid: (
    <>
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
      <rect x="14" y="14" width="7" height="7" rx="1" />
    </>
  ),
  vault: (
    <>
      <rect x="4" y="3" width="16" height="18" rx="2" />
      <circle cx="12" cy="12" r="4" />
      <path d="M12 8v8M8 12h8M4 7H2M4 17H2" />
    </>
  ),
  shield: (
    <>
      <path d="m12 3 8 3v5c0 5-4 8-8 10-4-2-8-5-8-10V6l8-3Z" />
      <path d="m8 12 3 3 5-6" />
    </>
  ),
  activity: <path d="M3 12h4l3-7 4 14 3-7h4" />,
  settings: (
    <>
      <path d="m9 3-.6 3-2 1L3.5 6l-2 3 2.3 2v2L1.5 15l2 3 2.9-1 2 1L9 21h4l.6-3 2-1 2.9 1 2-3-2.3-2v-2l2.3-2-2-3-2.9 1-2-1L13 3Z" />
      <circle cx="11" cy="12" r="3" />
    </>
  ),
  search: (
    <>
      <circle cx="10.5" cy="10.5" r="6.5" />
      <path d="m16 16 5 5" />
    </>
  ),
  plus: <path d="M12 5v14M5 12h14" />,
  close: <path d="m6 6 12 12M18 6 6 18" />,
  lock: (
    <>
      <rect x="5" y="10" width="14" height="11" rx="2" />
      <path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3" />
    </>
  ),
  refresh: (
    <>
      <path d="M20 10a8 8 0 0 0-14-4L3 9M3 3v6h6M4 14a8 8 0 0 0 14 4l3-3M21 21v-6h-6" />
    </>
  ),
  arrow: <path d="M4 12h16m-6-6 6 6-6 6" />,
  key: (
    <>
      <circle cx="8" cy="16" r="4" />
      <path d="m11 13 9-9M16 8l3 3M14 10l3 3" />
    </>
  ),
  terminal: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="m7 9 3 3-3 3M13 15h4" />
    </>
  ),
  chevron: <path d="m9 5 7 7-7 7" />,
  copy: (
    <>
      <rect x="8" y="8" width="12" height="13" rx="2" />
      <path d="M15 8V3H3v13h5" />
    </>
  ),
  edit: (
    <>
      <path d="m4 16-1 5 5-1L20 8l-4-4L4 16ZM14 6l4 4" />
    </>
  ),
  trash: <path d="M3 6h18M8 6V3h8v3M6 6l1 15h10l1-15M10 10v7M14 10v7" />,
  star: (
    <path d="m12 3 2.8 5.7 6.2.9-4.5 4.4 1.1 6.2L12 17.3l-5.6 2.9 1.1-6.2L3 9.6l6.2-.9L12 3Z" />
  ),
  eye: (
    <>
      <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7S2 12 2 12Z" />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
  hide: (
    <>
      <path d="m3 3 18 18M10 5h2c7 0 10 7 10 7l-3 4M6 6l-4 6s3 7 10 7l4-1" />
    </>
  ),
  pause: <path d="M8 5v14M16 5v14" />,
  play: <path d="m8 4 12 8-12 8V4Z" />,
  bell: (
    <>
      <path d="M5 16h14l-2-3V8a5 5 0 0 0-10 0v5l-2 3ZM10 20h4" />
    </>
  ),
  check: <path d="m5 12 4 4L20 5" />,
  globe: (
    <>
      <circle cx="12" cy="12" r="9" />
      <ellipse cx="12" cy="12" rx="4" ry="9" />
      <path d="M3 12h18" />
    </>
  ),
  download: <path d="M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5" />,
  upload: <path d="M12 15V3m-5 5 5-5 5 5M4 16v5h16v-5" />,
  sun: (
    <>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1 1M18 18l1 1M5 19l1-1M18 6l1-1" />
    </>
  ),
  moon: <path d="M20 15A9 9 0 0 1 9 4a9 9 0 1 0 11 11Z" />,
  logout: <path d="M10 4H4v16h6M10 12h11m-5-5 5 5-5 5" />,
};
export function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {paths[name]}
    </svg>
  );
}
export function Brand() {
  return (
    <div className="brand">
      <span className="brand-symbol">
        <svg
          width="30"
          height="36"
          viewBox="0 0 30 36"
          fill="none"
          aria-hidden="true"
        >
          <path
            d="M15 1 5 11v22l7-7V14l5-5 6 6-6 6v9l12-12V12L15 1Z"
            fill="currentColor"
          />
          <path d="m12 20 5-5v9l-5 5v-9Z" fill="currentColor" opacity=".55" />
        </svg>
      </span>
      <div>
        <strong>pman</strong>
        <small>本地授权工作台</small>
      </div>
    </div>
  );
}
export function Notice({
  error,
  message,
}: {
  error?: string | null;
  message?: string | null;
}) {
  return (
    <>
      {error && (
        <div className="notice error" role="alert">
          {error}
        </div>
      )}
      {message && (
        <div className="notice success" role="status">
          {message}
        </div>
      )}
    </>
  );
}
export function Badge({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: string;
}) {
  return (
    <span className={`badge ${tone}`}>
      <i />
      {children}
    </span>
  );
}
export function Empty({
  icon = "vault",
  title,
  children,
  action,
}: {
  icon?: IconName;
  title: string;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <span className="empty-icon">
        <Icon name={icon} size={28} />
      </span>
      <h3>{title}</h3>
      <p>{children}</p>
      {action}
    </div>
  );
}
export function IconButton({
  icon,
  label,
  onClick,
  disabled = false,
  active = false,
}: {
  icon: IconName;
  label: string;
  onClick: () => void;
  disabled?: boolean;
  active?: boolean;
}) {
  return (
    <button
      type="button"
      className={`icon-button${active ? " active" : ""}`}
      aria-label={label}
      title={label}
      onClick={onClick}
      disabled={disabled}
    >
      <Icon name={icon} />
    </button>
  );
}
export function Modal({
  title,
  subtitle,
  children,
  onClose,
  wide = false,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  onClose: () => void;
  wide?: boolean;
}) {
  const ref = useRef<HTMLElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  const id = useRef(`modal-${Math.random().toString(36).slice(2)}`).current;
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const panel = ref.current;
    const focusable = () =>
      Array.from(
        panel?.querySelectorAll<HTMLElement>(
          'button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href], [tabindex="0"]',
        ) || [],
      ).filter((node) => !node.closest("[hidden]"));
    const initial =
      panel?.querySelector<HTMLElement>("[autofocus]") || focusable()[0];
    initial?.focus();
    const handle = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        closeRef.current();
      }
      if (event.key === "Tab") {
        const elements = focusable();
        const first = elements[0];
        const last = elements[elements.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last?.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first?.focus();
        }
      }
    };
    panel?.addEventListener("keydown", handle);
    return () => {
      panel?.removeEventListener("keydown", handle);
      if (previous?.isConnected) previous.focus();
    };
  }, []);
  return (
    <div className="modal-backdrop">
      <section
        ref={ref}
        className={`modal${wide ? " wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={id}
      >
        <header className="modal-heading">
          <div>
            <h2 id={id}>{title}</h2>
            {subtitle && <p>{subtitle}</p>}
          </div>
          <IconButton icon="close" label="关闭对话框" onClick={onClose} />
        </header>
        {children}
      </section>
    </div>
  );
}
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const mounted = useRef(true);
  const working = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  async function run<T>(
    action: () => Promise<T>,
    success?: string,
  ): Promise<T | undefined> {
    if (working.current) return;
    working.current = true;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const result = await action();
      if (mounted.current && success) setMessage(success);
      return result;
    } catch (err) {
      if (mounted.current) setError(errorText(err));
      return undefined;
    } finally {
      working.current = false;
      if (mounted.current) setBusy(false);
    }
  }
  return { busy, error, message, setError, setMessage, run };
}
