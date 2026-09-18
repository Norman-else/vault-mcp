import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { Tooltip } from "./Tooltip";

export type IconName =
  | "lock"
  | "database"
  | "folder"
  | "key"
  | "search"
  | "plus"
  | "chevron"
  | "copy"
  | "eye"
  | "hidden"
  | "edit"
  | "trash"
  | "refresh"
  | "clock"
  | "code"
  | "close"
  | "sun"
  | "moon"
  | "check"
  | "arrow";
const shapes: Record<IconName, ReactNode> = {
  lock: (
    <>
      <rect x="4" y="10" width="16" height="11" rx="2" />
      <path d="M8 10V6a4 4 0 0 1 8 0v4M12 14v3" />
    </>
  ),
  database: (
    <>
      <ellipse cx="12" cy="5" rx="8" ry="3" />
      <path d="M4 5v14c0 4 16 4 16 0V5M4 12c0 4 16 4 16 0" />
    </>
  ),
  folder: (
    <path d="M3 7V5a2 2 0 0 1 2-2h5l3 4h6a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z" />
  ),
  key: (
    <>
      <circle cx="8" cy="8" r="5" />
      <path d="m12 12 9 9m-3-3 3-3m-6 0 3-3" />
    </>
  ),
  search: (
    <>
      <circle cx="10.5" cy="10.5" r="7" />
      <path d="m16 16 5 5" />
    </>
  ),
  plus: <path d="M12 5v14M5 12h14" />,
  chevron: <path d="m9 5 7 7-7 7" />,
  copy: (
    <>
      <rect x="8" y="8" width="12" height="13" rx="2" />
      <path d="M16 8V3H3v13h5" />
    </>
  ),
  eye: (
    <>
      <path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12Z" />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
  hidden: (
    <>
      <path d="m3 3 18 18M10 5h2c6 0 10 7 10 7a22 22 0 0 1-4 4M6 6c-3 2-4 6-4 6s4 7 10 7h2" />
    </>
  ),
  edit: (
    <>
      <path d="m15 4 5 5M4 16 16 4a3 3 0 0 1 4 4L8 20H4v-4Z" />
    </>
  ),
  trash: (
    <>
      <path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7M14 10v7" />
    </>
  ),
  refresh: (
    <>
      <path d="M20 7v5h-5M4 17v-5h5M20 12a8 8 0 0 0-14-5M4 12a8 8 0 0 0 14 5" />
    </>
  ),
  clock: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 6v6l4 2" />
    </>
  ),
  code: <path d="m8 6-6 6 6 6m8-12 6 6-6 6M14 3l-4 18" />,
  close: <path d="m6 6 12 12M6 18 18 6" />,
  sun: (
    <>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 1v2m0 18v2M1 12h2m18 0h2M4 4l2 2m12 12 2 2M4 20l2-2M18 6l2-2" />
    </>
  ),
  moon: <path d="M21 13a9 9 0 0 1-10-10 9 9 0 1 0 10 10Z" />,
  check: <path d="m5 12 4 4L20 5" />,
  arrow: <path d="M19 12H5m6-6-6 6 6 6" />,
};
export function Icon({
  name,
  className = "",
}: {
  name: IconName;
  className?: string;
}) {
  return (
    <svg
      className={`icon ${className}`}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {shapes[name]}
    </svg>
  );
}
export function IconButton({
  icon,
  label,
  onClick,
  disabled = false,
  danger = false,
}: {
  icon: IconName;
  label: string;
  onClick: () => void;
  disabled?: boolean;
  danger?: boolean;
}) {
  return (
    <Tooltip content={label}>
      <button
        type="button"
        className={`icon-button${danger ? " danger" : ""}`}
        aria-label={label}
        onClick={onClick}
        disabled={disabled}
      >
        <Icon name={icon} />
      </button>
    </Tooltip>
  );
}
export function Loading({ text = "Loading…" }: { text?: string }) {
  return (
    <div className="loading" role="status">
      <span className="spinner" />
      {text}
    </div>
  );
}
export function ErrorBanner({
  message,
  children,
}: {
  message: string;
  children?: ReactNode;
}) {
  return (
    <div className="error-banner" role="alert">
      <span>{message}</span>
      {children}
    </div>
  );
}

export function Modal({
  title,
  children,
  onClose,
  wide = false,
  editor = false,
  busy = false,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  wide?: boolean;
  editor?: boolean;
  busy?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const closeRef = useRef(onClose);
  const busyRef = useRef(busy);
  closeRef.current = onClose;
  busyRef.current = busy;
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const root = document.getElementById("root");
    const previousInert = root?.inert ?? false;
    const previousOverflow = document.body.style.overflow;
    if (root) root.inert = true;
    document.body.style.overflow = "hidden";
    const element = ref.current;
    const focusables = () =>
      Array.from(
        element?.querySelectorAll<HTMLElement>(
          'button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex="0"]',
        ) || [],
      );
    (
      element?.querySelector<HTMLElement>("[data-autofocus]") ||
      focusables()[0] ||
      element
    )?.focus();
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busyRef.current) {
        event.preventDefault();
        event.stopPropagation();
        closeRef.current();
      }
      if (event.key !== "Tab") return;
      const items = focusables();
      const first = items[0];
      const last = items.at(-1);
      if (!first) {
        event.preventDefault();
        element?.focus();
      } else if (
        event.shiftKey &&
        (document.activeElement === first || document.activeElement === element)
      ) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    element?.addEventListener("keydown", handler);
    return () => {
      element?.removeEventListener("keydown", handler);
      if (root) root.inert = previousInert;
      document.body.style.overflow = previousOverflow;
      previous?.focus();
    };
  }, []);
  return createPortal(
    <div
      className={`modal-overlay${editor ? " modal-editor-overlay" : ""}`}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !busy) onClose();
      }}
    >
      <div
        className={`modal ${wide ? "modal-wide" : ""}${editor ? " modal-editor" : ""}`}
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <div className="modal-heading">
          <h2 id={titleId}>{title}</h2>
          <IconButton
            icon="close"
            label="Close dialog"
            onClick={onClose}
            disabled={busy}
          />
        </div>
        {children}
      </div>
    </div>,
    document.body,
  );
}

export function MaskedValue({
  value,
  label,
  copy,
}: {
  value: string;
  label: string;
  copy: (value: string) => void;
}) {
  const [revealed, setRevealed] = useState(false);
  useEffect(() => {
    setRevealed(false);
  }, [value]);
  return (
    <div className="masked-value">
      <code
        className={revealed ? "revealed" : "masked"}
        aria-label={revealed ? undefined : `${label} hidden`}
      >
        {revealed ? value : "••••••••••••"}
      </code>
      <div className="row-actions">
        <IconButton
          icon={revealed ? "hidden" : "eye"}
          label={`${revealed ? "Hide" : "Reveal"} ${label}`}
          onClick={() => setRevealed(!revealed)}
        />
        <IconButton
          icon="copy"
          label={`Copy ${label}`}
          onClick={() => copy(value)}
        />
      </div>
    </div>
  );
}

export function Disclosure({
  title,
  children,
  className = "",
}: {
  title: string;
  children: ReactNode;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const id = useId();
  return (
    <div className={`disclosure ${className}`}>
      <button
        type="button"
        className="disclosure-trigger"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen(!open)}
      >
        <Icon name="chevron" />
        {title}
      </button>
      <div id={id} hidden={!open}>
        {children}
      </div>
    </div>
  );
}
