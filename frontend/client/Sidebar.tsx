import { useEffect, useRef, useState, type ReactNode } from "react";

const storageKey = "vault-ops-sidebar-width";
const minimum = 272;
const defaultWidth = 320;

export function Sidebar({ children }: { children: ReactNode }) {
  const [preferredWidth, setPreferredWidth] = useState(() => {
    try {
      const saved = Number(localStorage.getItem(storageKey));
      return Number.isFinite(saved) && saved >= minimum && saved <= 560
        ? saved
        : defaultWidth;
    } catch {
      return defaultWidth;
    }
  });
  const [viewport, setViewport] = useState(window.innerWidth);
  const [dragging, setDragging] = useState(false);
  const drag = useRef<{ x: number; width: number } | null>(null);
  const maximum = Math.max(minimum, Math.min(560, Math.floor(viewport * 0.45)));
  const width = Math.min(preferredWidth, maximum);
  const clamp = (value: number) =>
    Math.round(Math.max(minimum, Math.min(maximum, value)));

  useEffect(() => {
    const resize = () => setViewport(window.innerWidth);
    window.addEventListener("resize", resize);
    return () => window.removeEventListener("resize", resize);
  }, []);
  useEffect(() => {
    try {
      localStorage.setItem(storageKey, String(preferredWidth));
    } catch {
      /* A blocked preference store must not prevent resizing. */
    }
  }, [preferredWidth]);

  return (
    <aside
      id="vault-navigation"
      className={`sidebar${dragging ? " sidebar-resizing" : ""}`}
      aria-label="Vault navigation"
      style={{ "--sidebar-width": `${width}px` } as React.CSSProperties}
    >
      {children}
      <div
        className="sidebar-resizer"
        role="separator"
        aria-label="Resize navigation"
        aria-orientation="vertical"
        aria-controls="vault-navigation"
        aria-valuemin={minimum}
        aria-valuemax={maximum}
        aria-valuenow={width}
        tabIndex={0}
        onDoubleClick={() => setPreferredWidth(defaultWidth)}
        onKeyDown={(event) => {
          const next =
            event.key === "ArrowLeft"
              ? width - 16
              : event.key === "ArrowRight"
                ? width + 16
                : event.key === "Home"
                  ? minimum
                  : event.key === "End"
                    ? maximum
                    : event.key === "Enter"
                      ? defaultWidth
                      : null;
          if (next === null) return;
          event.preventDefault();
          setPreferredWidth(clamp(next));
        }}
        onPointerDown={(event) => {
          if (event.button !== 0) return;
          event.preventDefault();
          event.currentTarget.focus();
          event.currentTarget.setPointerCapture(event.pointerId);
          drag.current = { x: event.clientX, width };
          setDragging(true);
        }}
        onPointerMove={(event) => {
          if (drag.current)
            setPreferredWidth(
              clamp(drag.current.width + event.clientX - drag.current.x),
            );
        }}
        onPointerUp={(event) => {
          drag.current = null;
          setDragging(false);
          if (event.currentTarget.hasPointerCapture(event.pointerId))
            event.currentTarget.releasePointerCapture(event.pointerId);
        }}
        onPointerCancel={() => {
          drag.current = null;
          setDragging(false);
        }}
        onLostPointerCapture={() => {
          drag.current = null;
          setDragging(false);
        }}
      />
    </aside>
  );
}
